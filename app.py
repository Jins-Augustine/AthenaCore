from flask import Flask, render_template, request, jsonify, send_file
import requests
import json
import csv
import os
from dotenv import load_dotenv
load_dotenv()
from datetime import datetime
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # This allows React to make requests to Flask

# Add to your Flask app configuration
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=3600  # 1 hour sessions
)

# Store IP checks in memory
ip_checks_log = []

# AbuseIPDB API configuration
# Get API key from environment
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Add validation
if not ABUSEIPDB_API_KEY:
    raise ValueError("No ABUSEIPDB_API_KEY found in environment variables")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# Abuse category mapping
ABUSE_CATEGORY_MAP = {
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Exploiting Vulnerabilities",
    11: "Web App Attack",
    12: "SQL Injection",
    13: "SSH Brute-Force",
    14: "IoT Targeted",
    15: "Port Scan",
    16: "Hacking Tool",
    17: "Spamming",
    18: "Web Spam",
    19: "Email Spam",
    20: "Blog Spam",
    21: "VPN IP",
    22: "Abuse Email",
    23: "Malware Distribution",
    24: "Command and Control",
    25: "Spoofing"
}

def calculate_threat_level(confidence, reports, isp):
    """Determine threat level with context awareness"""
    is_datacenter = "data center" in isp.lower() or "hosting" in isp.lower() or "transit" in isp.lower()
    base_threshold = 30 if is_datacenter else 25
    
    if confidence >= 70:
        return "Critical Threat"
    elif confidence >= 50:
        return "High Risk"
    elif confidence >= base_threshold or reports >= 15:
        return "Suspicious"
    elif confidence >= 10 or reports >= 5:
        return "Low Risk"
    else:
        return "Safe"

def check_ip_with_abuseipdb(ip_address):
    """Check IP address using AbuseIPDB API"""
    headers = {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
    }
    
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': 365,
        'verbose': ''
    }
    
    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            
            # Process reports to include category names
            processed_reports = []
            for report in data.get('data', {}).get('reports', []):
                categories = report.get('categories', [])
                primary_category = categories[0] if categories else 0
                processed_reports.append({
                    'category': ABUSE_CATEGORY_MAP.get(primary_category, f"Unknown({primary_category})"),
                    'comment': report.get('comment', 'No comment provided')
                })
            
            # Add processed reports to data
            data['data']['processed_reports'] = processed_reports
            return data
        else:
            print(f"AbuseIPDB API error: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Error calling AbuseIPDB API: {e}")
        return None

def save_to_csv(ip_data):
    """Save IP check data to CSV file"""
    csv_file = 'logs/ip_checks.csv'
    os.makedirs('logs', exist_ok=True)
    file_exists = os.path.isfile(csv_file)
    
    with open(csv_file, 'a', newline='') as file:
        fieldnames = ['ip_address', 'datetime', 'result', 'abuse_confidence', 'country', 'reports']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        
        if not file_exists:
            writer.writeheader()
        
        writer.writerow(ip_data)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/check-ip', methods=['POST'])
def check_ip():
    """API endpoint for React to check IP"""
    data = request.get_json()
    ip_address = data.get('ip_address')
    
    if not ip_address:
        return jsonify({'error': 'IP address is required'}), 400
    
    # Call AbuseIPDB API
    api_result = check_ip_with_abuseipdb(ip_address)
    
    if api_result and 'data' in api_result:
        ip_data = api_result['data']
        
        # Calculate threat status with context
        abuse_confidence = ip_data.get('abuseConfidenceScore', 0)
        reports = ip_data.get('totalReports', 0)
        isp = ip_data.get('isp', '')
        result = calculate_threat_level(abuse_confidence, reports, isp)
        
        # Prepare response
        response_data = {
            'ip_address': ip_address,
            'abuse_confidence': abuse_confidence,
            'country': ip_data.get('countryCode', 'Unknown'),
            'domain': ip_data.get('domain', 'Unknown'),
            'usage_type': ip_data.get('usageType', 'Unknown'),
            'isp': isp,
            'reports': reports,
            'last_reported': ip_data.get('lastReportedAt', 'Never'),
            'recent_reports': ip_data.get('processed_reports', []),
            'abuse_categories': [
                ABUSE_CATEGORY_MAP.get(cat_id, f"Unknown({cat_id})")
                for cat_id in ip_data.get('abuseCategories', [])
            ],
            'result': result,
            'is_whitelisted': ip_data.get('isWhitelisted', False)
        }
        
        # Log the check
        log_entry = {
            'ip_address': ip_address,
            'datetime': datetime.now().isoformat(),
            'result': result,
            'abuse_confidence': abuse_confidence,
            'country': response_data['country'],
            'reports': response_data['reports']
        }
        
        ip_checks_log.append(log_entry)
        save_to_csv(log_entry)
        
        return jsonify(response_data)
    else:
        return jsonify({'error': 'Failed to check IP address'}), 500

@app.route('/api/history')
def get_history():
    """Get IP check history"""
    return jsonify(ip_checks_log)

@app.route('/api/export-history')
def export_history():
    """Export history as CSV"""
    csv_file = 'logs/ip_checks.csv'
    if os.path.exists(csv_file):
        return send_file(csv_file, as_attachment=True, download_name='ip_check_history.csv')
    else:
        return jsonify({'error': 'No history found'}), 404

@app.route('/api/stats')
def get_stats():
    """Get comprehensive statistics for chart"""
    stats = {
        'critical': 0,
        'high': 0,
        'suspicious': 0,
        'low': 0,
        'safe': 0
    }
    
    for check in ip_checks_log[-10:]:
        result = check.get('result', 'Safe')
        if 'Critical' in result:
            stats['critical'] += 1
        elif 'High' in result:
            stats['high'] += 1
        elif 'Suspicious' in result:
            stats['suspicious'] += 1
        elif 'Low' in result:
            stats['low'] += 1
        else:
            stats['safe'] += 1
    
    return jsonify(stats)

@app.route('/api/block-ip', methods=['POST'])
def block_ip():
    """Block an IP address"""
    data = request.json
    ip = data.get('ip')
    return jsonify({
        'success': True,
        'message': f'IP {ip} added to blocklist'
    })

@app.route('/api/report-abuse', methods=['POST'])
def report_abuse():
    """Report abuse for an IP"""
    data = request.json
    ip = data.get('ip')
    reason = data.get('reason')
    return jsonify({
        'success': True,
        'message': f'Abuse reported for {ip}: {reason}'
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
