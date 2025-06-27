document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('ipForm');
    const resultsDiv = document.getElementById('results');
    const resultsContent = document.getElementById('resultsContent');
    const historyTable = document.getElementById('historyTable');
    const exportBtn = document.getElementById('exportBtn');

    let statsChart;
    let currentIP = null; // Store the currently analyzed IP

    // Quick Actions functionality
    document.getElementById('blockIpBtn').addEventListener('click', function() {
        if (!currentIP) {
            alert('Please analyze an IP address first');
            return;
        }
        
        if (confirm(`Are you sure you want to block IP ${currentIP}?`)) {
            fetch('/api/block-ip', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ ip: currentIP })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert(data.message);
                } else {
                    alert('Failed to block IP');
                }
            })
            .catch(error => {
                console.error('Error blocking IP:', error);
                alert('Error blocking IP');
            });
        }
    });

    document.getElementById('reportAbuseBtn').addEventListener('click', function() {
        if (!currentIP) {
            alert('Please analyze an IP address first');
            return;
        }
        
        const reason = prompt(`Enter reason for reporting abuse of ${currentIP}:`);
        if (reason) {
            fetch('/api/report-abuse', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ ip: currentIP, reason: reason })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert(data.message);
                } else {
                    alert('Failed to report abuse');
                }
            })
            .catch(error => {
                console.error('Error reporting abuse:', error);
                alert('Error reporting abuse');
            });
        }
    });

    document.getElementById('viewHistoryBtn').addEventListener('click', function() {
        const historySection = document.getElementById('historySection');
        historySection.scrollIntoView({ behavior: 'smooth' });
    });

    

    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const ipAddress = document.getElementById('ipAddress').value;
        currentIP = ipAddress; // Store current IP for Quick Actions
        
        try {
            const response = await fetch('/api/check-ip', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ ip_address: ipAddress })
            });

            const data = await response.json();

            if (response.ok) {
                displayResults(data);
                loadHistory();
                loadStats();
                
                // Enable Quick Actions buttons
                document.getElementById('blockIpBtn').disabled = false;
                document.getElementById('reportAbuseBtn').disabled = false;
            } else {
                alert('Error: ' + data.error);
            }
        } catch (error) {
            alert('Error checking IP: ' + error.message);
        }
    });

    exportBtn.addEventListener('click', function() {
        window.location.href = '/api/export-history';
    });

    function displayResults(data) {
        const safeClass = data.result === 'Safe' ? 'status-safe' : 'status-danger';
        
        resultsContent.innerHTML = `
            <tr>
                <td>IP Address</td>
                <td>${data.ip_address}</td>
            </tr>
            <tr>
                <td>Status</td>
                <td><span class="status-badge ${safeClass}">${data.result}</span></td>
            </tr>
            <tr>
                <td>Abuse Confidence</td>
                <td>${data.abuse_confidence}%</td>
            </tr>
            <tr>
                <td>Domain</td>
                <td>${data.domain}</td>
            </tr>
            <tr>
                <td>Usage Type</td>
                <td>${data.usage_type}</td>
            </tr>
            <tr>
                <td>Whitelisted</td>
                <td>${data.is_whitelisted}</td>
            </tr>
            <tr>
                <td>Country</td>
                <td>${data.country}</td>
            </tr>
            <tr>
                <td>Reports</td>
                <td>${data.reports}</td>
            </tr>
            <tr>
                <td>ISP</td>
                <td>${data.isp}</td>
            </tr>
            <tr>
                <td>Last Reported</td>
                <td>${data.last_reported || 'Never'}</td>
            </tr>
            ${data.abuse_categories.length > 0 ? `
            <tr>
                <td>Abuse Categories</td>
                <td>${data.abuse_categories.join(', ')}</td>
            </tr>` : ''}
            ${data.recent_reports.length > 0 ? `
            <tr>
                <td colspan="2">
                    <div class="recent-reports">
                        <strong>Recent Reports:</strong>
                        <button class="btn btn-sm btn-outline-secondary ms-2" id="toggleReports">
                            Show Details <i class="fas fa-chevron-down"></i>
                        </button>
                        <div class="reports-list mt-2" id="reportsList" style="display: none;">
                            <ul class="mb-0">
                                ${data.recent_reports.map(r => `
                                <li><strong>${r.category}</strong>: ${r.comment || 'No comment'}</li>
                                `).join('')}
                            </ul>
                        </div>
                    </div>
                </td>
            </tr>` : ''}
        `;
        
        // Add toggle functionality for reports
        const toggleBtn = document.getElementById('toggleReports');
        const reportsList = document.getElementById('reportsList');
        
        if (toggleBtn && reportsList) {
            toggleBtn.addEventListener('click', function() {
                const isHidden = reportsList.style.display === 'none';
                reportsList.style.display = isHidden ? 'block' : 'none';
                toggleBtn.innerHTML = isHidden ? 
                    'Hide Details <i class="fas fa-chevron-up"></i>' : 
                    'Show Details <i class="fas fa-chevron-down"></i>';
            });
        }
        
        resultsDiv.style.display = 'block';
    }

    async function loadHistory() {
        try {
            const response = await fetch('/api/history');
            const history = await response.json();
            
            historyTable.innerHTML = '';
            
            // Limit to last 10 entries initially
            const displayHistory = history.slice(-10);
            const hasMore = history.length > 10;
            
            displayHistory.forEach(item => {
                const row = historyTable.insertRow();
                const resultClass = item.result === 'Safe' ? 'status-safe' : 'status-danger';
                
                row.innerHTML = `
                    <td>${item.ip_address}</td>
                    <td>${new Date(item.datetime).toLocaleString()}</td>
                    <td><span class="status-badge ${resultClass}">${item.result}</span></td>
                    <td>${item.abuse_confidence}%</td>
                    <td>
                        <button class="btn btn-sm btn-outline-primary" onclick="analyzeIP('${item.ip_address}')">
                            <i class="fas fa-redo me-1"></i>Re-analyze
                        </button>
                    </td>
                `;
            });
            
            // Add "Show More" button if there are more entries
            if (hasMore) {
                const row = historyTable.insertRow();
                row.innerHTML = `
                    <td colspan="5" class="text-center">
                        <button class="btn btn-outline-secondary" id="showMoreHistory">
                            Show All ${history.length} Entries <i class="fas fa-chevron-down"></i>
                        </button>
                    </td>
                `;
                
                document.getElementById('showMoreHistory').addEventListener('click', function() {
                    loadFullHistory();
                });
            }
            
        } catch (error) {
            console.error('Error loading history:', error);
        }
    }

    async function loadFullHistory() {
        try {
            const response = await fetch('/api/history');
            const history = await response.json();
            
            historyTable.innerHTML = '';
            history.forEach(item => {
                const row = historyTable.insertRow();
                const resultClass = item.result === 'Safe' ? 'status-safe' : 'status-danger';
                
                row.innerHTML = `
                    <td>${item.ip_address}</td>
                    <td>${new Date(item.datetime).toLocaleString()}</td>
                    <td><span class="status-badge ${resultClass}">${item.result}</span></td>
                    <td>${item.abuse_confidence}%</td>
                    <td>
                        <button class="btn btn-sm btn-outline-primary" onclick="analyzeIP('${item.ip_address}')">
                            <i class="fas fa-redo me-1"></i>Re-analyze
                        </button>
                    </td>
                `;
            });
            
            // Add "Show Less" button
            const row = historyTable.insertRow(0);
            row.innerHTML = `
                <td colspan="5" class="text-center">
                    <button class="btn btn-outline-secondary" id="showLessHistory">
                        Show Recent Only <i class="fas fa-chevron-up"></i>
                    </button>
                </td>
            `;
            
            document.getElementById('showLessHistory').addEventListener('click', function() {
                loadHistory();
            });
            
        } catch (error) {
            console.error('Error loading full history:', error);
        }
    }

    // Global function to analyze IP from history
    window.analyzeIP = function(ip) {
        document.getElementById('ipAddress').value = ip;
        form.dispatchEvent(new Event('submit'));
    };

    async function loadStats() {
        try {
            const response = await fetch('/api/stats');
            const stats = await response.json();
            
            updateChart(stats);
        } catch (error) {
            console.error('Error loading stats:', error);
        }
    }

    function updateChart(stats) {
        const ctx = document.getElementById('statsChart').getContext('2d');
        
        if (statsChart) {
            statsChart.destroy();
        }
        
        statsChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Critical', 'High Risk', 'Medium', 'Low Risk', 'Safe'],
                datasets: [{
                    label: 'Threat Distribution',
                    data: [
                        stats.critical, 
                        stats.high, 
                        stats.medium || stats.suspicious, // Handle both 'medium' and 'suspicious'
                        stats.low, 
                        stats.safe
                    ],
                    backgroundColor: [
                        '#dc3545', '#fd7e14', '#ffc107', '#20c997', '#198754'
                    ],
                    borderColor: [
                        '#a71d2a', '#d2600a', '#d39e00', '#1a9f7f', '#0f6848'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Number of IPs'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Threat Level'
                        }
                    }
                }
            }
        });
    }

    // Load initial data
    loadHistory();
    loadStats();
    
    // Initially disable Quick Actions buttons until an IP is analyzed
    document.getElementById('blockIpBtn').disabled = true;
    document.getElementById('reportAbuseBtn').disabled = true;
});