document.addEventListener('DOMContentLoaded', () => {
    // Check authentication
    const authToken = localStorage.getItem('authToken');
    const username = localStorage.getItem('username');

    if (!authToken) {
        // Redirect to login if not authenticated
        window.location.href = '/';
        return;
    }

    // Set username
    document.getElementById('username').textContent = username;

    // Logout functionality
    const logoutBtn = document.getElementById('logout-btn');
    logoutBtn.addEventListener('click', async () => {
        try {
            const response = await fetch('/logout', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${authToken}`
                }
            });

            if (response.ok) {
                // Clear authentication data
                localStorage.removeItem('authToken');
                localStorage.removeItem('username');
                
                // Redirect to login
                window.location.href = '/';
            } else {
                console.error('Logout failed');
            }
        } catch (error) {
            console.error('Logout error:', error);
        }
    });

    // Fetch and render compliance data
    async function fetchComplianceStatus() {
        try {
            const response = await fetch('/api/compliance_status', {
                headers: {
                    'Authorization': `Bearer ${authToken}`
                }
            });
            const data = await response.json();

            // Update overall compliance score
            document.getElementById('overall-compliance-score').textContent = 
                `${data.overall_compliance}%`;

            // Render compliance frameworks chart
            const frameworkNames = Object.keys(data.frameworks);
            const frameworkScores = Object.values(data.frameworks);

            const complianceChart = {
                x: frameworkNames,
                y: frameworkScores,
                type: 'bar',
                marker: {
                    color: 'rgba(102, 126, 234, 0.7)',
                    line: {
                        color: 'rgba(102, 126, 234, 1)',
                        width: 1.5
                    }
                }
            };

            Plotly.newPlot('compliance-chart', [complianceChart], {
                title: 'Compliance Frameworks',
                xaxis: { title: 'Frameworks' },
                yaxis: { title: 'Compliance Score (%)' }
            });

            // Render compliance trend
            const trendChart = {
                x: Array.from({length: data.trend.length}, (_, i) => i + 1),
                y: data.trend,
                type: 'line',
                mode: 'lines+markers',
                line: {color: 'rgba(102, 126, 234, 1)'}
            };

            Plotly.plot('compliance-chart', [trendChart], {
                title: 'Compliance Trend',
                xaxis: { title: 'Time Period' },
                yaxis: { title: 'Compliance Score (%)' }
            });
        } catch (error) {
            console.error('Compliance status fetch error:', error);
        }
    }

    // Fetch and render vulnerability data
    async function fetchVulnerabilitySummary() {
        try {
            const response = await fetch('/api/vulnerability_summary', {
                headers: {
                    'Authorization': `Bearer ${authToken}`
                }
            });
            const data = await response.json();

            // Update total vulnerabilities
            document.getElementById('total-vulnerabilities').textContent = 
                data.total_vulnerabilities;

            // Render vulnerability severity distribution
            const severityChart = {
                labels: Object.keys(data.severity_distribution),
                values: Object.values(data.severity_distribution),
                type: 'pie',
                marker: {
                    colors: [
                        'rgba(255, 65, 54, 0.7)',   // Critical
                        'rgba(255, 133, 27, 0.7)', // High
                        'rgba(255, 220, 0, 0.7)',  // Medium
                        'rgba(46, 204, 64, 0.7)'   // Low
                    ]
                }
            };

            Plotly.newPlot('vulnerability-chart', [severityChart], {
                title: 'Vulnerability Severity Distribution'
            });

            // Populate top vulnerabilities list
            const topVulnList = document.getElementById('top-vulnerabilities-list');
            data.top_vulnerabilities.forEach(vuln => {
                const li = document.createElement('li');
                li.textContent = `${vuln.type}: ${vuln.count} instances`;
                topVulnList.appendChild(li);
            });
        } catch (error) {
            console.error('Vulnerability summary fetch error:', error);
        }
    }

    // Fetch and render risk assessment data
    async function fetchRiskAssessment() {
        try {
            const response = await fetch('/api/risk_assessment', {
                headers: {
                    'Authorization': `Bearer ${authToken}`
                }
            });
            const data = await response.json();

            // Render risk categories chart
            const riskCategories = Object.keys(data.risk_categories);
            const riskScores = Object.values(data.risk_categories);

            const riskChart = {
                x: riskCategories,
                y: riskScores,
                type: 'bar',
                marker: {
                    color: 'rgba(126, 74, 178, 0.7)',
                    line: {
                        color: 'rgba(126, 74, 178, 1)',
                        width: 1.5
                    }
                }
            };

            Plotly.newPlot('risk-chart', [riskChart], {
                title: 'Risk Categories',
                xaxis: { title: 'Risk Category' },
                yaxis: { title: 'Risk Score' }
            });
        } catch (error) {
            console.error('Risk assessment fetch error:', error);
        }
    }

    // Initialize dashboard data
    fetchComplianceStatus();
    fetchVulnerabilitySummary();
    fetchRiskAssessment();
});
