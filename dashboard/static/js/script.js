// Sentinel IDS - Dashboard Javascript

let alertsData = [];
let charts = {};

// Initialize charts on DOM Load
document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    fetchDashboardData();
    
    // Auto-refresh every 5 seconds
    setInterval(fetchDashboardData, 5000);
    
    // Setup event listeners for filtering
    document.getElementById("searchInput").addEventListener("keyup", renderAlertsTable);
    document.getElementById("severityFilter").addEventListener("change", renderAlertsTable);
    
    // Manual refresh button
    document.getElementById("refreshBtn").addEventListener("click", () => {
        const btn = document.getElementById("refreshBtn");
        btn.innerHTML = '<i class="bi bi-arrow-repeat spin"></i> Refreshing...';
        fetchDashboardData().then(() => {
            setTimeout(() => {
                btn.innerHTML = '<i class="bi bi-arrow-repeat"></i> Refresh';
            }, 500);
        });
    });
    
    // Update live clock
    setInterval(updateClock, 1000);
    updateClock();
});

function updateClock() {
    const now = new Date();
    document.getElementById("currentTime").innerText = now.toLocaleString();
}

function initCharts() {
    // Shared chart options for dark theme
    const commonOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: { color: '#f8f9fa', font: { weight: '600' } }
            },
            tooltip: {
                backgroundColor: 'rgba(21, 27, 43, 0.95)',
                titleColor: '#f8f9fa',
                bodyColor: '#adb5bd',
                borderColor: '#2c3246',
                borderWidth: 1,
                padding: 10,
                displayColors: true,
                boxPadding: 4
            }
        },
        scales: {
            x: {
                ticks: { color: '#adb5bd', font: { size: 11 } },
                grid: { color: 'rgba(255, 255, 255, 0.08)' }
            },
            y: {
                ticks: { color: '#adb5bd', font: { size: 11 } },
                grid: { color: 'rgba(255, 255, 255, 0.08)' }
            }
        }
    };

    const pieOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'right',
                labels: { color: '#f8f9fa', font: { weight: '600' } }
            },
            tooltip: commonOptions.plugins.tooltip
        }
    };

    // Protocol Distribution (Pie Chart)
    const ctxProtocol = document.getElementById('protocolChart').getContext('2d');
    charts.protocol = new Chart(ctxProtocol, {
        type: 'pie',
        data: {
            labels: ['TCP', 'UDP', 'ICMP'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#0d6efd', '#20c997', '#ffc107'],
                borderColor: '#151b2b',
                borderWidth: 2
            }]
        },
        options: pieOptions
    });

    // Severity Distribution (Doughnut Chart)
    const ctxSeverity = document.getElementById('severityChart').getContext('2d');
    charts.severity = new Chart(ctxSeverity, {
        type: 'doughnut',
        data: {
            labels: ['HIGH', 'MEDIUM', 'LOW'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#ff4d5a', '#fd7e14', '#20c997'],
                borderColor: '#151b2b',
                borderWidth: 2
            }]
        },
        options: pieOptions
    });

    // Top Attackers (Bar Chart)
    const ctxAttackers = document.getElementById('attackersChart').getContext('2d');
    charts.attackers = new Chart(ctxAttackers, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Alerts',
                data: [],
                backgroundColor: '#0d6efd',
                borderRadius: 4
            }]
        },
        options: {
            ...commonOptions,
            plugins: { 
                ...commonOptions.plugins,
                legend: { display: false } 
            }
        }
    });

    // Alerts Timeline (Line Chart)
    const ctxTimeline = document.getElementById('timelineChart').getContext('2d');
    charts.timeline = new Chart(ctxTimeline, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Alerts',
                data: [],
                borderColor: '#ff4d5a',
                backgroundColor: 'rgba(255, 77, 90, 0.15)',
                borderWidth: 2,
                fill: true,
                tension: 0.3,
                pointBackgroundColor: '#151b2b',
                pointBorderColor: '#ff4d5a',
                pointBorderWidth: 2,
                pointRadius: 4,
                pointHoverRadius: 6
            }]
        },
        options: commonOptions
    });
}

async function fetchDashboardData() {
    try {
        const response = await fetch('/api/dashboard-data');
        
        if (!response.ok) throw new Error('API Error');
        
        const data = await response.json();
        
        // Update connection status
        updateConnectionStatus(true);
        
        // Update Summary Cards
        updateSummaryCards(data);
        
        // Update Charts
        updateCharts(data.charts);
        updateTimelineChart(data.recent_alerts);
        
        // Update Alerts Table
        alertsData = data.recent_alerts;
        renderAlertsTable();
        
    } catch (error) {
        console.error("Failed to fetch dashboard data:", error);
        updateConnectionStatus(false);
    }
}

function updateConnectionStatus(isConnected) {
    const statusDot = document.getElementById('statusIndicator');
    const statusText = document.getElementById('statusText');
    
    if (isConnected) {
        statusDot.classList.remove('offline');
        statusText.innerText = "Monitoring Live";
        statusText.classList.remove('text-danger');
        statusText.classList.add('text-success');
    } else {
        statusDot.classList.add('offline');
        statusText.innerText = "Disconnected - Retrying...";
        statusText.classList.remove('text-success');
        statusText.classList.add('text-danger');
    }
}

function updateSummaryCards(data) {
    document.getElementById('valTotalAlerts').innerText = data.alert_stats.total;
    document.getElementById('valHighAlerts').innerText = data.alert_stats.high;
    document.getElementById('valMediumAlerts').innerText = data.alert_stats.medium;
    document.getElementById('valLowAlerts').innerText = data.alert_stats.low;
    
    document.getElementById('valTotalPackets').innerText = data.stats.total_packets;
    document.getElementById('valTopAttacker').innerText = data.top_attacker;
}

function updateCharts(chartData) {
    // Protocol Chart
    charts.protocol.data.datasets[0].data = [
        chartData.protocols.TCP || 0,
        chartData.protocols.UDP || 0,
        chartData.protocols.ICMP || 0
    ];
    charts.protocol.update();

    // Severity Chart
    charts.severity.data.datasets[0].data = [
        chartData.severities.HIGH || 0,
        chartData.severities.MEDIUM || 0,
        chartData.severities.LOW || 0
    ];
    charts.severity.update();

    // Attackers Chart
    const attackerIps = Object.keys(chartData.top_attackers);
    const attackerCounts = Object.values(chartData.top_attackers);
    
    charts.attackers.data.labels = attackerIps;
    charts.attackers.data.datasets[0].data = attackerCounts;
    charts.attackers.update();
}

function updateTimelineChart(recentAlerts) {
    // Group alerts by hour (or just show the last 10 alerts for simplicity)
    // For a simple timeline, let's reverse the top 10 alerts and plot them
    const latest = [...recentAlerts].slice(0, 15).reverse();
    
    charts.timeline.data.labels = latest.map(a => a[0].split(' ')[1] || a[0]); // Time portion
    charts.timeline.data.datasets[0].data = latest.map((a, i) => i + 1); // Mock cumulative or just scatter
    
    // To make it an actual timeline of counts, we would group by time. 
    // Let's do a simple grouping by minute.
    const countsByMinute = {};
    recentAlerts.forEach(alert => {
        const timeParts = alert[0].split(':');
        if(timeParts.length >= 2) {
            const minute = timeParts[0] + ':' + timeParts[1];
            countsByMinute[minute] = (countsByMinute[minute] || 0) + 1;
        }
    });
    
    const sortedMinutes = Object.keys(countsByMinute).sort().slice(-10);
    charts.timeline.data.labels = sortedMinutes;
    charts.timeline.data.datasets[0].data = sortedMinutes.map(m => countsByMinute[m]);
    
    charts.timeline.update();
}

function renderAlertsTable() {
    const searchTerm = document.getElementById("searchInput").value.toLowerCase();
    const severityFilter = document.getElementById("severityFilter").value;
    const tbody = document.getElementById("alertsTableBody");
    
    tbody.innerHTML = "";
    
    const filteredAlerts = alertsData.filter(alert => {
        const time = alert[0].toLowerCase();
        const type = alert[1].toLowerCase();
        const ip = alert[2].toLowerCase();
        const severity = alert[3];
        
        const matchesSearch = time.includes(searchTerm) || type.includes(searchTerm) || ip.includes(searchTerm);
        const matchesSeverity = (severityFilter === "ALL") || (severity === severityFilter);
        
        return matchesSearch && matchesSeverity;
    });
    
    if (filteredAlerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted py-4">No alerts found matching your criteria.</td></tr>`;
        return;
    }
    
    filteredAlerts.forEach(alert => {
        const severity = alert[3];
        let badgeClass = "badge-low";
        let icon = "bi-shield-check";
        
        if (severity === "HIGH") {
            badgeClass = "badge-high";
            icon = "bi-shield-fill-x";
        } else if (severity === "MEDIUM") {
            badgeClass = "badge-medium";
            icon = "bi-shield-exclamation";
        }
        
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td>${alert[0]}</td>
            <td class="fw-medium">${alert[1]}</td>
            <td class="font-monospace">${alert[2]}</td>
            <td>
                <span class="badge ${badgeClass} px-2 py-1 rounded-pill">
                    <i class="bi ${icon} me-1"></i> ${severity}
                </span>
            </td>
        `;
        tbody.appendChild(tr);
    });
}
