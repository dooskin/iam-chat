// Fetch and display access patterns data
async function fetchAccessPatterns() {
    try {
        const response = await fetch('/api/access-patterns');
        const data = await response.json();
        
        createResourceChart(data.resource_stats);
        createActionChart(data.action_stats);
        createTimelineChart(data.timeline_data);
    } catch (error) {
        console.error('Error fetching access patterns:', error);
    }
}

function createResourceChart(data) {
    const ctx = document.getElementById('resourceChart').getContext('2d');
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.map(d => d.resource_name),
            datasets: [{
                label: 'Access Count',
                data: data.map(d => d.count),
                backgroundColor: 'rgba(54, 162, 235, 0.5)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });
}

function createActionChart(data) {
    const ctx = document.getElementById('actionChart').getContext('2d');
    new Chart(ctx, {
        type: 'pie',
        data: {
            labels: data.map(d => d.action_type),
            datasets: [{
                data: data.map(d => d.count),
                backgroundColor: [
                    'rgba(54, 162, 235, 0.5)',
                    'rgba(255, 99, 132, 0.5)',
                    'rgba(255, 206, 86, 0.5)',
                    'rgba(75, 192, 192, 0.5)'
                ]
            }]
        },
        options: {
            responsive: true
        }
    });
}

function createTimelineChart(data) {
    const ctx = document.getElementById('timelineChart').getContext('2d');
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.map(d => new Date(d.date).toLocaleDateString()),
            datasets: [{
                label: 'Access Count',
                data: data.map(d => d.count),
                borderColor: 'rgba(75, 192, 192, 1)',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });
}

// Initialize charts when page loads
document.addEventListener('DOMContentLoaded', fetchAccessPatterns);
