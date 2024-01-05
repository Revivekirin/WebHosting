// graph.js

async function fetchDailyAnalysisData() {
    try {
        // Fetch the data from the CSV file
        const csvFileUrl = 'https://raw.githubusercontent.com/Revivekirin/StaticWebHosting/main/count/DailyCount.csv';
        const csvFileResponse = await fetch(csvFileUrl);
        const csvFileData = await csvFileResponse.text();

        // Parse the data from the CSV file
        const csvLines = csvFileData.split('\n');
        const csvData = csvLines.slice(1).map(line => {
            const parts = line.split(',');
            return { date: parts[0], count: parseInt(parts[1]) };
        });

        return csvData;
    } catch (error) {
        console.error('Error fetching daily analysis data:', error);
        return [];
    }
}

// Function to create and update the daily analysis chart
function createDailyAnalysisChart(data) {
    const ctx = document.getElementById('dailyAnalysisChart').getContext('2d');

    const dates = data.map(entry => entry.date);
    const counts = data.map(entry => entry.count);

    const chart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: dates,
            datasets: [{
                label: 'Daily Analysis Count',
                data: counts,
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                borderColor: 'rgba(75, 192, 192, 1)',
                borderWidth: 1
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}


