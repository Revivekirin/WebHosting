// Assume you have a function to fetch daily analysis data from your backend/API
// This function returns data in the format { date: '2022-01-05', count: 10 }
async function fetchDailyAnalysisData() {
    const baseUrl = 'https://github.com/Revivekirin/StaticWebHosting/tree/main/count';
    const currentDate = new Date();
    const currentDay = currentDate.toISOString().split('T')[0]; // Get the current date in YYYY-MM-DD format

    try {
        const response = await fetch(baseUrl + currentDay + '.txt');
        const data = await response.text();

        // Parse the data from the file
        const lines = data.split('\n');
        const result = lines.map(line => {
            const parts = line.split(/\s+/);
            return { date: parts[0], count: parseInt(parts[1]) };
        });

        return result;
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
