// graph.js

async function fetchDailyAnalysisData() {
    const baseUrl = 'https://github.com/Revivekirin/StaticWebHosting/tree/main/count';

    try {
        // Fetch the HTML page of the directory
        const response = await fetch(baseUrl);
        const html = await response.text();

        // Extract file names from the HTML
        const fileNames = extractFileNames(html);

        // Fetch data from each file
        const dataPromises = fileNames.map(async fileName => {
            const fileUrl = `${baseUrl}/${fileName}`;
            const fileResponse = await fetch(fileUrl);
            const fileData = await fileResponse.text();

            // Parse the data from the file
            const lines = fileData.split('\n');
            return lines.map(line => {
                const parts = line.split(/\s+/);
                return { date: parts[0], count: parseInt(parts[1]) };
            });
        });

        // Wait for all promises to resolve
        const dataArray = await Promise.all(dataPromises);

        // Combine data from all files into a single array
        const result = dataArray.flat();

        return result;
    } catch (error) {
        console.error('Error fetching daily analysis data:', error);
        return [];
    }
}

// Helper function to extract file names from HTML
function extractFileNames(html) {
    const regex = /<a href=".*?">(.*?)<\/a>/g;
    const matches = html.matchAll(regex);
    const fileNames = [];

    for (const match of matches) {
        const fileName = match[1];
        if (fileName.endsWith('.txt')) {
            fileNames.push(fileName);
        }
    }

    return fileNames;
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
