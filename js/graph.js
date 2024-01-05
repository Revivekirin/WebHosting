// graph.js

async function fetchDailyAnalysisData() {
    const baseUrl = 'https://github.com/Revivekirin/StaticWebHosting/tree/main/count';

    try {
        // Fetch the list of files in the directory
        const response = await fetch(baseUrl);
        const html = await response.text();

        // Extract file names from the HTML (simplified for demonstration)
        const fileNames = html.match(/<a href=".*?">(.*?\.txt)<\/a>/g).map(match => match.match(/<a href=".*?">(.*?\.txt)<\/a>/)[1]);

        // Fetch data from each file
        const dataPromises = fileNames.map(async fileName => {
            const fileUrl = `${baseUrl}/${fileName}`;
            const fileResponse = await fetch(fileUrl);
            const fileData = await fileResponse.text();

            // Parse the data from the file
            const lines = fileData.split('\n');
            const dateMatch = fileName.match(/^(\d{8}|\d{7})\.txt$/); // Match YYYYMMDD.txt or YYMMDD.txt
            const date = dateMatch ? dateMatch[1] : null;
            

            return lines.map(line => {
                const parts = line.split(/\s+/);
                return { date, count: parseInt(parts[1]) };
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

