
// main.js

document.addEventListener('DOMContentLoaded', async function() {
    var textFileURL = 'file_urls.txt';

    try {
        const dataResponse = await fetch(textFileURL);
        const data = await dataResponse.text();

        var lines = data.split('\n');

        lines.forEach(async function(line) {
            if (line.trim() !== '') {
                var parts = line.split(/\s+/);
                var timestamp = parts[0] + ' ' + parts[1];
                var count = parts[2];
                var filePath = parts.slice(3).join(' ');

                appendFileLink(filePath, timestamp, count);
            }
        });

        // Fetch the daily analysis data from GitHub using the function from graph.js
        const dailyAnalysisData = await fetchDailyAnalysisData();

        // Fetch specific count data from separate text files
        const specificCountDataPromises = lines.map(async function(line) {
            if (line.trim() !== '') {
                var parts = line.split(/\s+/);
                var date = parts[0];
                var specificCountDataURL = `https://github.com/Revivekirin/StaticWebHosting/count/${date}.txt`;
                const specificCountDataResponse = await fetch(specificCountDataURL);
                const specificCountData = await specificCountDataResponse.text();
                const specificCountLines = specificCountData.split('\n');

                return specificCountLines.map(specificCountLine => {
                    const specificCountParts = specificCountLine.split(/\s+/);
                    return { date, count: parseInt(specificCountParts[1]) };
                });
            }
        });

        // Wait for all promises to resolve
        const specificCountDataArray = await Promise.all(specificCountDataPromises);

        // Combine specific count data with fetched data
        const combinedData = [...dailyAnalysisData, ...specificCountDataArray.flat()];

        // Update the chart with combined data
        createDailyAnalysisChart(combinedData);
    } catch (error) {
        console.error('Error fetching data:', error);
    }

    function appendFileLink(filePath, timestamp, count) {
        var fileName = filePath.split('/').pop();
        var listItem = document.createElement('li');
        listItem.innerHTML = '<a href="' + filePath + '" download>' + fileName + '</a> (' + timestamp + ', Count: ' + count + ')';
        document.getElementById('fileList').appendChild(listItem);
    }

    window.filterFiles = function() {
        var input, filter, ul, li, a, i, txtValue;
        input = document.getElementById('searchBox');
        filter = input.value.toUpperCase();
        ul = document.getElementById('fileList');
        li = ul.getElementsByTagName('li');

        for (i = 0; i < li.length; i++) {
            a = li[i].getElementsByTagName('a')[0];
            txtValue = a.textContent || a.innerText;
            if (txtValue.toUpperCase().indexOf(filter) > -1) {
                li[i].style.display = '';
            } else {
                li[i].style.display = 'none';
            }
        }
    };
});
