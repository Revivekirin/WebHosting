// main.js
document.addEventListener('DOMContentLoaded', async function() {
    var textFileURL = 'file_urls.txt';

    try {
        const dataResponse = await fetch(textFileURL);
        const data = await dataResponse.text();

        var lines = data.split('\n');
        const filesPerPage = 50;
        let currentPage = 1;

    
        function displayFiles(startIndex, endIndex) {
            for (let i = startIndex; i < endIndex && i < lines.length; i++) {
                const line = lines[i].trim();
                if (line !== '') {
                    var parts = line.split(/\s+/);
                    var timestamp = parts[0] + ' ' + parts[1];
                    var count = parts[2];
                    var filePath = parts.slice(3).join(' ');
    
                    appendFileLink(filePath, timestamp, count);
                }
            }
        }
    
        function updatePagination() {
            const totalPages = Math.ceil(lines.length / filesPerPage);
            var paginationContainer = document.getElementById('pagination');
            paginationContainer.innerHTML = '';
    
            var prevButton = document.createElement('button');
            prevButton.innerHTML = '이전';
            prevButton.onclick = function() {
                if (currentPage > 1) {
                    currentPage--;
                    document.getElementById('fileList').innerHTML = '';
                    displayFiles((currentPage - 1) * filesPerPage, currentPage * filesPerPage);
                    updatePagination();
                }
            };
            paginationContainer.appendChild(prevButton);
    
            const startPage = Math.max(1, Math.floor((currentPage - 1) / 10) * 10 + 1);
            const endPage = Math.min(startPage + 9, totalPages);
    
            for (let i = startPage; i <= endPage; i++) {
                var pageButton = document.createElement('button');
                pageButton.innerHTML = i;
                pageButton.onclick = function() {
                    currentPage = i;
                    document.getElementById('fileList').innerHTML = '';
                    displayFiles((currentPage - 1) * filesPerPage, currentPage * filesPerPage);
                    updatePagination();
                };
                paginationContainer.appendChild(pageButton);
            }
    
            var nextButton = document.createElement('button');
            nextButton.innerHTML = '다음';
            nextButton.onclick = function() {
                if (currentPage < totalPages) {
                    currentPage++;
                    document.getElementById('fileList').innerHTML = '';
                    displayFiles((currentPage - 1) * filesPerPage, currentPage * filesPerPage);
                    updatePagination();
                }
            };
            paginationContainer.appendChild(nextButton);
        }
    
        // Display files for the first page
        displayFiles(0, filesPerPage);
    
        // Display pagination buttons
        updatePagination();
        // Fetch the daily analysis data from GitHub using the function from graph.js
        const dailyAnalysisData = await fetchDailyAnalysisData();

        // Update the chart with new data
        createDailyAnalysisChart(dailyAnalysisData);
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
