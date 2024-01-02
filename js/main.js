
document.addEventListener('DOMContentLoaded', function() {
    var textFileURL = 'file_urls.txt';
    var s3BucketURL = '/'; // Assuming relative paths for Amplify deployment

    fetch(textFileURL)
        .then(response => response.text())
        .then(data => {
            var lines = data.split('\n');

            lines.forEach(function(line) {
                if (line.trim() !== '') {
                    var parts = line.split(/\s+/);
                    var timestamp = parts[0] + ' ' + parts[1];
                    var count = parts[2];
                    var filePath = parts.slice(3).join(' ');

                    appendFileLink(filePath, timestamp, count);
                }
            });
        })
        .catch(error => console.error('Error fetching the text file:', error));

    function appendFileLink(filePath, timestamp, count) {
        var fileName = filePath.split('/').pop();
        var fileURL = s3BucketURL + filePath;
        var listItem = document.createElement('li');
        listItem.innerHTML = '<a href="' + fileURL + '" download>' + fileName + '</a> (' + timestamp + ', Count: ' + count + ')';
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
