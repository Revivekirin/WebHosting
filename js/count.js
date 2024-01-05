// count.js

document.addEventListener('DOMContentLoaded', async function() {
    const baseUrl = 'https://raw.githubusercontent.com/Revivekirin/StaticWebHosting/main/count';


    // Fetch the data from the CSV file
    const csvFileUrl = 'https://raw.githubusercontent.com/Revivekirin/StaticWebHosting/main/count/DailyCount.csv';


    try{

        const csvFileResponse = await fetch(csvFileUrl);
        const csvFileData = await csvFileResponse.text();

        // Parse the data from the CSV file
        const csvLines = csvFileData.split('\n');
        const csvData = csvLines.slice(1).map(line => {
            const parts = line.split(',');
            const count = parts[1] !== 'null' && !isNaN(parts[1]) ? parseInt(parts[1]) : 0;
            return { date: parts[0], count };
        });
        
        // Calculate the total sum of 'count' values including null
        const totalCount = csvData.reduce((sum, entry) => sum + entry.count, 0);
        
        // console.log(totalCount.toString())

        const yesterday = new Date();
        yesterday.setDate(yesterday.getDate() - 1);

        // 어제 날짜에 해당하는 파일명 생성
        const fileName = formatDate(yesterday) +'.txt';
        const fileUrl = `${baseUrl}/${fileName}`;

        // console.log(fileName);


        // 해당 파일에서 데이터 가져오기
        const fileResponse = await fetch(fileUrl);
        const fileData = await fileResponse.text();

        // 텍스트 파일의 내용을 화면에 표시
        displayDailyCount(fileData);

        displayTotalCount(totalCount);


    } catch (error) {
        console.error('Error fetching data:', error);
    }

    // 텍스트 파일의 내용을 화면에 표시하는 함수
    function displayDailyCount(content) {
        var contentElement = document.getElementById('displayDailyCount');
        contentElement.textContent = content;
    }

    // 텍스트 파일의 내용을 화면에 표시하는 함수
    function displayTotalCount(content) {
        var contentElement = document.getElementById('displayTotalCount');
        contentElement.textContent = content;
    }
    

    // 날짜 포맷팅 함수
    function formatDate(date) {
        const year = date.getFullYear();
        const month = (date.getMonth()+1).toString().padStart(2, '0'); // 수정된 부분
        const day = date.getDate().toString().padStart(2, '0');
        return `${year}${month}${day}`;
    }
});
