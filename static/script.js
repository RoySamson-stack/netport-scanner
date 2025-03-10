document.getElementById('scanForm').addEventListener('submit', function (e) {
    e.preventDefault();
    const formData = new FormData(this);

    fetch('/scan', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        const resultsOutput = document.getElementById('resultsOutput');
        const downloadLink = document.getElementById('downloadLink');

        if (data.status === 'success') {
            resultsOutput.textContent = JSON.stringify(data.results, null, 2);

            downloadLink.href = data.download_link;
            downloadLink.style.display = 'block';
        } else {
            resultsOutput.textContent = `Error: ${data.message}`;
            downloadLink.style.display = 'none';
        }
    })
    .catch(error => {
        console.error('Error:', error);
    });
});