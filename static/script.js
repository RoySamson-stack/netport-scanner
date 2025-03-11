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
document.getElementById('toggleButton').addEventListener('click', function() {
    var targetDiv2 = document.getElementById('targetDiv2');
    if (targetDiv2.style.display === 'none' || targetDiv2.style.display === '') {
        targetDiv2.style.display = 'block';
    } else {
        targetDiv2.style.display = 'none';
    }
});
document.getElementById('toggleSidePanelButton').addEventListener('click', function() {
    var sidePanel = document.getElementById('sidePanel');
    if (sidePanel.classList.contains('open')) {
        sidePanel.classList.remove('open');
    } else {
        sidePanel.classList.add('open');
    }
});

document.getElementById('toggleSidePanelButton').addEventListener('click', function () {
    const sidePanel = document.getElementById('sidePanel');
    sidePanel.classList.toggle('active'); 
});