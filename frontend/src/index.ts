document.getElementById('scanForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();

    const target = (document.getElementById('target') as HTMLInputElement).value;
    const ports = (document.getElementById('ports') as HTMLInputElement).value;

    const response = await fetch('http://localhost:5000/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ target, ports }),
    });

    const data = await response.json();
    const resultsElement = document.getElementById('results');

    if (resultsElement) {
        if (response.ok) {
            resultsElement.textContent = `Scan completed. Results saved to: ${data.file}`;
        } else {
            resultsElement.textContent = `Error: ${data.error}`;
        }
    }
});