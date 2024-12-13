document.addEventListener('DOMContentLoaded', function() {
    const scanForm = document.getElementById('scanForm');
    const scanButton = document.getElementById('scanButton');
    const spinner = scanButton.querySelector('.spinner-border');
    const resultsCard = document.getElementById('resultsCard');
    const scanResults = document.getElementById('scanResults');

    scanForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        // Show loading state
        scanButton.disabled = true;
        spinner.classList.remove('d-none');
        resultsCard.classList.add('d-none');

        const formData = new FormData(scanForm);
        const target = formData.get('target');
        const portRange = formData.get('port_range');

        try {
            const response = await fetch('/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    target: target,
                    port_range: portRange
                })
            });

            const data = await response.json();

            if (response.ok) {
                // Display results
                resultsCard.classList.remove('d-none');
                displayResults(data);
                
                // Show success message if scan completed
                const alertHtml = `
                    <div class="alert alert-success alert-dismissible fade show mb-3" role="alert">
                        Scan completed successfully!
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                `;
                scanResults.insertAdjacentHTML('beforebegin', alertHtml);
            } else {
                showError(data.error || 'An error occurred during the scan');
            }
        } catch (error) {
            showError('Network error occurred');
        } finally {
            // Reset loading state
            scanButton.disabled = false;
            spinner.classList.add('d-none');
        }
    });

    function displayResults(data) {
        let html = `
            <table class="table">
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>State</th>
                        <th>Service</th>
                    </tr>
                </thead>
                <tbody>
        `;

        data.results.forEach(result => {
            html += `
                <tr>
                    <td>${result.port}</td>
                    <td><span class="badge bg-${result.state === 'open' ? 'success' : 'danger'}">${result.state}</span></td>
                    <td>${result.service}</td>
                </tr>
            `;
        });

        html += '</tbody></table>';
        scanResults.innerHTML = html;
    }

    function showError(message) {
        const alertHtml = `
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        `;
        scanResults.innerHTML = alertHtml;
        resultsCard.classList.remove('d-none');
    }
});
