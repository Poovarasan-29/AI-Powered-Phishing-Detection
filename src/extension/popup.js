chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const currentTab = tabs[0];
    const url = currentTab.url;

    document.getElementById('url').textContent = url;

    chrome.storage.local.get([url], (result) => {
        const data = result[url];
        if (data) {
            if (data.error) {
                // Show error state
                document.getElementById('verdict').textContent = "Error";
                document.getElementById('verdict').className = "verdict warning";
                document.getElementById('score').textContent = "N/A";
                document.getElementById('reasons-container').style.display = "block";
                document.getElementById('reasons-list').innerHTML = `<li>${data.message}</li>`;
            } else {
                updateUI(data);
            }
        } else {
            // If no stored result, show loading
            document.getElementById('verdict').textContent = "Analyzing...";
            document.getElementById('verdict').className = "verdict";
            document.getElementById('score').textContent = "...";
        }
    });

});

function updateUI(data) {
    const scoreElement = document.getElementById('score');
    const verdictElement = document.getElementById('verdict');
    const reasonsContainer = document.getElementById('reasons-container');
    const reasonsList = document.getElementById('reasons-list');

    const prob = (data.probability * 100).toFixed(1);
    scoreElement.textContent = `${prob}%`;

    if (data.is_phishing) {
        verdictElement.textContent = "High Risk";
        verdictElement.className = "verdict danger";
        scoreElement.style.color = "#dc3545";

        if (data.explanations && data.explanations.length > 0) {
            reasonsContainer.style.display = "block";
            reasonsList.innerHTML = "";
            data.explanations.forEach(reason => {
                const li = document.createElement('li');
                li.textContent = reason;
                reasonsList.appendChild(li);
            });
        }
    } else {
        verdictElement.textContent = "Safe";
        verdictElement.className = "verdict safe";
        scoreElement.style.color = "#28a745";
        reasonsContainer.style.display = "none";
    }
}
