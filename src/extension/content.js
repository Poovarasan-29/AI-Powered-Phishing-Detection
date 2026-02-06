// Show "I'm verifying..." notification
const notify = document.createElement('div');
notify.id = 'ai-phishing-detector-notice';
notify.style.cssText = `
    position: fixed; 
     top: 20px; 
     right: 20px; 
     z-index: 2147483647; 
     background: #1a1a1a; 
     color: #ffffff; 
     padding: 12px 24px; 
     border-radius: 12px; 
     font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; 
     font-size: 14px;
     font-weight: 500;
     box-shadow: 0 8px 32px rgba(0,0,0,0.3); 
     border-left: 5px solid #007bff;
     display: flex;
     align-items: center;
     gap: 12px;
     transition: all 0.5s cubic-bezier(0.4, 0, 0.2, 1);
     transform: translateX(200%);
`;
notify.innerHTML = `
    <span style="font-size: 18px;">🔍</span>
    <span>AI Phishing Detector: <b>I'm verifying...</b></span>
`;
document.body.appendChild(notify);

// Slide in
setTimeout(() => {
    notify.style.transform = 'translateX(0)';
}, 100);

// Slide out and remove after 3.5 seconds
setTimeout(() => {
    notify.style.transform = 'translateX(200%)';
    setTimeout(() => notify.remove(), 600);
}, 3500);

// Extract HTML, removing sensitive values before sending
const clone = document.documentElement.cloneNode(true);
clone.querySelectorAll('input[type="password"], input[type="text"]').forEach(el => {
    el.value = ""; // Clear any typed values
    el.setAttribute('value', '');
});

const htmlContent = clone.outerHTML;
const currentUrl = window.location.href;

chrome.runtime.sendMessage({
    type: "ANALYZE_CONTENT",
    url: currentUrl,
    html: htmlContent
});

console.log("AI Phishing Detector: Content captured and sent for analysis.");

// Listen for the result from background.js
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "ANALYSIS_RESULT") {
        const result = message.result;
        const notice = document.getElementById('ai-phishing-detector-notice');

        if (result.is_phishing) {
            if (notice) notice.remove(); // Remove toast if it exists
            showWarningPage(result);
        } else {
            // Update toast for non-phishing results
            if (!notice) return;

            if (result.method === "rule-based (whitelist)") {
                notice.style.background = "#28a745";
                notice.style.borderLeft = "5px solid #ffffff";
                notice.innerHTML = `<span style="font-size: 18px;">✅</span><span>AI Phishing Detector: <b>Safe Website</b></span>`;
            } else {
                notice.style.background = "#6c757d";
                notice.innerHTML = `<span style="font-size: 18px;">ℹ️</span><span>AI Phishing Detector: <b>Analysis Complete, Safe ✅</b></span>`;
            }

            setTimeout(() => {
                notice.style.transform = 'translateX(200%)';
                setTimeout(() => notice.remove(), 600);
            }, 3000);
        }
    }
});

function showWarningPage(result) {
    const overlay = document.createElement('div');
    overlay.id = 'ai-phishing-overlay';
    overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        background: #000;
        color: white;
        z-index: 2147483647;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        font-family: 'Segoe UI', system-ui, sans-serif;
        text-align: center;
        padding: 20px;  
    `;

    overlay.innerHTML = `
        <div style="max-width: 600px;">
            <div style="font-size: 80px; margin-bottom: 20px;">🚨</div>
            <h1 style="font-size: 32px; margin-bottom: 10px; color: #ff4d4d;">Unsafe site</h1>
            <p style="font-size: 18px; margin-bottom: 30px; line-height: 1.6; color: #ccc;">
                AI Phishing Detector has flagged this site as <b>dangerous</b>. 
                It has been identified as a phishing website in our security database.
            </p>
            

            <button id="back-to-safety" style="
                background: #007bff;
                color: white;
                border: none;
                padding: 15px 40px;
                font-size: 18px;
                font-weight: bold;
                border-radius: 30px;
                cursor: pointer;
                box-shadow: 0 4px 15px rgba(0, 123, 255, 0.4);
                transition: transform 0.2s;
            ">Back to Safety</button>

            <div style="margin-top: 30px;">
                <a id="proceed-anyway" href="#" style="color: #666; font-size: 14px; text-decoration: none;">Proceed anyway (unsafe)</a>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);
    document.body.style.overflow = 'hidden'; // Prevent scrolling
    document.documentElement.style.overflow = 'hidden'; // For some sites

    document.getElementById('back-to-safety').onclick = () => {
        window.history.back();
        setTimeout(() => {
            window.close(); // Browser security might block this if not opened by script
        }, 500);
    };

    document.getElementById('proceed-anyway').onclick = (e) => {
        e.preventDefault();
        overlay.remove();
        document.body.style.overflow = '';
        document.documentElement.style.overflow = '';
    };
}


