const API_URL = "http://127.0.0.1:5000/analyze";

chrome.webNavigation.onCompleted.addListener(async (details) => {
    // Only analyze top-level frames
    if (details.frameId !== 0) return;

    const url = details.url;
    if (url.startsWith('chrome://') || url.startsWith('about:')) return;

    console.log(`[AI Phishing] Page loaded: ${url}`);
    // We don't trigger analyzeURL here anymore because content.js will send the message
    // with HTML content for better accuracy.
});

async function analyzeURL(url, tabId, html = null) {
    console.log(`[AI Phishing] Starting analysis for: ${url} (Tab: ${tabId})`);

    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, html })
        });

        if (!response.ok) {
            throw new Error(`API returned ${response.status}: ${response.statusText}`);
        }

        const result = await response.json();
        console.log(`[AI Phishing] Analysis result:`, result);

        // Set badge based on result
        if (result.is_phishing) {
            chrome.action.setBadgeText({ text: "⚠" });
            chrome.action.setBadgeBackgroundColor({ color: "#FF0000" });
            console.warn(`[AI Phishing] 🚨 PHISHING DETECTED: ${url}`, result.explanations);

            // Show system notification for phishing
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icon.png',
                title: '⚠️ Phishing Warning',
                message: `This site may be dangerous!\n${result.explanations[0] || 'Suspicious activity detected'}`,
                priority: 2
            });
        } else {
            chrome.action.setBadgeText({ text: "✓" });
            chrome.action.setBadgeBackgroundColor({ color: "#00FF00" });
            console.log(`[AI Phishing] ✅ Site appears safe: ${url}`);
        }

        // Save result for the popup
        chrome.storage.local.set({ [url]: result });

        // Phase 1: Send result back to content script for on-page feedback
        if (tabId) {
            chrome.tabs.sendMessage(tabId, {
                type: "ANALYSIS_RESULT",
                result: result
            }).catch(err => console.log("Tab closed or script not ready."));
        }

    } catch (error) {

        // console.error(`[AI Phishing] ❌ Error analyzing ${url}:`, error);

        // Set error badge
        chrome.action.setBadgeText({ text: "?" });
        chrome.action.setBadgeBackgroundColor({ color: "#FFA500" });

        // Save error state
        chrome.storage.local.set({
            [url]: {
                error: true,
                message: `Analysis failed: ${error.message}. Is the backend running?`
            }
        });
    }
}


chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === "ANALYZE_CONTENT") {
        analyzeURL(request.url, sender.tab.id, request.html);
    }
});

