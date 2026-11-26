const checkButton = document.getElementById("checkButton");
const urlInput = document.getElementById("urlInput");
const result = document.getElementById("result");

checkButton.addEventListener("click", async function () {

    const url = urlInput.value.trim();

    if (url === "") {
        result.innerHTML = `
            <div class="result-card error-card">
                <h2>⚠️ Please enter a URL</h2>
                <p>Enter a website URL to continue.</p>
            </div>`;
        return;
    }

    result.innerHTML = `
        <div class="result-card loading-card">
            <h2>🔍 V7 Scanning...</h2>
            <p>Please wait while we analyze the URL.</p>
        </div>`;

    checkButton.disabled = true;

    try {
        const response = await fetch("/check_url_v7", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (data.status !== "success") {
            throw new Error(data.message || "V7 scan failed.");
        }

        const v = data.v7_result;
        const risk = v.risk_score || {};
        const indicators = v.risk_indicators || {};
        const live = v.live_analysis || {};
        const google = v.google_safe_browsing || {};
        const ml = v.ml_prediction;

        const score = risk.score ?? 0;
        const level = risk.risk_level || "Unknown";

        let resultClass = "safe-card";
        let icon = "🟢";

        if (score >= 80) {
            resultClass = "danger-card";
            icon = "🔴";
        } else if (score >= 60) {
            resultClass = "danger-card";
            icon = "🚨";
        } else if (score >= 40) {
            resultClass = "warning-card";
            icon = "🟠";
        } else if (score >= 20) {
            resultClass = "warning-card";
            icon = "🟡";
        }

        // Risk indicators
        const triggered = risk.triggered_indicators || [];

        let indicatorsHTML = "";

        if (triggered.length > 0) {
            indicatorsHTML = `
                <div class="warnings">
                    <h3>⚠️ Risk Indicators</h3>
                    <ul>
                        ${triggered.map(item => `
                            <li>
                                <strong>${item.category}</strong>
                                <p>${item.description}</p>
                                <small>Risk points: +${item.points}</small>
                            </li>
                        `).join("")}
                    </ul>
                </div>`;
        } else {
            indicatorsHTML = `
                <div class="warnings">
                    <h3>✅ No Risk Indicators Triggered</h3>
                    <p>No scored risk indicators were triggered in this scan.</p>
                </div>`;
        }

        // Google Safe Browsing
        let googleHTML = "";

        if (google.success) {
            googleHTML = google.threat_found
                ? `<p>🔴 Threat detected</p>
                   <p>${google.message || ""}</p>`
                : `<p>✅ No threat found</p>
                   <p>${google.message || ""}</p>`;
        } else {
            googleHTML = `
                <p>⚪ Google Safe Browsing unavailable</p>
                <p>${google.message || "Unable to check this source."}</p>`;
        }

        // DNS
        const dns = live.dns || {};

        const dnsHTML = `
            <p>
                <strong>Status:</strong>
                ${dns.success ? "✅ Successful" : "⚠️ Unavailable"}
            </p>
            <p><strong>Hostname:</strong> ${dns.hostname || "N/A"}</p>
            <p><strong>IP Addresses:</strong>
                ${(dns.ip_addresses || []).join(", ") || "N/A"}
            </p>
            <p>${dns.message || ""}</p>
        `;

        // HTTP
        const http = live.http || {};

        const httpHTML = `
            <p>
                <strong>Status:</strong>
                ${http.success ? "✅" : "⚠️"}
                ${http.status_code ?? "N/A"}
                ${http.status_text || ""}
            </p>
            <p><strong>Server:</strong> ${http.server || "N/A"}</p>
            <p><strong>Content Type:</strong> ${http.content_type || "N/A"}</p>
            <p>${http.message || ""}</p>
        `;

        // Redirects
        const redirects = live.redirects || {};

        const redirectHTML = `
            <p><strong>Redirect Count:</strong>
                ${redirects.redirect_count ?? "N/A"}
            </p>
            <p><strong>Final URL:</strong>
                ${redirects.final_url || "N/A"}
            </p>
            <p>${redirects.message || ""}</p>
        `;

        // TLS
        const tls = live.tls || {};

        const tlsHTML = `
            <p>
                <strong>Status:</strong>
                ${tls.success ? "✅ Verified" : "⚠️ Problem or unavailable"}
            </p>
            <p><strong>TLS Version:</strong>
                ${tls.tls_version || "N/A"}
            </p>
            <p><strong>Certificate Issuer:</strong>
                ${tls.certificate_issuer || "N/A"}
            </p>
            <p>${tls.message || ""}</p>
        `;

        // Other threat database results
        const phishtank = v.phishtank || {};
        const urlhaus = v.urlhaus || {};

        // ML result
        const mlHTML = `
            <p><strong>ML Prediction:</strong>
                ${ml !== undefined && ml !== null ? ml : "N/A"}
            </p>
            <p><strong>ML Probabilities:</strong>
                ${(v.ml_probabilities || []).join(", ") || "N/A"}
            </p>
            <small>ML output is shown separately from the risk score.</small>
        `;

        // Feature summary
        const featureItems = [
            ["URL Length", v.features?.url_length],
            ["Domain Length", v.features?.domain_length],
            ["Subdomains", v.features?.no_of_subdomains],
            ["Suspicious Keywords", v.features?.suspicious_keyword_count],
            ["Hostname Entropy", v.features?.hostname_entropy],
            ["HTTPS", v.features?.has_https ? "Yes" : "No"]
        ];

        const featuresHTML = `
            <ul>
                ${featureItems.map(([name, value]) => `
                    <li><strong>${name}:</strong> ${value ?? "N/A"}</li>
                `).join("")}
            </ul>
        `;

        result.innerHTML = `
            <div class="result-card ${resultClass}">

                <div class="result-header">
                    <span class="result-icon">${icon}</span>
                    <div>
                        <h2>${level}</h2>
                        <p>V7 Analysis Completed</p>
                    </div>
                </div>

                <div class="url-box">
                    <strong>Scanned URL:</strong>
                    <p>${v.url || url}</p>
                </div>

                <div class="risk-score">
                    <strong>Risk Score:</strong>
                    <span>${score}/100</span>
                </div>

                <div class="risk-meter">
                    <div class="risk-meter-track">
                        <div class="risk-meter-fill" style="width: ${Math.max(0, Math.min(100, Number(score) || 0))}%"></div>
                    </div>

                    <div class="risk-meter-labels">
                        <span>0 – Low</span>
                        <span>20 – Moderate</span>
                        <span>40 – Suspicious</span>
                        <span>60 – High</span>
                        <span>80 – Critical</span>
                    </div>
                </div>

                <div class="risk-level">
                    <strong>Risk Level:</strong>
                    <span>${level}</span>
                </div>

                <div class="warnings">
                    <h3>🛡️ Risk Analysis</h3>
                    <p>Triggered Indicators: ${risk.total_indicators ?? 0}</p>
                    <p>Maximum Score: ${risk.max_score ?? 100}</p>
                </div>

                ${indicatorsHTML}

                <div class="warnings">
                    <h3>🌐 Google Safe Browsing</h3>
                    ${googleHTML}
                </div>

                <div class="warnings">
                    <h3>🌍 DNS Analysis</h3>
                    ${dnsHTML}
                </div>

                <div class="warnings">
                    <h3>📡 HTTP Analysis</h3>
                    ${httpHTML}
                </div>

                <div class="warnings">
                    <h3>🔄 Redirect Analysis</h3>
                    ${redirectHTML}
                </div>

                <div class="warnings">
                    <h3>🔐 TLS / Certificate Analysis</h3>
                    ${tlsHTML}
                </div>

                <div class="warnings">
                    <h3>🤖 Machine Learning Analysis</h3>
                    ${mlHTML}
                </div>

                <div class="warnings">
                    <h3>📊 URL Feature Summary</h3>
                    ${featuresHTML}
                </div>

                <div class="warnings">
                    <h3>🐟 PhishTank</h3>
                    <p>${phishtank.message || "No result available."}</p>
                    <p>Status: ${phishtank.success ? "Available" : "Unavailable"}</p>
                </div>

                <div class="warnings">
                    <h3>🛡️ URLhaus</h3>
                    <p>${urlhaus.message || "No result available."}</p>
                    <p>Status: ${urlhaus.success ? "Available" : "Unavailable"}</p>
                </div>

                <div class="report-download">
                    <button type="button" id="copyScanSummary" class="copy-summary-btn">
                        📋 Copy Scan Summary
                    </button>
                </div>

            </div>
        `;
        const copySummaryButton = document.getElementById("copyScanSummary");

        if (copySummaryButton) {
            copySummaryButton.addEventListener("click", async () => {

                const detectedIndicators = Object.entries(indicators)
                    .filter(([key, value]) => value === true)
                    .map(([key]) => key.replace(/_/g, " "))
                    .join(", ");

                const summary = 
                `URL GUARD - V7 SCAN REPORT

                URL: ${v.url || url}
                Risk Score: ${score}/100
                Risk Level: ${level}
                Triggered Indicators: ${risk.total_indicators ?? 0}

                Detected Indicators:
                ${detectedIndicators || "None detected"}

                Google Safe Browsing: ${
                    google.success
                        ? (google.threat_found ? "Threat detected" : "No threat found")
                        : "Unavailable"
                }

                Disclaimer: Automated analysis cannot guarantee website safety.`;

                try {
                    await navigator.clipboard.writeText(summary);
                    copySummaryButton.textContent = "✅ Summary Copied!";
                } catch (error) {
                    copySummaryButton.textContent = "❌ Copy Failed";
                    console.error(error);
                }
            });
        }

    } catch (err) {

        result.innerHTML = `
            <div class="result-card error-card">
                <h2>❌ V7 Scan Failed</h2>
                <p>${err.message || "Please try again."}</p>
            </div>
        `;

        console.error(err);

    } finally {
        checkButton.disabled = false;
    }
});