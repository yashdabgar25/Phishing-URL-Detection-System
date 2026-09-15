const checkButton = document.getElementById("checkButton");
const urlInput = document.getElementById("urlInput");
const result = document.getElementById("result");
checkButton.addEventListener("click", async function()
{
    const url = urlInput.value.trim();
    if (url === ""){
        result.innerHTML = `
            <div class="result-card error-card">
                <h2> ⚠️ Please enter a URL</h2>
                <p>Enter a website URL to continue.</p>
            </div>
        `;
        return;
    }

    result.innerHTML = `
            <div class="result-card loading-card">
                <h2> 🔍 Checking URL...</h2>
                <p>Please wait while we analyze the URL.</p>
            </div>
         `;
    try {
        const response = await fetch("/check-url", {
            method: "POST",
            headers:{
                "Content-Type": "application/json"
            },
            body:JSON.stringify({
                url: url
            })
        });
        const data = await response.json();

        if (data.status === "success"){

            let resultClass = "";
            let icon = "";

            if (data.message === "Likely Safe"){
                resultClass = "safe-card";
                icon = "";
            }

            if (data.message === "Likely Safe") {
                resultClass = "safe-card";
                icon = "🟢";
            }
            else if (data.message === "Suspicious") {
                resultClass = "warning-card";
                icon = "🟡";
            }
            else {
                resultClass = "danger-card";
                icon = "🔴";
            }

            let checksHTML = `
                <div class="warnings">
                    <h3>🔎 Detection Details</h3>
                    <ul>
                        ${Object.entries(data.checks).map(([check, status]) => `
                    <li><strong>${check}:</strong> ${status === "Passed" ? "✅ Passed" : "❌ Failed"}</li>
                    `).join("")}
                    </ul>
                </div>
            `;
            let warningsHTML = "";

            if (data.warnings.length > 0){
            warningsHTML = `
           <div class = "warnings">
           <h3 ⚠️ Warnings</h3>
           <ul>
                ${data.warnings.map(warning => `<li>${warning}</li>`).join("")}
            </ul>
            </div>
            `;
            }else {
                warningsHTML = `
                    <div class = "warnings"
                        <h3> ✓ No major warnings detected</h3>
                    </div>
                    `;
            }
                    result.innerHTML = 
                    `<div class = "result-card ${resultClass}">

                        <div class = "result-header">
                        <span class = "result-icon">${icon}</span>
                            <div>
                                <h2>${data.message}</h2>
                                <p>URL analysis completed</p>
                            </div>
                        </div>

                        <div class= "url-box">
                            <strong> Scanned URL: </strong>
                            <p>${data.url}</p>
                        </div>

                        <div class = "risk-score">
                            <strong>Risk Score:</strong>
                            <span>${data.risk_score}/10</span>
                        </div>

                        <div class = "risk_level">
                            <strong>Risk Level:</strong>
                            <span>${data.risk_level}</span>
                        </div>

                        ${warningsHTML}
                        ${checksHTML}
                    </div>
                    `;
        }
        else {
            result.innerHTML = `
            <div class = "result-card error-card">
                <h2> ❌ Error</h2>
                <p>${data.message}</p>
            </div>
            `;
        }
    }catch (err) {
        result.innerHTML = `
        <div class = "result-card error-card">
            <h2> ❌ Something went wrong</h2>
            <p>Please try again.</p>
        </div>
        `;

        console.error(err);
    }
});
