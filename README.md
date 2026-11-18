Phishing URL Detection System (V6)

A web-based system that analyzes website URLs and identifies potentially suspicious or phishing URLs using a hybrid approach combining Machine Learning, rule-based analysis, and VirusTotal threat intelligence.

Project Overview

Phishing attacks are commonly used to trick users into visiting fake websites and sharing sensitive information such as usernames, passwords, banking details, and personal data.

The Phishing URL Detection System (V6) analyzes a given URL using multiple detection techniques to identify potential phishing threats.

The system checks for indicators such as:

- Unusually long URLs
- Missing HTTPS
- IP addresses instead of domain names
- Suspicious keywords and URL patterns
- Multiple hyphens and unusual subdomains
- Suspicious URL symbols
- Brand impersonation
- External redirects
- Machine Learning-based phishing predictions
- VirusTotal threat intelligence results

The system combines these checks to calculate a risk score and classify the URL as:

- Likely Safe
- Suspicious
- Potentially Phishing

Technologies Used

Frontend

- HTML
- CSS
- JavaScript

Backend

- Python
- Flask

Machine Learning

- Random Forest Classifier
- Python-based feature extraction
- JSON-based trained model

Database

- SQLite

Threat Intelligence

- VirusTotal API

Development Tools

- Visual Studio Code
- Git
- GitHub

Main Features

1. URL input and scanning
2. URL validation and normalization
3. Machine Learning-based phishing detection
4. Rule-based URL analysis
5. Brand impersonation detection
6. External redirect detection
7. VirusTotal threat intelligence integration
8. Hybrid risk analysis and risk score calculation
9. Risk level classification
10. Warning messages for detected indicators
11. Scan history with SQLite database storage
12. History search and filtering
13. Clear scan history functionality
14. Separate VirusTotal detection counts in scan history
15. Responsive web interface

Machine Learning Model

The V6 system uses a Random Forest Classifier trained on the PhiUSIIL Phishing URL Dataset.

Model details:

- Algorithm: Random Forest Classifier
- Number of trees: 200
- Number of input features: 37
- Model format used by the application: JSON
- Dataset split: 80% training and 20% testing
- Domain-based splitting was used to reduce overlap between training and testing domains.

Model Evaluation Results

The model was evaluated on 46,605 test records.

Evaluation Metric| Result
Accuracy| 98.41%
Precision| 98.80%
Recall| 97.44%
F1-Score| 98.12%
ROC-AUC| 0.99225
False Positive Rate| 0.87%
False Negative Rate| 2.56%

Note: These metrics represent the trained ML model's performance on the prepared test dataset. They do not guarantee the same performance on every real-world URL. The complete hybrid system has not been independently evaluated using these metrics.

Project Structure

Phishing-URL-Detection-System/
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── script.js
│
├── templates/
│   ├── index.html
│   └── history.html
│
├── V6/
│   ├── feature_extractor_v6.py
│   ├── predictor_v6.py
│   └── train_model_v6.py
│
├── app.py
├── app_v6.py
├── phishing_model_v6.json
├── phishing_history.db
├── README.md
├── .gitignore
└── .env

Note: The ".env" file stores the VirusTotal API key and must not be uploaded to GitHub. The project backup folder and generated dataset files are not shown in this simplified structure.

How the System Works

1. The user enters a website URL.
2. The backend validates and normalizes the URL.
3. The feature extractor extracts 37 features.
4. The Machine Learning model predicts the phishing probability.
5. Rule-based checks identify suspicious URL patterns.
6. Brand impersonation and redirect checks analyze additional risks.
7. VirusTotal provides external threat intelligence when available.
8. The system combines the results and calculates a risk score.
9. The final result and warnings are displayed to the user.
10. The scan details are stored in the SQLite database.

Risk Classification

The system classifies scanned URLs into three categories:

- Likely Safe: No major phishing indicators were detected.
- Suspicious: One or more suspicious indicators were detected.
- Potentially Phishing: Multiple or significant phishing indicators were detected.

The classification is based on the system's combined analysis. A Likely Safe result does not guarantee that a website is completely safe.

Installation and Execution

1. Clone or download the project from GitHub.
2. Open the project folder in Visual Studio Code.
3. Create and activate the required Python virtual environment.
4. Install the required Python dependencies.
5. Configure the VirusTotal API key in the local ".env" file.
6. Run the V6 Flask application:

python app_v6.py

7. Open the following address in your browser:

http://127.0.0.1:5000

Testing

The system was tested with different types of URLs, including legitimate websites, suspicious domains, IP-based URLs, and URLs with possible phishing indicators.

Example test results:

Test URL| Result
https://google.com| Likely Safe
https://secure-paypal-login.com| Potentially Phishing
https://www.googleimg.top| Suspicious
http://192.168.1.1/login| Suspicious
https://example.com| Suspicious

Results can vary depending on model predictions, detection rules, and available VirusTotal information.

Limitations

- No phishing detection system can guarantee 100% accuracy.
- New phishing websites may not always be detected.
- VirusTotal results depend on external service availability and threat intelligence.
- A legitimate website may sometimes receive a suspicious classification.
- Detection results should be treated as risk indicators, not absolute proof.

Future Enhancements

- Improve detection using larger and updated datasets.
- Add more advanced Machine Learning techniques.
- Improve detection of newly created phishing domains.
- Enhance the user interface and reporting features.
- Add additional threat intelligence sources.

Contributors

Developed as a college project by the project team.