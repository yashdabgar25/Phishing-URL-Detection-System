# Phishing URL Detection System

A web-based system that analyzes website URLs and identifies potentially suspicious or phishing URLs using rule-based URL analysis.

## Project Overview

Phishing attacks are commonly used to trick users into visiting fake websites and sharing sensitive information such as usernames, passwords, banking details, and personal data.

This project analyzes a given URL and checks for common phishing indicators such as:

- Unusually long URLs
- Missing HTTPS
- IP address instead of a domain name
- Suspicious keywords
- Multiple hyphens
- Unusual number of subdomains
- Suspicious URL symbols

The system calculates a risk score and classifies the URL as:

- Likely Safe
- Suspicious
- Potentially Phishing

## Technologies Used

### Frontend
- HTML
- CSS
- JavaScript

### Backend
- Python
- Flask

### Database
- SQLite

### Development Tools
- Visual Studio Code
- Git
- GitHub

## Main Features

1. URL input and scanning
2. Rule-based phishing detection
3. Risk score calculation
4. Risk level classification
5. Warning messages for detected indicators
6. Scan history
7. SQLite database storage
8. Responsive web interface

## Project Structure

```text
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
├── app.py
├── README.md
├── .gitignore
└── phishing_history.db