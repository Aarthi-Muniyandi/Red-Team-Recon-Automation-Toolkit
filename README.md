# Red Team Recon Automation Toolkit

An automated reconnaissance framework designed to assist cybersecurity professionals and penetration testers during the **information gathering and attack surface mapping phase of security assessments**.

The toolkit integrates multiple reconnaissance techniques such as **subdomain discovery, live host detection, port scanning, directory enumeration, technology fingerprinting, and CVSS-based risk analysis** into a single automated platform with a web dashboard and report generation system.

---

# Project Overview

Reconnaissance is the first and most critical phase in penetration testing and red-team operations. Security analysts often rely on several independent tools to gather information about a target system. This fragmented workflow makes the process time-consuming and difficult to manage.

The **Red Team Recon Automation Toolkit** solves this problem by automating multiple reconnaissance modules and aggregating their results into a unified system. The platform performs attack surface discovery, analyzes detected services, and evaluates security risks using CVSS scoring.

The system follows this workflow:

Target Input → Recon Modules Execution → Data Aggregation → Risk Evaluation → Report Generation

---

# Project Screenshot

*(Place screenshots of your dashboard here)*

Example screenshots you can include:

* Login page
* Dashboard
* Scan results page
* Generated report

Example markdown:

![Dashboard Screenshot](data:image/jpeg;base64,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)

---

# Key Features

• Automated reconnaissance workflow
• Subdomain enumeration
• Live host detection
• Port scanning and service detection
• Directory enumeration
• Web technology fingerprinting
• CVSS-based risk scoring engine
• Web dashboard for managing scans
• Report generation in HTML and PDF format

---

# System Architecture

*(Place architecture diagram here)*

The system follows a modular architecture where reconnaissance modules are executed sequentially and their outputs are aggregated for risk analysis and reporting.

Example markdown:

![System Architecture](images/architecture.png)

Architecture Components:

* Web Interface (Flask)
* Recon Modules
* Data Aggregation Layer
* Risk Analysis Engine
* Reporting Module

---

# Scan Workflow

*(Place scan workflow diagram here)*

Example markdown:

![Scan Workflow](images/workflow.png)

Workflow Steps:

1. User enters target domain or IP address
2. System selects scan mode (Simple Scan / Deep Scan)
3. Recon modules are executed
4. Results are aggregated and processed
5. Risk engine calculates vulnerability severity using CVSS
6. Scan results are displayed in the dashboard
7. Security report is generated

---

# Recon Modules

The reconnaissance modules are located inside the `recon` directory.

| Module              | Description                      |
| ------------------- | -------------------------------- |
| subdomain.py        | Performs subdomain enumeration   |
| live_hosts.py       | Detects active hosts             |
| port_scan.py        | Scans open ports and services    |
| directory_enum.py   | Performs directory enumeration   |
| tech_fingerprint.py | Identifies web technologies      |
| risk_engine.py      | Calculates CVSS-based risk score |

---

# Technology Stack

## Backend

Python
Flask Framework

## Frontend

HTML
CSS
JavaScript

## Database

SQLite

---

# Libraries and Tools Used

Flask – Web application framework
Requests – HTTP request handling
Python-Nmap – Integration with Nmap for port scanning
BeautifulSoup – HTML parsing for enumeration tasks
Regex – Output parsing and data extraction
JSON – Structured data storage
WeasyPrint – PDF report generation

---

# Project Structure

```
red-team-recon
│
├── recon/
│   ├── directory_enum.py
│   ├── live_hosts.py
│   ├── port_scan.py
│   ├── risk_engine.py
│   ├── subdomain.py
│   └── tech_fingerprint.py
│
├── reports/
├── static/css/style.css
├── templates/
│
├── app.py
├── config.py
├── database.py
├── init_db.py
├── requirements.txt
└── README.md
```

---

# Installation Guide

Clone the repository

```
git clone https://github.com/YOUR_USERNAME/red-team-recon-automation-toolkit.git
```

Navigate to the project directory

```
cd red-team-recon-automation-toolkit
```

Create a virtual environment

```
python -m venv venv
```

Activate the virtual environment

Windows:

```
venv\Scripts\activate
```

Linux / Mac:

```
source venv/bin/activate
```

Install dependencies

```
pip install -r requirements.txt
```

Initialize the database

```
python init_db.py
```

---

# Running the Application

Start the application

```
python app.py
```

Open the browser and navigate to

```
http://127.0.0.1:5000
```

From the dashboard, enter a target domain or IP address to start a reconnaissance scan.

---

# Report Generation

After the scan completes, the toolkit generates structured reports summarizing discovered assets, detected services, and calculated risk scores.

Reports can be exported in **HTML or PDF format** using the WeasyPrint library.

---

# Disclaimer

This project is developed **strictly for educational purposes and authorized penetration testing**.

Do not use this tool against systems or networks without explicit permission. Unauthorized scanning or testing may violate legal regulations.

The author is not responsible for misuse of this software.

---

# License

This project is licensed under the **MIT License**.
You are free to use, modify, and distribute this software with proper attribution.

---

# Author

Aarthi M
Cybersecurity Student | Red Team Enthusiast
