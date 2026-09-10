# Log Analyzer

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+" />
  <img src="https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask" />
  <img src="https://img.shields.io/badge/MITRE-ATT%26CK-1F4D8?style=for-the-badge" alt="MITRE ATT&CK" />
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-5C5C5C?style=for-the-badge" alt="Windows and Linux" />
</p>

<p align="center">
  <strong>Advanced log analysis and threat detection platform for security operations, forensic review, and proactive monitoring.</strong>
</p>

---

## Overview

Log Analyzer is a modern security-focused application for ingesting, correlating, and analyzing logs from multiple sources including Windows events, Linux system logs, network devices, web servers, and firewall telemetry. It helps security teams identify suspicious behaviors, map events to MITRE ATT&CK techniques, and generate professional reports from raw log data.

This project combines:

- Web-based analytics dashboard
- Desktop launcher for local collection
- Playbook-driven detection logic
- Threat correlation and alerting
- Multi-platform log support
- PDF/CSV/HTML reporting

---

## Why this project matters

Security teams often have fragmented log sources spread across different platforms and devices. This tool centralizes the analysis workflow and makes it easier to:

- detect brute force and lateral movement activity
- spot suspicious privilege escalation attempts
- monitor web exploitation patterns
- investigate network reconnaissance and exfiltration activity
- view structured, actionable security findings in one place

---

## Key Features

### 🔐 Threat Detection
- Rule-based detection for common attack patterns
- MITRE ATT&CK mapping for identified tactics and techniques
- Suspicious login, privilege abuse, scanning, and malware indicators
- Log classification for high-risk events

### 📊 Dashboard & Insights
- Centralized web interface for log review
- Summary statistics and anomaly detection
- Playbook-driven alerts and recommendations
- Real-time or batch log analysis workflow

### 🛡️ Multi-Source Log Support
- Windows event logs
- Linux/Unix syslog activity
- Apache, Nginx, IIS, DNS, and proxy logs
- Firewall and network telemetry
- Fortinet and OSFC-style security data

### 📄 Reporting
- HTML summary reports
- CSV export
- PDF report generation for operational handoff
- Security-friendly output for audits and investigations

### ⚙️ Flexible Deployment
- Portable launcher mode
- Web UI execution via Flask
- Desktop GUI launcher support
- Manifest-based playbook scope selection

---

## Project Structure

```text
.
├── Log_Analyzer.py              # Core application and analysis engine
├── Launcher.py                 # GUI launcher for web/desktop modes
├── run_portable.py             # Portable startup entry point
├── LogCollector_GUI.py         # Desktop log collection interface
├── playbooks.json             # Legacy playbook definitions
├── playbooks_windows.json     # Windows-specific rules
├── playbooks_linux.json       # Linux-specific rules
├── playbooks_mac.json         # macOS-specific rules
├── playbooks_apache.json      # Apache log rules
├── playbooks_nginx.json       # NGINX log rules
├── playbooks_iis.json         # IIS log rules
├── playbooks_dns.json         # DNS log rules
├── playbooks_proxy.json       # Proxy log rules
├── playbooks_fortinet.json    # Fortinet rules
├── playbooks_syslog.json      # Syslog rules
├── playbooks_osfc.json        # OSFC rules
├── uploads/                   # Uploaded log files
├── reports/                   # Generated analysis reports
├── logs.db                    # SQLite database store
├── requirements.txt           # Optional dependency manifest
├── config.json                # App configuration
└── README.md                  # Project documentation
```

---

## Getting Started

### Prerequisites

- Python 3.10 or newer
- pip package manager
- Internet access for installing Python dependencies

### Installation

Clone the repository:

```bash
git clone https://github.com/your-username/log-analyzer.git
cd log-analyzer
```

Install the required dependencies:

```bash
pip install flask werkzeug plotly watchdog reportlab
```

### Run the application

#### Option 1: Portable startup

```bash
python run_portable.py
```

This launches the application in portable mode and automatically selects the active playbook scope.

#### Option 2: Launcher interface

```bash
python Launcher.py
```

This opens the launcher menu where you can choose between the web interface and desktop GUI.

#### Option 3: Direct web app

```bash
python Log_Analyzer.py
```

Then open:

```text
http://localhost:5000
```

---

## Typical Use Cases

### Security operations
- Investigate suspicious authentication attempts
- Track privilege escalations and account misuse
- Monitor unusual network behavior and scanning activity

### SOC workflow
- Correlate event data with known MITRE ATT&CK tactics
- Prioritize alerts based on severity and evidence
- Generate documentation for incident review and team response

### Forensics and audits
- Review historic event patterns
- Export CSV/PDF reports for legal or compliance review
- Validate detection coverage using playbook rules

---

## Detection Capabilities

The project includes detection logic for patterns such as:

- brute-force authentication attempts
- successful logins after repeated failures
- admin privilege misuse
- unauthorized sudo activity
- port scanning and reconnaissance
- SQL injection and XSS patterns
- suspicious PowerShell execution
- malware download attempts
- data exfiltration scenarios
- firewall and network attack detection

These detections are associated with risk levels and mapped to relevant ATT&CK techniques when applicable.

---

## Playbooks and Runbooks

The project supports structured rule sets stored as JSON playbooks and associated runbook guidance. These can be used to:

- narrow analysis to a specific platform or log type
- define custom detection rules
- manage operational response guidance
- adapt the system to different environments

---

## Reporting

The application can generate:

- summary dashboards
- threat overview reports
- CSV exports for external analysis
- PDF reports for stakeholder communication

Reports are useful for presenting findings to technical teams, management, or auditors.

---

## Security Note

This project is intended for defensive security monitoring, analysis, and research use. It is not designed for unauthorized surveillance or malicious activity. Always use it in compliance with organizational policy, applicable laws, and security governance requirements.

---

## Contributing

Contributions are welcome. If you would like to improve detections, reporting, playbooks, or the user interface:

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Submit a pull request with a clear description

---

## License

This repository does not currently include an explicit license file. Please confirm the licensing terms before using it in a production or commercial environment.

---

## Contact

For questions, improvements, or collaboration, feel free to open an issue or reach out through the repository discussion channel.

<p align="center">
  <strong>Built for security analysis, threat hunting, and proactive log defense.</strong>
</p>
