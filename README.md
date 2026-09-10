<div align="center">

# 🛡️ Log Analyzer

### Security log intelligence, playbook detection, and forensic reporting

**A Python-based log analysis and alerting platform for SOC, security operations, and incident investigation workflows.**
It combines multi-source log ingestion, structured threat playbooks, MITRE ATT&CK correlation, desktop/web interfaces, and automated reporting in a single operational toolkit.

<br/>

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-1F4D8?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-5C5C5C?style=for-the-badge)

</div>

---

> [!IMPORTANT]
> This project is built for defensive cyber operations and authorized log review. It is intended for security monitoring, detection engineering, investigation support, and operational reporting — not for unauthorized surveillance or malicious activity.

---

## ✨ What this project does

| Area | Capability |
|---|---|
| 🔐 Threat detection | Rule-based correlation for brute force, privilege misuse, web exploitation, recon activity, malware delivery, and data exfiltration patterns |
| 🧠 MITRE mapping | ATT&CK-aligned playbook logic for common attack behaviors and suspicious security events |
| 📊 Multi-source ingestion | Windows Event Logs, Linux/macOS syslog, Apache/Nginx/IIS logs, DNS, proxies, Fortinet data, and OSFC-style telemetry |
| 🧩 Playbook engine | JSON-driven detection rules and operational runbooks for multiple platform and attack categories |
| 🖥️ Interface options | Web dashboard plus desktop GUI launcher for local collection and analysis |
| 📄 Reporting | PDF, CSV, HTML, and structured security summaries for investigations and stakeholder handoff |

---

## 🚀 Quick start

```bash
# 1. create a virtual environment
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

# 2. install dependencies
pip install --upgrade pip
pip install flask werkzeug plotly watchdog reportlab

# 3. run the app
python run_portable.py
# or
python Launcher.py
# or
python Log_Analyzer.py
```

Open the application in a browser at:

```text
http://localhost:5000
```

> The portable launcher automatically detects the playbook scope and starts the application in the most suitable mode.

---

## ✅ Requirements

| Component | Notes |
|---|---|
| Python 3.10+ | Required runtime |
| pip | For dependency installation |
| Flask | Web interface and request handling |
| Plotly | Visualization and dashboard metrics |
| Watchdog | File system monitoring support |
| ReportLab | PDF report generation |
| SQLite | Local storage for collected data and stats |
| OS support | Works across Windows, Linux, and macOS environments |

---

## ⚙️ Configuration

The application uses configuration values from [`config.json`](config.json) and supports environment-driven playbook selection through variables such as:

- `ACTIVE_PLAYBOOK_TYPES`
- `ACTIVE_PLAYBOOK_TYPE`

Example runtime settings in [`config.json`](config.json):

```json
{
  "enabled_playbooks": [],
  "watch_directories": ["uploads"],
  "analysis_settings": {
    "enable_real_time": true,
    "batch_size": 100,
    "analysis_interval": 5
  },
  "report_settings": {
    "auto_generate": true,
    "format": "pdf",
    "output_directory": "reports"
  }
}
```

This gives the project a lightweight configuration layer for playbook scope, monitoring, and report output.

---

## 📂 Repository layout

```text
.
├── Log_Analyzer.py              # Core Flask web app and analysis engine
├── Launcher.py                  # GUI launcher for web/desktop modes
├── LogCollector_GUI.py          # Desktop log collection interface
├── run_portable.py              # Portable startup entry point
├── start_portable.sh            # Shell launcher for portable mode
├── deployment_helper.py         # Deployment and environment helper
├── diagnose_view_rules.py       # Diagnostic helper for playbook visibility
├── playbooks.json               # Main playbook definitions
├── playbooks_windows.json       # Windows log detection rules
├── playbooks_linux.json         # Linux log detection rules
├── playbooks_mac.json           # macOS detection rules
├── playbooks_apache.json        # Apache log attack signatures
├── playbooks_nginx.json         # NGINX log signatures
├── playbooks_iis.json           # IIS log analysis rules
├── playbooks_dns.json           # DNS analysis signatures
├── playbooks_proxy.json         # Proxy/firewall indicators
├── playbooks_fortinet.json      # Fortinet detection rules
├── playbooks_syslog.json        # Syslog rules
├── playbooks_osfc.json          # OSFC-related rules
├── playbook_selector_modal.html # UI modal for playbook selection
├── runbooks.json                # Response runbooks for detected playbooks
├── config.json                  # Runtime configuration file
├── uploads/                     # Uploaded logs and forensic files
├── reports/                     # Generated HTML/PDF/CSV outputs
├── logs.db                      # SQLite inspection database
├── sample_ocfs.log              # Example sample log input
├── README.md                    # Project documentation
└── .git/                        # Version control metadata
```

---

## 🔄 How it works

The application follows a practical security-analysis workflow:

1. A log source is ingested from files, system locations, or collected streams.
2. The engine normalizes and classifies the raw records.
3. Detection logic matches known attack patterns from the configured playbook set.
4. Matching events are correlated with related time windows, users, IPs, and device signals.
5. Findings are mapped to MITRE ATT&CK techniques when applicable.
6. The results are shown in the dashboard and exported into operational reports.

The project is designed to support both live monitoring and post-incident review.

---

## 🧪 Detection coverage

The built-in playbook set includes logic for patterns such as:

- brute-force authentication attempts
- successful logins after repeated failures
- privilege escalation and admin misuse
- unauthorized sudo or root activity
- firewall port scanning and recon activity
- web exploitation patterns including SQL injection and XSS
- suspicious PowerShell execution and malware downloads
- outbound transfer and possible exfiltration events
- Suricata and Zeek anomaly signals
- LDAP and network reconnaissance indicators

Many of these are tied to ATT&CK tactic IDs such as `T1110`, `T1068`, `T1190`, `T1041`, and related techniques.

---

## 🖥️ Using the interface

### Web app

The Flask-based dashboard provides a browser interface for:

- reviewing activity summaries
- inspecting playbook matches
- exploring risk trends and log categories
- downloading or generating reports
- switching playbook sets based on environment scope

### Desktop GUI

The desktop launcher enables local collection workflows and log-review tasks from a native GUI, including:

- Windows Event Log collection
- syslog-style log review
- network activity collection
- database-backed incident history

---

## 📄 Reporting and evidence output

The system can generate operational outputs such as:

- summary dashboards
- CSV exports
- HTML investigation reports
- PDF reports for presentation or stakeholder review

Reports are useful for escalations, forensic case reviews, and documenting SOC findings in a structured format.

---

## 🛡️ Security and responsible use

This project is intended for:

- internal security monitoring
- defensive analysis
- investigation support
- security automation research

It should never be used for unauthorized monitoring, privacy violations, or malicious access. Always follow internal governance, security policy, and legal requirements before collecting or analyzing logs in production environments.

---

## 🗺️ Roadmap

Planned improvements include:

- broader correlation rules and machine-learning-assisted ranking
- stronger live monitoring and alert tuning
- more export formats and dashboard enhancements
- better multi-environment deployment support
- more advanced playbook configuration and user management

---

## 🤝 Contributing

Contributions are welcome. If you want to improve detection logic, expand the integration set, create new playbooks, or refine reporting:

1. Fork the repository
2. Create a feature branch
3. Implement your change
4. submit a pull request with a clear description of the improvement

---

## ⚖️ Licensing

This repository does not currently include a dedicated license file. Please review the repository policy and confirm the legal usage terms before production or commercial deployment.

---

<div align="center">
<sub>Built for defensive security operations, forensic review, and structured threat investigation.</sub>
</div>


<p align="center">
  <strong>Built for security analysis, threat hunting, and proactive log defense.</strong>
</p>
