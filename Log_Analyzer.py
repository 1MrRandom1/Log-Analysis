import os
import sys
import re
import json
import csv
import sqlite3
import hashlib
import threading
import queue
import time
import zipfile
import io
import base64
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field, asdict
from dataclasses import dataclass, field as dc_field, asdict
from collections import defaultdict
from contextlib import contextmanager
from functools import wraps
import html

# Third-party imports check
try:
    from flask import Flask, render_template_string, request, redirect, url_for, flash, send_file, jsonify, session, Response, make_response
    from flask.typing import ResponseReturnValue
    from werkzeug.security import generate_password_hash, check_password_hash
    from werkzeug.utils import secure_filename
    import plotly.graph_objects as go
    import plotly.io as pio
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
        from reportlab.lib import colors
        HAS_REPORTLAB = True
    except ImportError:
        HAS_REPORTLAB = False
    HAS_DEPS = True
except ImportError as e:
    print(f"Missing dependencies: {e}")
    print("\nInstall required packages:")
    print("pip install flask werkzeug plotly watchdog reportlab")
    HAS_DEPS = False
    sys.exit(1)

    # ============================================================================
    # PLAYBOOKS AND RUNBOOKS (Embedded)
    # ============================================================================

    PLAYBOOKS = [
        {
            "id": "PB-001",
            "name": "Brute Force Authentication Attempts",
            "description": "Detects repeated failed login attempts from same IP or against same user within a short window.",
            "event_types": ["auth_failure", "windows_4625", "linux_auth"],
            "conditions": {"failed_threshold": 5, "window_minutes": 5},
            "mitre": ["T1110"],
            "severity": "High",
            "category": "Authentication Attack",
        },
        {
            "id": "PB-002",
            "name": "Successful Login After Brute Force",
            "description": "Detects successful login immediately after multiple failures.",
            "event_types": ["auth_success", "windows_4624"],
            "conditions": {"min_failed_attempts_before": 5, "time_delta_minutes": 2},
            "mitre": ["T1110"],
            "severity": "Critical",
            "category": "Account Compromise",
        },
        {
            "id": "PB-003",
            "name": "Suspicious Admin Privilege Assignment",
            "description": "Detects sudden assignment of admin/root privileges.",
            "event_types": ["windows_4728", "linux_sudoers_edit"],
            "conditions": {},
            "mitre": ["T1068"],
            "severity": "High",
            "category": "Privilege Escalation",
        },
        {
            "id": "PB-004",
            "name": "Unauthorized SUDO Attempt",
            "description": "Repeated unauthorized sudo attempts on Linux hosts.",
            "event_types": ["linux_sudo_failure"],
            "conditions": {"threshold": 3, "window_minutes": 5},
            "mitre": ["T1069"],
            "severity": "Medium",
            "category": "Authorization Abuse",
        },
        {
            "id": "PB-005",
            "name": "VPN Login From New Geo-Location",
            "description": "Detects VPN login from suspicious or impossible geo locations.",
            "event_types": ["vpn_login"],
            "conditions": {"impossible_travel": True},
            "mitre": ["T1078"],
            "severity": "High",
            "category": "Credential Misuse",
        },
        {
            "id": "PB-006",
            "name": "Firewall Port Scan Detection",
            "description": "Detects multiple port hits from same source IP.",
            "event_types": ["firewall_conn_attempt"],
            "conditions": {"distinct_ports": 10, "window_minutes": 2},
            "mitre": ["T1595"],
            "severity": "Medium",
            "category": "Reconnaissance",
        },
        {
            "id": "PB-007",
            "name": "Web Directory Brute Forcing",
            "description": "Detects rapid multiple 404/403 responses from same IP.",
            "event_types": ["apache_access", "nginx_access"],
            "conditions": {"error_rate": 10, "window_minutes": 2},
            "mitre": ["T1190"],
            "severity": "Medium",
            "category": "Web Recon",
        },
        {
            "id": "PB-008",
            "name": "Malware Download Activity",
            "description": "Detects users downloading .exe/.dll/.bat/.ps1 files.",
            "event_types": ["http_request"],
            "conditions": {"url_regex": ".*(\\.(exe|dll|ps1|bat))$"},
            "mitre": ["T1105"],
            "severity": "High",
            "category": "Malware Delivery",
        },
        {
            "id": "PB-009",
            "name": "PowerShell Suspicious Execution",
            "description": "Detects obfuscated or encoded PowerShell commands.",
            "event_types": ["windows_4104"],
            "conditions": {"contains_base64": True, "contains_obfuscation": True},
            "mitre": ["T1059.001"],
            "severity": "High",
            "category": "Execution",
        },
        {
            "id": "PB-010",
            "name": "Possible Data Exfiltration",
            "description": "Detects large outbound data transfers.",
            "event_types": ["firewall_traffic"],
            "conditions": {"min_mb": 500, "direction": "outbound"},
            "mitre": ["T1041"],
            "severity": "Critical",
            "category": "Data Exfiltration",
        },
        {
            "id": "PB-011",
            "name": "Suricata High-Severity Alert",
            "description": "Triggers on Suricata alerts with severity >= 3.",
            "event_types": ["suricata_alert"],
            "conditions": {"severity": 3},
            "mitre": ["T1203"],
            "severity": "Critical",
            "category": "Exploit Attempt",
        },
        {
            "id": "PB-012",
            "name": "Zeek Suspicious SSL Certificate",
            "description": "Detects self-signed, expired, or mismatched SSL certificates.",
            "event_types": ["zeek_ssl"],
            "conditions": {"certificate_issue": True},
            "mitre": ["T1553"],
            "severity": "Medium",
            "category": "Network Threat",
        },
        {
            "id": "PB-013",
            "name": "Fortigate Intrusion Event",
            "description": "Detects intrusion events from Fortigate logs.",
            "event_types": ["fortigate_attack"],
            "conditions": {"severity": ["high", "critical"]},
            "mitre": ["T1190"],
            "severity": "Critical",
            "category": "Firewall Threat",
        },
        {
            "id": "PB-014",
            "name": "SQL Injection Attempt",
            "description": "Detects SQL injection patterns in web logs.",
            "event_types": ["apache_access", "nginx_access", "waf"],
            "conditions": {"payload_regex": "(union.*select|sleep\\(| or 1=1)"},
            "mitre": ["T1190"],
            "severity": "High",
            "category": "Web Exploitation",
        },
        {
            "id": "PB-015",
            "name": "XSS Injection Attempt",
            "description": "Detects XSS payloads in web requests.",
            "event_types": ["web_request"],
            "conditions": {"payload_regex": "<script>|onerror=|alert\\("},
            "mitre": ["T1059"],
            "severity": "Medium",
            "category": "Web Exploitation",
        },
        {
            "id": "PB-016",
            "name": "Suspicious LDAP Query",
            "description": "Detects LDAP enumeration queries.",
            "event_types": ["ldap_query"],
            "conditions": {"query_type": "enumeration"},
            "mitre": ["T1087"],
            "severity": "Medium",
            "category": "Privilege Discovery",
        },
    ]

    RUNBOOKS = {
        "PB-001": {
            "title": "Brute Force Authentication Investigation",
            "steps": [
                "Count failed login attempts by source IP and username.",
                "Check time window between failures.",
                "Check for successful login following failures.",
                "Extract OS, user agent, and authentication method.",
                "Recommend locking account, blocking IP, and enabling MFA.",
            ],
        },
        "PB-002": {
            "title": "Compromised Account Validation",
            "steps": [
                "Identify failed attempts preceding a successful login.",
                "Determine if login came from unusual location.",
                "Check whether privileged operations followed immediately.",
                "Flag the account for forced password rotation.",
                "Verify if lateral movement occurred.",
            ],
        },
        "PB-003": {
            "title": "Privilege Escalation Review",
            "steps": [
                "Extract event assigning admin/root privileges.",
                "Verify who initiated the change.",
                "Check if the user was previously privileged.",
                "Review recent login history of the actor account.",
                "Recommend revoking access and investigating motivation.",
            ],
        },
        "PB-004": {
            "title": "Unauthorized SUDO Attempt",
            "steps": [
                "List all failed sudo events for this account.",
                "Identify commands attempted.",
                "Check for brute force sudo password attempts.",
                "Review user's group membership.",
                "Suggest restricting sudo usage or enabling MFA.",
            ],
        },
        "PB-005": {
            "title": "VPN Geo-Location Anomaly Investigation",
            "steps": [
                "Compare last login geo-location with current login.",
                "Calculate impossible-travel time and distance.",
                "Check for known VPN/proxy IP ranges.",
                "Recommend step-up authentication.",
                "Flag account as suspicious.",
            ],
        },
        "PB-006": {
            "title": "Port Scan Detection Workflow",
            "steps": [
                "Group connection attempts by source IP.",
                "Count distinct ports targeted.",
                "Check for known scanning tools (masscan/nmap).",
                "Recommend firewall rate-limiting.",
                "Block attacker IP.",
            ],
        },
        "PB-007": {
            "title": "Web Recon Activity Investigation",
            "steps": [
                "Analyze 404/403 patterns.",
                "Extract targeted directories.",
                "Check for automated scanner signatures.",
                "Advise enabling WAF rules and blocking source IP.",
            ],
        },
        "PB-008": {
            "title": "Malware Download Investigation",
            "steps": [
                "Extract URL, file name, and requesting user.",
                "Check for unusual user agents.",
                "Check if file executed after download.",
                "Run hash against threat intel.",
                "Recommend blocking domain and scanning host.",
            ],
        },
        "PB-009": {
            "title": "Suspicious PowerShell Activity Investigation",
            "steps": [
                "Decode Base64 command if present.",
                "Identify obfuscation techniques.",
                "Check for outbound connections.",
                "Verify if script created any persistence.",
                "Recommend endpoint isolation.",
            ],
        },
        "PB-010": {
            "title": "Data Exfiltration Runbook",
            "steps": [
                "Identify source system initiating large outbound transfers.",
                "Check destination IP reputation.",
                "Determine protocol used (DNS/HTTPS/FTP/etc).",
                "Correlate with host process logs.",
                "Recommend blocking transfer method and isolating host.",
            ],
        },
        "PB-011": {
            "title": "Suricata Alert Validation",
            "steps": [
                "Extract rule signature and attack category.",
                "Check if multiple alerts came from same actor.",
                "Correlate alerts with firewall logs.",
                "Determine impact and exploitation likelihood.",
            ],
        },
    }
# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def formatFileSize(bytes_size: int) -> str:
    """Convert bytes to human-readable file size format."""
    if bytes_size == 0:
        return '0 Bytes'
    size_names = ('Bytes', 'KB', 'MB', 'GB', 'TB')
    size_index = 0
    size_float = float(bytes_size)
    while size_float >= 1024 and size_index < len(size_names) - 1:
        size_float /= 1024
        size_index += 1
    return f"{size_float:.2f} {size_names[size_index]}"

# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class LogEntry:
    """Normalized log entry structure."""
    timestamp: datetime
    source: str
    severity: str
    event_type: str
    message: str
    raw_log: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    user: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    tags: List[str] = dc_field(default_factory=list)
    ttp_match: Optional[str] = None
    anomaly_score: float = 0.0


@dataclass
class CustomRule:
    """User-defined detection rule."""
    id: Optional[int]
    name: str
    description: str
    rule_type: str  # signature | heuristic | anomaly | behavior
    field: str      # message | raw_log | source_ip | dest_ip | user | tags
    pattern: str
    severity: str
    tags: List[str] = dc_field(default_factory=list)
    enabled: bool = True

@dataclass
class ThreatSignature:
    """Threat detection signature based on MITRE ATT&CK TTPs."""
    id: str
    name: str
    description: str
    tactic: str
    technique: str
    pattern: str
    severity: str
    indicators: List[str]

# ============================================================================
# DATABASE MANAGER
# ============================================================================

class Database:
    """SQLite database manager with thread-safe connections."""
    
    def __init__(self, db_path='logs.db'):
        self.db_path = db_path
        self._init_db()

    def clear_log_data(self):
        """Clear existing logs and related alerts for a fresh upload."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Remove log entries and alerts to avoid mixing old data with new uploads
            cursor.execute('DELETE FROM alerts')
            cursor.execute('DELETE FROM log_entries')
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def _init_db(self):
        """Initialize database tables."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT,
                    role TEXT DEFAULT 'analyst',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            
            # Log entries table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS log_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP NOT NULL,
                    source_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    event_type TEXT,
                    message TEXT,
                    raw_log TEXT,
                    source_ip TEXT,
                    dest_ip TEXT,
                    user TEXT,
                    port INTEGER,
                    protocol TEXT,
                    tags TEXT,
                    ttp_match TEXT,
                    anomaly_score REAL DEFAULT 0.0,
                    imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_entries_timestamp ON log_entries(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_entries_severity ON log_entries(severity)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_entries_source_ip ON log_entries(source_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_entries_ttp ON log_entries(ttp_match)')
            
            # Alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT NOT NULL,
                    log_entry_ids TEXT,
                    source_ips TEXT,
                    affected_hosts TEXT,
                    threat_type TEXT,
                    ttp_match TEXT,
                    status TEXT DEFAULT 'new',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP,
                    resolved_at TIMESTAMP
                )
            ''')
            
            # Settings table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Custom rules table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS custom_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    rule_type TEXT NOT NULL,
                    field TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    tags TEXT,
                    enabled BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Reports table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id TEXT UNIQUE NOT NULL,
                    report_type TEXT NOT NULL,
                    generated_by TEXT,
                    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'pending',
                    file_path TEXT,
                    parameters TEXT
                )
            ''')
            
            # Insert default admin user if not exists
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
            if cursor.fetchone()[0] == 0:
                password_hash = generate_password_hash('admin123')
                cursor.execute('''
                    INSERT INTO users (username, email, password_hash, full_name, role)
                    VALUES (?, ?, ?, ?, ?)
                ''', ('admin', 'admin@logs.local', password_hash, 'Administrator', 'admin'))
            
            # Insert default settings
            default_settings = [
                ('app_name', 'Portable Log Analyzer'),
                ('app_version', '1.0.0'),
                ('retention_days', '30'),
                ('max_upload_size', '100'),  # MB
                ('auto_monitor', '1'),
                ('active_playbook_type', 'all'),
                ('ddos_threshold_per_min', '200'),
            ]
            
            for key, value in default_settings:
                cursor.execute('''
                    INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)
                ''', (key, value))

    def get_custom_rules(self, include_disabled: bool = False) -> List[sqlite3.Row]:
        """Fetch custom detection rules."""
        query = "SELECT * FROM custom_rules"
        if not include_disabled:
            query += " WHERE enabled = 1"
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            return cursor.fetchall()

    def add_custom_rule(self, rule: CustomRule) -> None:
        """Insert a new custom rule."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO custom_rules (name, description, rule_type, field, pattern, severity, tags, enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                rule.name,
                rule.description,
                rule.rule_type,
                rule.field,
                rule.pattern,
                rule.severity,
                ','.join(rule.tags),
                1 if rule.enabled else 0
            ))

# ============================================================================
# THREAT INTELLIGENCE DATABASE
# ============================================================================

class ThreatDatabase:
    """Built-in threat intelligence and TTP signatures."""
    
    SIGNATURES: List[ThreatSignature] = [
        # ===== CREDENTIAL ACCESS =====
        ThreatSignature(
            id="T1110.001", name="Brute Force - Password Guessing",
            description="Multiple failed login attempts detected",
            tactic="Credential Access", technique="Brute Force",
            pattern=r"(failed|invalid|incorrect).*(login|password|auth)",
            severity="HIGH",
            indicators=["failed login", "invalid password", "authentication failure"]
        ),
        ThreatSignature(
            id="T1110.004", name="Password Spraying / Credential Stuffing",
            description="Many usernames attempted from same IP",
            tactic="Credential Access", technique="Brute Force",
            pattern=r"(authentication failure|failed password|invalid user|pam_authenticate).*user",
            severity="HIGH",
            indicators=["many users", "same IP", "auth failure"]
        ),
        ThreatSignature(
            id="T1110.002", name="Account Lockout Abuse",
            description="Account lockout or manipulation events",
            tactic="Credential Access", technique="Account Lockout",
            pattern=r"(account lock(ed|out)|too many failure|lockout threshold)",
            severity="MEDIUM",
            indicators=["lockout", "account disabled"]
        ),
        ThreatSignature(
            id="T1550.002", name="Pass-the-Hash Indicators",
            description="NTLM authentication failures indicative of PtH",
            tactic="Credential Access", technique="Pass the Hash",
            pattern=r"(NTLM|Kerberos).*fail|STATUS_LOGON_FAILURE|0xc000006d",
            severity="HIGH",
            indicators=["NTLM fail", "0xc000006d", "pass the hash"]
        ),
        
        # ===== EXECUTION / MALWARE =====
        ThreatSignature(
            id="T1059.001", name="Suspicious PowerShell Execution",
            description="PowerShell execution with suspicious parameters",
            tactic="Execution", technique="Command and Scripting Interpreter",
            pattern=r"powershell.*(-enc|-encodedcommand|-exec\s*bypass|-nop|iex|invoke-webrequest)",
            severity="CRITICAL",
            indicators=["powershell", "-encodedcommand", "bypass", "iex"]
        ),
        ThreatSignature(
            id="T1203", name="Exploit Signatures",
            description="Exploit attempts seen in logs",
            tactic="Initial Access", technique="Exploitation",
            pattern=r"(SURICATA|ET\s+PROTOCOL|ET\s+EXPLOIT|ALERT).*exploit",
            severity="CRITICAL",
            indicators=["SURICATA ALERT", "ET EXPLOIT"]
        ),
        ThreatSignature(
            id="T1055", name="Process Injection",
            description="Potential process injection detected",
            tactic="Defense Evasion", technique="Process Injection",
            pattern=r"(inject|hollowing|dll.*load|createremotethread)",
            severity="CRITICAL",
            indicators=["injection", "hollowing", "remote thread"]
        ),
        ThreatSignature(
            id="T1105", name="Executable Download",
            description="Download of PE/Executable files",
            tactic="Command and Control", technique="Ingress Tool Transfer",
            pattern=r"(GET|POST)\s+[^\s]*\.(exe|dll|msi|bat|ps1)(\s|$)|application/x-msdownload",
            severity="HIGH",
            indicators=[".exe", ".dll", "x-msdownload"]
        ),
        
        # ===== PERSISTENCE / PRIVILEGE ESCALATION =====
        ThreatSignature(
            id="T1053.005", name="Scheduled Task Creation",
            description="New scheduled task created - persistence indicator",
            tactic="Persistence", technique="Scheduled Task",
            pattern=r"(schtasks|at\.exe|cron).*(/create|add)",
            severity="MEDIUM",
            indicators=["schtasks", "task scheduler", "cron"]
        ),
        ThreatSignature(
            id="T1547", name="Registry Run Persistence",
            description="Registry Run/RunOnce modification",
            tactic="Persistence", technique="Boot or Logon Autostart Execution",
            pattern=r"(HK(LM|CU)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|RunOnce)",
            severity="HIGH",
            indicators=["Run key", "autorun"]
        ),
        ThreatSignature(
            id="T1136.001", name="Local Account Creation",
            description="New local user account created",
            tactic="Persistence", technique="Create Account",
            pattern=r"(net\s+user|useradd|adduser).*(/add|create)",
            severity="HIGH",
            indicators=["net user", "account created"]
        ),
        ThreatSignature(
            id="T1098", name="Account Manipulation",
            description="Account privileges modified or granted",
            tactic="Persistence", technique="Account Manipulation",
            pattern=r"(net\s+localgroup\s+administrators\s+.+/add|usermod\s+-aG\s+sudo)",
            severity="HIGH",
            indicators=["Administrators group", "sudoers"]
        ),
        
        # ===== LATERAL MOVEMENT =====
        ThreatSignature(
            id="T1021.001", name="RDP Exploitation",
            description="RDP connection attempt detected",
            tactic="Lateral Movement", technique="Remote Services",
            pattern=r"(rdp|remote desktop|3389|mstsc|ms-wbt-server)",
            severity="MEDIUM",
            indicators=["RDP", "port 3389", "mstsc"]
        ),
        ThreatSignature(
            id="T1021.002", name="SMB/ADMIN$ Lateral Movement",
            description="Access to admin shares or SMB exec",
            tactic="Lateral Movement", technique="SMB/Windows Admin Shares",
            pattern=r"(ADMIN\$|C\$|smbclient\s+-L|psexec|wmic\s+.*process\s+call\s+create|winrm)",
            severity="HIGH",
            indicators=["ADMIN$", "psexec", "wmic", "winrm"]
        ),
        ThreatSignature(
            id="T1570", name="Lateral Tool Transfer",
            description="Tools being transferred for lateral movement",
            tactic="Lateral Movement", technique="Lateral Tool Transfer",
            pattern=r"(mimikatz|psexec|nmap|hashcat|wce\.exe|fgdump)",
            severity="HIGH",
            indicators=["mimikatz", "psexec", "nmap"]
        ),
        
        # ===== DISCOVERY / RECONNAISSANCE =====
        ThreatSignature(
            id="T1046", name="Port Scanning",
            description="Multiple ports probed from single source",
            tactic="Discovery", technique="Network Service Scanning",
            pattern=r"(nmap|masscan|zmap|SYN\s+scan)",
            severity="MEDIUM",
            indicators=["nmap", "SYN scan", "port scan"]
        ),
        ThreatSignature(
            id="T1018", name="Host/Ping Sweep",
            description="ICMP echo requests to multiple hosts",
            tactic="Discovery", technique="Remote System Discovery",
            pattern=r"(ICMP\s+(echo|ping)|ping\s+-c|fping)",
            severity="MEDIUM",
            indicators=["ICMP echo", "ping sweep"]
        ),
        ThreatSignature(
            id="T1592", name="Service Enumeration",
            description="Service/version detection probes",
            tactic="Discovery", technique="Service Discovery",
            pattern=r"(enum4linux|rpcinfo|snmpwalk|ldapsearch)",
            severity="MEDIUM",
            indicators=["enum4linux", "snmpwalk", "ldapsearch"]
        ),
        ThreatSignature(
            id="T1087", name="Web Directory Scanning",
            description="Bursts of 404s indicative of dir scanning",
            tactic="Discovery", technique="Web Enumeration",
            pattern=r"robots\.txt|admin\.php|wp-login\.php|\.git/HEAD",
            severity="MEDIUM",
            indicators=["404 burst", "robots.txt", "admin.php"]
        ),
        
        # ===== WEB ATTACKS =====
        ThreatSignature(
            id="T1190-SQLi", name="SQL Injection Attempt",
            description="SQL injection payloads detected",
            tactic="Initial Access", technique="Exploit Public-Facing Application",
            pattern=r"(\bUNION\s+SELECT\b|information_schema|or\s+1=1|sleep\(|benchmark\(|--|;\s*shutdown)",
            severity="HIGH",
            indicators=["UNION SELECT", "1=1", "information_schema"]
        ),
        ThreatSignature(
            id="T1190-XSS", name="Cross-site Scripting",
            description="XSS attack patterns detected",
            tactic="Initial Access", technique="Exploit Public-Facing Application",
            pattern=r"(<script|onerror=|onload=|javascript:|data:text|%3Cscript%3E|alert\()",
            severity="HIGH",
            indicators=["<script>", "onerror", "alert("]
        ),
        ThreatSignature(
            id="T1190-CMDI", name="Command Injection",
            description="Command injection metacharacters detected",
            tactic="Initial Access", technique="Exploit Public-Facing Application",
            pattern=r"(;|\|\||\|\s*whoami|`[^`]+`|\$\([^)]+\))",
            severity="HIGH",
            indicators=[";", "||", "command injection"]
        ),
        ThreatSignature(
            id="T1006", name="Path Traversal",
            description="Directory traversal sequences detected",
            tactic="Discovery", technique="Direct Volume Access",
            pattern=r"\.\./|%2e%2e/|\b/etc/passwd\b|C:\\Windows\\System32\\config\\SAM",
            severity="HIGH",
            indicators=["../", "/etc/passwd", "path traversal"]
        ),
        ThreatSignature(
            id="T1190-Upload", name="File Upload Abuse",
            description="Suspicious file upload attempts",
            tactic="Exfiltration", technique="Web Service",
            pattern=r"(multipart/form-data|POST\s+.*(upload|file|image).*(\.php|\.asp|\.jsp))",
            severity="HIGH",
            indicators=["multipart", "upload", ".php"]
        ),
        
        # ===== DENIAL OF SERVICE =====
        ThreatSignature(
            id="T1498", name="Network Denial of Service",
            description="Indicators of DoS/DDoS present in logs",
            tactic="Impact", technique="Network Denial of Service",
            pattern=r"(syn\s*flood|udp\s*flood|icmp\s*flood|slowloris|http\s*flood|rud(y|y)|ddos|denial\s+of\s+service|dos\s+attack|rate\s*limit\s*exceeded|too\s*many\s*connections|503\s*service\s*unavailable)",
            severity="CRITICAL",
            indicators=["SYN flood", "UDP flood", "DDoS", "Rate limit exceeded"]
        ),
        ThreatSignature(
            id="T1498.002", name="Reflection/Amplification DoS",
            description="Reflection/amplification patterns observed",
            tactic="Impact", technique="Reflection/Amplification",
            pattern=r"(ntp\s+monlist|ssdp|dns\s+amplification|chargen|memcached\s+amplification)",
            severity="CRITICAL",
            indicators=["NTP monlist", "SSDP", "DNS amplification", "Chargen"]
        ),
        
        # ===== COMMAND & CONTROL =====
        ThreatSignature(
            id="T1071.001", name="C2 Beaconing Over HTTP",
            description="C2 communication over HTTP/HTTPS",
            tactic="Command and Control", technique="Application Layer Protocol",
            pattern=r"(beacon|call\s*back|\bc2\b|command[ .-]?control|c2\.)",
            severity="CRITICAL",
            indicators=["beacon", "callback", "C2 server"]
        ),
        ThreatSignature(
            id="T1048.001", name="DNS Tunneling",
            description="DNS exfiltration or tunneling detected",
            tactic="Exfiltration", technique="DNS Tunneling",
            pattern=r"([a-z0-9\-]{8,}\.){4,}[a-z]{2,}|dns.*tunnel|dns.*exfil",
            severity="HIGH",
            indicators=["DNS tunnel", "long DNS query"]
        ),
        
        # ===== EXFILTRATION =====
        ThreatSignature(
            id="T1048.003", name="Data Exfiltration",
            description="Large data transfer or archive detected",
            tactic="Exfiltration", technique="Exfiltration Over Alternative Protocol",
            pattern=r"(upload|exfil|transfer).*(\d{6,}|large|bulk|mb|gb)|\.(zip|rar|7z|tar\.gz)",
            severity="CRITICAL",
            indicators=["large transfer", "bulk upload", ".zip"]
        ),
        ThreatSignature(
            id="T1030", name="Mass File Deletion",
            description="Bulk file deletion suspicious pattern",
            tactic="Impact", technique="Data Destruction",
            pattern=r"(delete.*\*|rm\s+-rf|format|cipher\s+/w)",
            severity="HIGH",
            indicators=["mass delete", "cipher /w"]
        ),
        
        # ===== DEFENSE EVASION / IMPACT =====
        ThreatSignature(
            id="T1498", name="DDoS - Flood Attack",
            description="SYN/UDP/ICMP flood patterns detected",
            tactic="Impact", technique="Network Denial of Service",
            pattern=r"(\bSYN\b|\bUDP\b|\bICMP\b).*flood|DDoS|DoS",
            severity="HIGH",
            indicators=["SYN flood", "UDP flood", "DDoS"]
        ),
        ThreatSignature(
            id="T1561", name="HTTP Flood/Application DDoS",
            description="HTTP POST/GET flood from single source",
            tactic="Impact", technique="Denial of Service",
            pattern=r"(POST|GET).*flood|http.*dos",
            severity="HIGH",
            indicators=["HTTP flood", "POST flood"]
        ),
        ThreatSignature(
            id="T1562", name="Security Tool Disabling",
            description="Antivirus or security tools disabled",
            tactic="Defense Evasion", technique="Impair Defenses",
            pattern=r"(Defender.*(disabled|turned off)|antivirus.*disabled|firewall.*disabled)",
            severity="CRITICAL",
            indicators=["Defender disabled", "AV disabled"]
        ),
        ThreatSignature(
            id="T1070.006", name="System Time Tampering",
            description="System time modified or changed",
            tactic="Defense Evasion", technique="Timestomp",
            pattern=r"(system time (changed|modified)|w32tm|time service)",
            severity="MEDIUM",
            indicators=["time changed", "w32tm"]
        ),
        
        # ===== INSIDER / MISUSE =====
        ThreatSignature(
            id="T1020", name="Insider Threat - Mass File Access",
            description="Bulk file access or data collection",
            tactic="Collection", technique="Data Collection",
            pattern=r"(opened file|read file|copied)\s+.*\.(docx|xlsx|pdf|csv|pptx)",
            severity="MEDIUM",
            indicators=["mass access", "bulk copy"]
        ),
        ThreatSignature(
            id="T1052", name="USB/Removable Media",
            description="USB storage device usage",
            tactic="Exfiltration", technique="Physical Medium",
            pattern=r"(USBSTOR|USB.*(installed|connected)|Removable.*Storage)",
            severity="MEDIUM",
            indicators=["USB device", "device install"]
        ),
        
        # ===== MISCONFIGURATION =====
        ThreatSignature(
            id="T1909", name="Weak Cryptography",
            description="Weak TLS/SSL or encryption detected",
            tactic="Defense Evasion", technique="",
            pattern=r"(TLS\s*1\.0|TLS\s*1\.1|SSLv3|weak cipher|md5|sha1)",
            severity="MEDIUM",
            indicators=["TLS1.0", "SSLv3", "weak cipher"]
        ),
        ThreatSignature(
            id="T1914", name="Firewall Misconfiguration",
            description="Allow-all or overly permissive rules",
            tactic="Defense Evasion", technique="",
            pattern=r"(ACCEPT\s+all|permit\s+ip\s+any\s+any|0\.0\.0\.0/0\s+allow)",
            severity="MEDIUM",
            indicators=["any any", "ACCEPT all", "0.0.0.0"]
        ),
        
        # ===== OCFS (ORACLE CLUSTER FILE SYSTEM) SPECIFIC =====
        ThreatSignature(
            id="OCFS-001", name="OCFS Node Eviction",
            description="Cluster node evicted due to communication failure or recovery",
            tactic="Impact", technique="Service Disruption",
            pattern=r"(node.*evicted|evict node|heartbeat.*failed|node.*offline|cluster.*split)",
            severity="HIGH",
            indicators=["node evicted", "heartbeat failed", "cluster split"]
        ),
        ThreatSignature(
            id="OCFS-002", name="OCFS Disk Lock Timeout",
            description="DLM lock timeout or deadlock detected in cluster",
            tactic="Impact", technique="Denial of Service",
            pattern=r"(lock timeout|dlm.*timeout|deadlock|lock.*wait|recovery.*failed)",
            severity="HIGH",
            indicators=["lock timeout", "deadlock", "dlm timeout"]
        ),
        ThreatSignature(
            id="OCFS-003", name="OCFS Recovery Failure",
            description="Cluster recovery failed or inconsistency detected",
            tactic="Impact", technique="Data Destruction",
            pattern=r"(recovery failed|inconsistent state|unable to recover|recovery.*error|fsck)",
            severity="CRITICAL",
            indicators=["recovery failed", "inconsistent state", "fsck error"]
        ),
        ThreatSignature(
            id="OCFS-004", name="OCFS Permission Violation",
            description="Unauthorized OCFS resource access attempt",
            tactic="Credential Access", technique="Unauthorized Access",
            pattern=r"(permission denied|EACCES|not authorized|access denied).*ocfs",
            severity="MEDIUM",
            indicators=["permission denied", "not authorized"]
        ),
        ThreatSignature(
            id="OCFS-005", name="OCFS Heartbeat Loss",
            description="Cluster member lost heartbeat communication",
            tactic="Impact", technique="Service Disruption",
            pattern=r"(heartbeat.*lost|no heartbeat|network.*unreachable|connection.*timeout)",
            severity="HIGH",
            indicators=["heartbeat lost", "no heartbeat", "network unreachable"]
        ),
        ThreatSignature(
            id="OCFS-006", name="OCFS Quorum Failure",
            description="Cluster lost quorum or majority",
            tactic="Impact", technique="Denial of Service",
            pattern=r"(quorum.*fail|lost quorum|no quorum|majority fail|minority partition)",
            severity="CRITICAL",
            indicators=["quorum fail", "lost quorum", "minority partition"]
        ),
        ThreatSignature(
            id="OCFS-007", name="OCFS File Corruption",
            description="Corrupted inodes or block group descriptors detected",
            tactic="Impact", technique="Data Destruction",
            pattern=r"(inode.*corrupt|block.*corrupt|checksum.*fail|bad block|bad inode)",
            severity="CRITICAL",
            indicators=["inode corrupt", "checksum fail", "bad block"]
        ),
        ThreatSignature(
            id="OCFS-008", name="OCFS Disk Space Critical",
            description="Cluster filesystem running critically low on space",
            tactic="Impact", technique="Resource Exhaustion",
            pattern=r"(disk space|out of space|ENOSPC|no space left|filesystem full)",
            severity="HIGH",
            indicators=["out of space", "ENOSPC", "filesystem full"]
        ),
    ]
    
    KNOWN_MALICIOUS_IPS = set()
    SUSPICIOUS_PORTS = set()

# ============================================================================
# LOG PARSER
# ============================================================================

class LogParser:
    """Multi-format log parser with automatic detection."""
    
    SYSLOG_PATTERN = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+(?P<service>\S+?)(?:\[\d+\])?:\s*(?P<message>.*)$'
    )
    
    WINDOWS_EVENT_PATTERN = re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<level>\w+)\s+(?P<source>\S+)\s+(?P<event_id>\d+)\s+(?P<message>.*)'
    )
    
    APACHE_COMBINED_PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+"(?P<request>[^"]+)"\s+'
        r'(?P<status>\d+)\s+(?P<size>\S+)'
    )
    
    OCFS_PATTERN = re.compile(
        r'^\[(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\]\s+'
        r'(?P<level>\w+)\s+(?P<subsystem>\w+):\s+(?P<node_info>\S+)?\s*(?P<message>.*)$|'
        r'^(?P<ts2>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<lev2>\w+)\s+(?P<source2>\S+):\s+(?P<msg2>.*)$'
    )
    
    # OCSF (Open Cybersecurity Schema Framework) Pattern - JSON-based security event format
    OCSF_PATTERN = re.compile(r'^\s*\{.*"class_uid"\s*:\s*\d+.*\}\s*$')
    
    IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    
    @classmethod
    def parse_line(cls, line: str, log_format: str, source_name: str) -> Optional[LogEntry]:
        """Parse a single log line into normalized format."""
        line = line.strip()
        if not line:
            return None
        
        try:
            if log_format == "ocsf" or (log_format == "auto" and cls.OCSF_PATTERN.match(line)):
                return cls._parse_ocsf(line, source_name)
            elif log_format == "json" or (log_format == "auto" and line.startswith("{")):
                return cls._parse_json(line, source_name)
            elif log_format == "ocfs" or (log_format == "auto" and cls.OCFS_PATTERN.match(line)):
                return cls._parse_ocfs(line, source_name)
            elif log_format == "syslog" or (log_format == "auto" and cls.SYSLOG_PATTERN.match(line)):
                return cls._parse_syslog(line, source_name)
            elif log_format == "windows" or (log_format == "auto" and cls.WINDOWS_EVENT_PATTERN.match(line)):
                return cls._parse_windows(line, source_name)
            elif log_format == "apache" or (log_format == "auto" and cls.APACHE_COMBINED_PATTERN.match(line)):
                return cls._parse_apache(line, source_name)
            elif log_format == "csv" or (log_format == "auto" and line.count(',') >= 3):
                return cls._parse_csv(line, source_name)
            else:
                return cls._parse_generic(line, source_name)
        except Exception:
            return cls._parse_generic(line, source_name)
    
    @classmethod
    def _parse_ocsf(cls, line: str, source: str) -> LogEntry:
        """Parse OCSF (Open Cybersecurity Schema Framework) JSON logs."""
        try:
            data = json.loads(line)
            
            # Extract OCSF-specific fields
            class_uid = data.get('class_uid', 0)
            category_name = data.get('category_name', 'Unknown')
            class_name = data.get('class_name', 'Unknown')
            severity_id = data.get('severity_id', 1)
            activity_name = data.get('activity_name', 'Unknown')
            
            # Map OCSF severity (1-6) to our severity levels
            severity_map = {1: 'INFO', 2: 'LOW', 3: 'MEDIUM', 4: 'HIGH', 5: 'CRITICAL', 6: 'CRITICAL'}
            severity = severity_map.get(severity_id, 'INFO')
            
            # Extract actor information
            actor = data.get('actor', {})
            user = actor.get('user', {}).get('name') or actor.get('user', {}).get('uid')
            
            # Extract network information
            src_endpoint = data.get('src_endpoint', {})
            dst_endpoint = data.get('dst_endpoint', {})
            source_ip = src_endpoint.get('ip') or src_endpoint.get('ip_address')
            dest_ip = dst_endpoint.get('ip') or dst_endpoint.get('ip_address')
            
            # Build message from OCSF fields
            message_parts = []
            if activity_name and activity_name != 'Unknown':
                message_parts.append(f"Activity: {activity_name}")
            if data.get('message'):
                message_parts.append(data['message'])
            elif data.get('activity_id'):
                message_parts.append(f"Activity ID: {data['activity_id']}")
            
            message = ' | '.join(message_parts) if message_parts else f"{class_name} event"
            
            # Extract timestamp (OCSF uses Unix milliseconds)
            time_val = data.get('time', data.get('timestamp', 0))
            if isinstance(time_val, (int, float)) and time_val > 1000000000000:
                timestamp = datetime.fromtimestamp(time_val / 1000.0)
            elif isinstance(time_val, str):
                timestamp = cls._parse_timestamp(time_val)
            else:
                timestamp = datetime.now()
            
            return LogEntry(
                timestamp=timestamp,
                source=f"{source}:OCSF:{class_name}",
                severity=severity,
                event_type=f"ocsf_{category_name.lower().replace(' ', '_')}",
                message=message[:500],
                raw_log=line[:1000],
                source_ip=source_ip,
                dest_ip=dest_ip,
                user=user,
                tags=['OCSF', category_name, class_name],
            )
        except json.JSONDecodeError:
            return cls._parse_generic(line, source)
        except Exception as e:
            return cls._parse_generic(line, source)
    
    @classmethod
    def _parse_json(cls, line: str, source: str) -> LogEntry:
        try:
            data = json.loads(line)
            timestamp = cls._parse_timestamp(data.get('timestamp', ''))
            return LogEntry(
                timestamp=timestamp,
                source=source,
                severity=cls._normalize_severity(data.get('level', 'INFO')),
                event_type=data.get('event_type', 'log'),
                message=data.get('message', line[:500]),
                raw_log=line[:1000],
                source_ip=data.get('source_ip') or cls._extract_ip(line),
                dest_ip=data.get('dest_ip'),
                user=data.get('user'),
            )
        except json.JSONDecodeError:
            return cls._parse_generic(line, source)
    
    @classmethod
    def _parse_syslog(cls, line: str, source: str) -> LogEntry:
        match = cls.SYSLOG_PATTERN.match(line)
        if match:
            return LogEntry(
                timestamp=cls._parse_timestamp(match.group('timestamp')),
                source=f"{source}:{match.group('service')}",
                severity=cls._infer_severity(match.group('message')),
                event_type="syslog",
                message=match.group('message')[:500],
                raw_log=line[:1000],
                source_ip=cls._extract_ip(line),
            )
        return cls._parse_generic(line, source)
    
    @classmethod
    def _parse_windows(cls, line: str, source: str) -> LogEntry:
        match = cls.WINDOWS_EVENT_PATTERN.match(line)
        if match:
            return LogEntry(
                timestamp=cls._parse_timestamp(match.group('timestamp')),
                source=f"{source}:{match.group('source')}",
                severity=cls._normalize_severity(match.group('level')),
                event_type=f"windows_event_{match.group('event_id')}",
                message=match.group('message')[:500],
                raw_log=line[:1000],
            )
        return cls._parse_generic(line, source)
    
    @classmethod
    def _parse_apache(cls, line: str, source: str) -> LogEntry:
        match = cls.APACHE_COMBINED_PATTERN.match(line)
        if match:
            status = int(match.group('status'))
            severity = "INFO"
            if status >= 400:
                severity = "MEDIUM" if status < 500 else "HIGH"
            
            return LogEntry(
                timestamp=cls._parse_timestamp(match.group('timestamp')),
                source=source,
                severity=severity,
                event_type="http_access",
                message=match.group('request')[:500],
                raw_log=line[:1000],
                source_ip=match.group('ip'),
                user=match.group('user') if match.group('user') != '-' else None,
            )
        return cls._parse_generic(line, source)
    
    @classmethod
    def _parse_ocfs(cls, line: str, source: str) -> LogEntry:
        """Parse Oracle Cluster File System (OCFS) log entries."""
        match = cls.OCFS_PATTERN.match(line)
        if match:
            # Try primary pattern first, fall back to secondary
            timestamp = match.group('timestamp') or match.group('ts2')
            level = match.group('level') or match.group('lev2')
            subsystem = match.group('subsystem') or match.group('source2') or 'ocfs'
            message = match.group('message') or match.group('msg2') or ''
            node_info = match.group('node_info')
            
            # Extract node name from node_info if present
            source_detail = f"{source}:{subsystem}"
            if node_info:
                source_detail = f"{source}:{node_info}:{subsystem}"
            
            return LogEntry(
                timestamp=cls._parse_timestamp(timestamp),
                source=source_detail,
                severity=cls._normalize_severity(level),
                event_type="ocfs_cluster_log",
                message=message[:500],
                raw_log=line[:1000],
                source_ip=cls._extract_ip(line),
                tags=['OCFS', 'Cluster'],
            )
        return cls._parse_generic(line, source)
    
    @classmethod
    def _parse_csv(cls, line: str, source: str) -> LogEntry:
        try:
            parts = list(csv.reader([line]))[0]
            if len(parts) >= 3:
                return LogEntry(
                    timestamp=cls._parse_timestamp(parts[0]),
                    source=source,
                    severity=cls._normalize_severity(parts[1]) if len(parts) > 1 else "INFO",
                    event_type="csv_log",
                    message=' | '.join(parts[2:])[:500] if len(parts) > 2 else parts[-1][:500],
                    raw_log=line[:1000],
                    source_ip=cls._extract_ip(line),
                )
        except Exception:
            pass
        return cls._parse_generic(line, source)
    
    @classmethod
    def _parse_generic(cls, line: str, source: str) -> LogEntry:
        return LogEntry(
            timestamp=cls._parse_timestamp(line[:23]) if len(line) >= 23 else datetime.now(),
            source=source,
            severity=cls._infer_severity(line),
            event_type="generic",
            message=line[:500],
            raw_log=line[:1000],
            source_ip=cls._extract_ip(line),
        )
    
    @classmethod
    def _parse_timestamp(cls, ts_string: str) -> datetime:
        """Parse various timestamp formats."""
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%b %d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S %z",
            "%Y/%m/%d %H:%M:%S",
            "%d-%b-%Y %H:%M:%S",
            "%Y%m%d %H:%M:%S",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(ts_string.strip(), fmt)
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.now().year)
                return dt
            except ValueError:
                continue
        return datetime.now()
    
    @classmethod
    def _normalize_severity(cls, level: str) -> str:
        level = str(level).upper()
        mapping = {
            'CRITICAL': 'CRITICAL', 'FATAL': 'CRITICAL', 'EMERGENCY': 'CRITICAL',
            'ERROR': 'HIGH', 'ERR': 'HIGH', 'SEVERE': 'HIGH', 'ALERT': 'HIGH',
            'WARNING': 'MEDIUM', 'WARN': 'MEDIUM',
            'NOTICE': 'LOW', 'INFO': 'INFO', 'DEBUG': 'INFO', 'TRACE': 'INFO',
        }
        return mapping.get(level, 'INFO')
    
    @classmethod
    def _infer_severity(cls, message: str) -> str:
        message_lower = message.lower()
        if any(w in message_lower for w in ['critical', 'fatal', 'emergency', 'exploit']):
            return 'CRITICAL'
        if any(w in message_lower for w in ['error', 'fail', 'denied', 'attack', 'malicious']):
            return 'HIGH'
        if any(w in message_lower for w in ['warning', 'warn', 'suspicious', 'unusual']):
            return 'MEDIUM'
        if any(w in message_lower for w in ['notice', 'attention']):
            return 'LOW'
        return 'INFO'
    
    @classmethod
    def _extract_ip(cls, text: str) -> Optional[str]:
        match = cls.IP_PATTERN.search(text)
        return match.group() if match else None

# ============================================================================
# THREAT DETECTOR
# ============================================================================

class ThreatDetector:
    """Real-time threat detection engine."""
    
    def __init__(self, custom_rules: Optional[List[CustomRule]] = None, playbook_rules: Optional[List[Dict]] = None):
        self.signatures = ThreatDatabase.SIGNATURES.copy()
        self.compiled_patterns = {
            sig.id: re.compile(sig.pattern, re.IGNORECASE)
            for sig in self.signatures
        }
        self.custom_rules: List[CustomRule] = custom_rules or []
        self.compiled_custom_rules = self._compile_custom_rules(self.custom_rules)
        
        # Playbook rules support
        self.playbook_rules = playbook_rules or []
        self.compiled_playbook_rules = self._compile_playbook_rules(self.playbook_rules)
    
    def analyze(self, entry: LogEntry) -> LogEntry:
        """Analyze log entry for threats and anomalies."""
        # Signature-based detection
        entry = self._check_signatures(entry)
        
        # Playbook-based detection (NEW)
        entry = self._check_playbook_rules(entry)
        
        # Heuristic checks
        entry = self._check_heuristics(entry)
        
        # Network behavior analysis
        entry = self._check_network_behavior(entry)
        
        # Custom rules
        entry = self._check_custom_rules(entry)
        
        return entry

    def update_custom_rules(self, rules: List[CustomRule]):
        """Refresh custom rules and compiled patterns."""
        self.custom_rules = rules
        self.compiled_custom_rules = self._compile_custom_rules(rules)
    
    def update_playbook_rules(self, rules: List[Dict]):
        """Update playbook rules and recompile patterns."""
        self.playbook_rules = rules
        self.compiled_playbook_rules = self._compile_playbook_rules(rules)

    @staticmethod
    def _compile_custom_rules(rules: List[CustomRule]):
        compiled = []
        for rule in rules:
            try:
                compiled.append((rule, re.compile(rule.pattern, re.IGNORECASE)))
            except re.error:
                continue
        return compiled
    
    @staticmethod
    def _compile_playbook_rules(rules: List[Dict]):
        """Compile playbook rules for faster matching."""
        compiled = []
        for rule in rules:
            if not rule.get('enabled', True):
                continue
            try:
                pattern = rule.get('pattern', '')
                if pattern:
                    compiled.append((rule, re.compile(pattern, re.IGNORECASE)))
            except re.error:
                continue
        return compiled
    
    def _check_playbook_rules(self, entry: LogEntry) -> LogEntry:
        """Match against playbook rules from all loaded playbooks."""
        for rule, pattern in self.compiled_playbook_rules:
            if pattern.search(entry.message) or pattern.search(entry.raw_log):
                rule_id = rule.get('id', 'UNKNOWN')
                rule_name = rule.get('name', 'Unknown Rule')
                severity = rule.get('severity', 'MEDIUM')
                category = rule.get('category', 'Unknown')
                tags = rule.get('tags', [])
                
                # Add playbook match information
                if not entry.ttp_match:
                    entry.ttp_match = f"{rule_id}: {rule_name}"
                
                # Add tags
                entry.tags.append(f"PLAYBOOK:{rule_id}")
                entry.tags.append(f"CATEGORY:{category}")
                for tag in tags:
                    if tag not in entry.tags:
                        entry.tags.append(tag)
                
                # Update severity if higher
                if self._severity_priority(severity) > self._severity_priority(entry.severity):
                    entry.severity = severity
                
                # Only match first rule to avoid excessive tagging
                break
        
        return entry
    
    def _check_signatures(self, entry: LogEntry) -> LogEntry:
        """Match against TTP signatures."""
        for sig in self.signatures:
            pattern = self.compiled_patterns.get(sig.id)
            if pattern and (pattern.search(entry.message) or pattern.search(entry.raw_log)):
                entry.ttp_match = f"{sig.id}: {sig.name}"
                entry.tags.append(f"TTP:{sig.id}")
                entry.tags.append(sig.tactic)
                if self._severity_priority(sig.severity) > self._severity_priority(entry.severity):
                    entry.severity = sig.severity
                break
        return entry
    
    def _check_heuristics(self, entry: LogEntry) -> LogEntry:
        """Apply heuristic rules."""
        msg_lower = entry.message.lower()
        
        # Failed login detection
        if 'fail' in msg_lower and 'login' in msg_lower:
            entry.tags.append("HEURISTIC:FAILED_LOGIN")
            if entry.severity == "INFO":
                entry.severity = "MEDIUM"
        
        # Large data transfer
        size_match = re.search(r'(\d+)\s*(mb|gb|bytes)', msg_lower)
        if size_match:
            size = int(size_match.group(1))
            unit = size_match.group(2)
            if unit == 'gb' or (unit == 'mb' and size > 100):
                entry.tags.append("HEURISTIC:LARGE_TRANSFER")
        
        # After hours activity
        if entry.timestamp.hour >= 22 or entry.timestamp.hour <= 5:
            if 'login' in msg_lower or 'access' in msg_lower:
                entry.tags.append("HEURISTIC:AFTER_HOURS")
        
        return entry
    
    def _check_network_behavior(self, entry: LogEntry) -> LogEntry:
        """Analyze network-related behavior."""
        # Network behavior analysis based on patterns, not hardcoded lists
        # This allows for real-time learning from actual data
        
        # Check for private IP accessing from public IP (potential threat)
        if entry.source_ip:
            try:
                octets = entry.source_ip.split('.')
                if len(octets) == 4:
                    first_octet = int(octets[0])
                    # Detect potential suspicious patterns based on IP characteristics
                    if first_octet in [0, 127, 255]:  # Reserved/loopback/broadcast
                        entry.tags.append("NETWORK:UNUSUAL_IP")
            except (ValueError, IndexError):
                pass
        
        # Check for uncommon high ports that might indicate backdoors
        if entry.port and entry.port > 49152:  # Dynamic/private port range
            msg_lower = entry.message.lower()
            if any(keyword in msg_lower for keyword in ['connection', 'listening', 'bind']):
                entry.tags.append("NETWORK:HIGH_PORT_ACTIVITY")
        
        return entry

    def _check_custom_rules(self, entry: LogEntry) -> LogEntry:
        """Apply user-defined rules (signature, heuristic, anomaly, behavior)."""
        field_map = {
            'message': entry.message,
            'raw_log': entry.raw_log,
            'source_ip': entry.source_ip,
            'dest_ip': entry.dest_ip,
            'user': entry.user,
            'tags': ','.join(entry.tags),
        }
        for rule, pattern in self.compiled_custom_rules:
            if not rule.enabled:
                continue
            target = field_map.get(rule.field, entry.message)
            target_text = '' if target is None else str(target)
            if not target_text:
                continue
            if pattern.search(target_text):
                entry.tags.append(f"CUSTOM:{rule.name}")
                if rule.rule_type == 'anomaly':
                    entry.anomaly_score = max(entry.anomaly_score, 0.7)
                if not entry.ttp_match and rule.rule_type in ('signature', 'behavior'):
                    entry.ttp_match = f"Custom: {rule.name}"
                if self._severity_priority(rule.severity) > self._severity_priority(entry.severity):
                    entry.severity = rule.severity
        return entry
    
    @staticmethod
    def _severity_priority(severity: str) -> int:
        return {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}.get(severity, 0)

# ============================================================================
# LOG MANAGER
# ============================================================================

class LogManager:
    """Manages log collection, storage, and analysis."""
    
    def __init__(self, db: Database, playbook_rules: Optional[List[Dict]] = None):
        self.db = db
        self.custom_rules = self._load_custom_rules()
        self.playbook_rules = playbook_rules or []
        self.detector = ThreatDetector(self.custom_rules, self.playbook_rules)
        self.playbook_paths = {
            'windows': 'playbooks_windows.json',
            'linux': 'playbooks_linux.json',
            'mac': 'playbooks_mac.json'
        }
    
    def update_playbook_rules(self, playbook_rules: List[Dict]):
        """Update playbook rules in the detector."""
        self.playbook_rules = playbook_rules
        self.detector.update_playbook_rules(playbook_rules)

    def _load_custom_rules(self) -> List[CustomRule]:
        """Load enabled custom rules from database."""
        rows = self.db.get_custom_rules(include_disabled=False)
        rules: List[CustomRule] = []
        for row in rows:
            rules.append(CustomRule(
                id=row['id'],
                name=row['name'],
                description=row['description'] or '',
                rule_type=row['rule_type'],
                field=row['field'],
                pattern=row['pattern'],
                severity=row['severity'],
                tags=[t for t in (row['tags'] or '').split(',') if t],
                enabled=bool(row['enabled']),
            ))
        return rules

    def add_custom_rule(self, rule: CustomRule):
        """Persist a new custom rule and refresh detector."""
        self.db.add_custom_rule(rule)
        self.custom_rules = self._load_custom_rules()
        self.detector.update_custom_rules(self.custom_rules)

    def get_custom_rules(self, include_disabled: bool = True) -> List[CustomRule]:
        rows = self.db.get_custom_rules(include_disabled)
        rules: List[CustomRule] = []
        for row in rows:
            rules.append(CustomRule(
                id=row['id'],
                name=row['name'],
                description=row['description'] or '',
                rule_type=row['rule_type'],
                field=row['field'],
                pattern=row['pattern'],
                severity=row['severity'],
                tags=[t for t in (row['tags'] or '').split(',') if t],
                enabled=bool(row['enabled']),
            ))
        return rules
    
    def get_playbook_rules(self, os_filter: str = 'all') -> List[Dict]:
        """Load playbook rules from playbooks.json file."""
        all_rules = []
        
        playbook_file = 'playbooks.json'
        if not os.path.exists(playbook_file):
            return []
        
        try:
            with open(playbook_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                playbooks = data.get('playbooks', [])
                
                for pb in playbooks:
                    # Extract OS type from event_types
                    event_types = pb.get('event_types', [])
                    os_types = set()
                    
                    if any(et in ['windows_event', 'windows_security', 'windows'] for et in event_types):
                        os_types.add('windows')
                    if any(et in ['linux_syslog', 'linux_auth', 'linux'] for et in event_types):
                        os_types.add('linux')
                    if any(et in ['macos_unified', 'macos_system', 'macos'] for et in event_types):
                        os_types.add('mac')
                    
                    # If multiple OS or generic events, mark as applicable to filtered OS
                    if not os_types or len(event_types) > 3:
                        os_types = {'windows', 'linux', 'mac'}
                    
                    # Filter based on os_filter
                    if os_filter != 'all':
                        if os_filter.lower() not in os_types:
                            continue
                    
                    # Create rule entry
                    rule = {
                        'id': pb.get('id', ''),
                        'name': pb.get('name', ''),
                        'description': pb.get('description', ''),
                        'severity': pb.get('severity', 'Medium'),
                        'category': pb.get('category', 'General'),
                        'pattern': str(pb.get('conditions', {})),
                        'event_types': event_types,
                        'mitre': pb.get('mitre', []),
                        'tags': pb.get('tags', []),
                        'enabled': True,
                        'os': ', '.join(sorted(os_types)),
                        'remediation': pb.get('remediation', [])
                    }
                    all_rules.append(rule)
                    
        except Exception as e:
            print(f"Error loading playbooks from {playbook_file}: {e}")
            import traceback
            traceback.print_exc()
        
        return all_rules
    
    def update_playbook_rule(self, rule_data: Dict) -> bool:
        """Update a playbook rule in the appropriate OS-specific file."""
        try:
            os_type = rule_data.get('os', '').lower()
            if os_type not in self.playbook_paths:
                return False
            
            filepath = self.playbook_paths[os_type]
            if not os.path.exists(filepath):
                return False
            
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            # Find and update the rule
            rules = data.get('rules', [])
            for i, rule in enumerate(rules):
                if rule.get('id') == rule_data.get('id'):
                    # Update fields
                    rules[i].update({
                        'name': rule_data.get('name'),
                        'description': rule_data.get('description'),
                        'severity': rule_data.get('severity'),
                        'category': rule_data.get('category'),
                        'pattern': rule_data.get('pattern'),
                        'enabled': rule_data.get('enabled', True)
                    })
                    break
            
            # Save back to file
            data['rules'] = rules
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error updating playbook rule: {e}")
            return False
    
    def delete_playbook_rule(self, rule_id: str, os_type: Optional[str] = 'all') -> bool:
        """Delete a playbook rule from one or more OS-specific files.

        If `os_type` is 'all' or None, attempt deletion from all known playbook files.
        Returns True if at least one deletion succeeded.
        """
        try:
            deleted_any = False
            targets = []
            if not os_type or str(os_type).lower() == 'all':
                targets = list(self.playbook_paths.values())
            else:
                ot = str(os_type).lower()
                if ot in self.playbook_paths:
                    targets = [self.playbook_paths[ot]]
                else:
                    return False

            for filepath in targets:
                try:
                    if not os.path.exists(filepath):
                        continue
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)

                    rules = data.get('rules', [])
                    new_rules = [r for r in rules if r.get('id') != rule_id]
                    if len(new_rules) != len(rules):
                        data['rules'] = new_rules
                        with open(filepath, 'w', encoding='utf-8') as f:
                            json.dump(data, f, indent=2)
                        deleted_any = True
                except Exception:
                    continue

            return deleted_any
        except Exception as e:
            print(f"Error deleting playbook rule: {e}")
            return False
    
    def process_log_file(self, file_path: str, source_name: str, log_format: str = 'auto', refresh: bool = False) -> Dict:
        """Process a log file and store in database."""
        entries = []
        try:
            # When refreshing, clear previous data so only the latest upload is shown
            if refresh:
                self.db.clear_log_data()
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    entry = LogParser.parse_line(line, log_format, source_name)
                    if entry:
                        entry = self.detector.analyze(entry)
                        entries.append(entry)
            
            # Heuristic: Detect potential DoS/DDoS by high per-minute request rates per source IP
            try:
                # Load threshold from settings; fall back to 200 if missing
                threshold = 200
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT value FROM settings WHERE key = 'ddos_threshold_per_min'")
                    row = cursor.fetchone()
                    if row:
                        try:
                            threshold = int(str(row['value']).strip())
                        except Exception:
                            pass
                # Count requests per IP per minute
                ip_minute_counts: Dict[Tuple[str, str], int] = {}
                for e in entries:
                    if not e.source_ip or not isinstance(e.timestamp, datetime):
                        continue
                    minute_key = e.timestamp.strftime('%Y-%m-%d %H:%M')
                    ip_minute_counts[(e.source_ip, minute_key)] = ip_minute_counts.get((e.source_ip, minute_key), 0) + 1
                # Determine flagged buckets
                flagged: Dict[Tuple[str, str], int] = {k: c for k, c in ip_minute_counts.items() if c >= threshold}
                if flagged:
                    for e in entries:
                        if not e.source_ip or not isinstance(e.timestamp, datetime):
                            continue
                        minute_key = e.timestamp.strftime('%Y-%m-%d %H:%M')
                        key = (e.source_ip, minute_key)
                        if key in flagged:
                            e.tags.append('HEURISTIC:HIGH_REQ_RATE')
                            e.tags.append('DOS/DDOS_SUSPECTED')
                            if not e.ttp_match:
                                e.ttp_match = 'T1498: Network Denial of Service (rate-based)'
                            # Escalate severity at least to HIGH; CRITICAL if 3x threshold
                            if e.severity in ['INFO', 'LOW', 'MEDIUM']:
                                e.severity = 'HIGH'
                            if flagged[key] >= threshold * 3:
                                e.severity = 'CRITICAL'
            except Exception as _ddos_err:
                # Non-fatal: continue without rate-based tagging
                pass
            
            # Store in database
            self._store_entries(entries)
            
            # Create alerts for critical threats
            critical_entries = [e for e in entries if e.severity in ['CRITICAL', 'HIGH']]
            if critical_entries:
                self._create_alert(critical_entries, source_name)
            
            return {
                'success': True,
                'count': len(entries),
                'source': source_name,
                'critical_count': sum(1 for e in entries if e.severity == 'CRITICAL'),
                'high_count': sum(1 for e in entries if e.severity == 'HIGH'),
                'ttp_matches': sum(1 for e in entries if e.ttp_match),
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _store_entries(self, entries: List[LogEntry]):
        """Store log entries in database."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            
            for entry in entries:
                cursor.execute('''
                    INSERT INTO log_entries 
                    (timestamp, source_name, severity, event_type, message, raw_log,
                     source_ip, dest_ip, user, port, protocol, tags, ttp_match, anomaly_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    entry.timestamp,
                    entry.source,
                    entry.severity,
                    entry.event_type,
                    entry.message,
                    entry.raw_log,
                    entry.source_ip,
                    entry.dest_ip,
                    entry.user,
                    entry.port,
                    entry.protocol,
                    ','.join(entry.tags),
                    entry.ttp_match,
                    entry.anomaly_score
                ))
    
    def _create_alert(self, entries: List[LogEntry], source_name: str):
        """Create alert for critical threats."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            
            ttp_matches = list(set(e.ttp_match for e in entries if e.ttp_match))
            source_ips = list(set(e.source_ip for e in entries if e.source_ip))
            
            cursor.execute('''
                INSERT INTO alerts (title, description, severity, threat_type, ttp_match, source_ips)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                f"Critical threats detected in {source_name}",
                f"Found {len(entries)} critical/high severity events",
                "HIGH",
                "AUTOMATED_DETECTION",
                ','.join(ttp_matches) if ttp_matches else "",
                ','.join(source_ips) if source_ips else ""
            ))
    
    def search_logs(self, search_params: Dict) -> Tuple[List[Dict], int]:
        """Search logs based on parameters with enhanced filtering."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            
            # Build query with proper parameter handling
            query = "SELECT * FROM log_entries WHERE 1=1"
            params = []
            
            if search_params.get('search_query'):
                query += " AND (LOWER(message) LIKE ? OR LOWER(raw_log) LIKE ? OR LOWER(source_name) LIKE ?)"
                search_term = f"%{search_params['search_query'].lower()}%"
                params.extend([search_term, search_term, search_term])
            
            if search_params.get('severity') and search_params['severity'] != 'all':
                query += " AND severity = ?"
                params.append(search_params['severity'].upper())
            
            if search_params.get('source'):
                query += " AND source_name LIKE ?"
                params.append(f"%{search_params['source']}%")
            
            if search_params.get('source_ip'):
                query += " AND source_ip LIKE ?"
                params.append(f"%{search_params['source_ip']}%")
            
            if search_params.get('user'):
                query += " AND user LIKE ?"
                params.append(f"%{search_params['user']}%")
            
            if search_params.get('event_type'):
                query += " AND event_type LIKE ?"
                params.append(f"%{search_params['event_type']}%")
            
            if search_params.get('date_from'):
                query += " AND DATE(timestamp) >= ?"
                params.append(search_params['date_from'])
            
            if search_params.get('date_to'):
                query += " AND DATE(timestamp) <= ?"
                params.append(search_params['date_to'])
            
            # Handle tags search
            if search_params.get('tags'):
                tags = search_params['tags'].split(',')
                tag_conditions = []
                for tag in tags:
                    if tag.strip():
                        tag_conditions.append("tags LIKE ?")
                        params.append(f"%{tag.strip()}%")
                if tag_conditions:
                    query += " AND (" + " OR ".join(tag_conditions) + ")"
            
            # Get total count for pagination
            count_query = f"SELECT COUNT(*) FROM ({query})"
            cursor.execute(count_query, params)
            total = cursor.fetchone()[0]
            
            # Add sorting
            sort_field = search_params.get('sort', 'timestamp')
            sort_order = search_params.get('order', 'desc')
            valid_sort_fields = ['timestamp', 'severity', 'source_name', 'source_ip', 'user']
            if sort_field not in valid_sort_fields:
                sort_field = 'timestamp'
            query += f" ORDER BY {sort_field} {sort_order.upper()}"
            
            # Add pagination
            page = search_params.get('page', 1)
            per_page = search_params.get('per_page', 50)
            offset = (page - 1) * per_page
            query += " LIMIT ? OFFSET ?"
            params.extend([per_page, offset])
            
            # Execute query
            cursor.execute(query, params)
            logs = [dict(row) for row in cursor.fetchall()]
            
            # Parse tags and add additional fields
            for log in logs:
                if log['tags']:
                    log['tags_list'] = [t.strip() for t in log['tags'].split(',') if t.strip()]
                else:
                    log['tags_list'] = []
                
                # Format timestamp for display
                if log['timestamp']:
                    try:
                        log['display_time'] = log['timestamp'].split('.')[0]  # Remove milliseconds
                    except:
                        log['display_time'] = log['timestamp']
                
                # Truncate message for display
                if log['message'] and len(log['message']) > 200:
                    log['short_message'] = log['message'][:197] + "..."
                else:
                    log['short_message'] = log['message'] or ""
            
            return logs, total

    def get_statistics(self) -> Dict:
        """Get log statistics."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            
            stats = {}
            
            # Total logs count
            cursor.execute("SELECT COUNT(*) FROM log_entries")
            stats['total_logs'] = cursor.fetchone()[0] or 0
            
            # Severity distribution - ensure all severities are included
            cursor.execute("SELECT severity, COUNT(*) FROM log_entries GROUP BY severity")
            severity_data = dict(cursor.fetchall())
            
            # Ensure all severity levels exist in the result
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if severity not in severity_data:
                    severity_data[severity] = 0
            
            stats['severity_dist'] = severity_data
            
            # Rest of the existing code remains the same...
            # Top sources
            cursor.execute("SELECT source_name, COUNT(*) FROM log_entries GROUP BY source_name ORDER BY COUNT(*) DESC LIMIT 10")
            stats['top_sources'] = cursor.fetchall()
            
            # TTP matches
            cursor.execute("SELECT COUNT(*) FROM log_entries WHERE ttp_match IS NOT NULL")
            stats['ttp_matches'] = cursor.fetchone()[0] or 0
            
            # Recent threats
            cursor.execute('''
                SELECT timestamp, source_name, severity, message, ttp_match 
                FROM log_entries 
                WHERE severity IN ('CRITICAL', 'HIGH') 
                ORDER BY timestamp DESC LIMIT 10
            ''')
            stats['recent_threats'] = cursor.fetchall()
            
            # Hourly distribution
            cursor.execute("SELECT strftime('%H', timestamp) as hour, COUNT(*) FROM log_entries GROUP BY hour ORDER BY hour")
            stats['hourly_dist'] = cursor.fetchall()
            
            return stats
    
    def get_alerts(self, limit: int = 50) -> List[Dict]:
        """Get recent alerts."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM alerts 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def _get_detailed_threat_analysis(self) -> Dict:
        """Get detailed threat analysis including patterns and recommendations."""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get threat details by TTP
                cursor.execute('''
                    SELECT ttp_match, COUNT(*) as count, 
                           GROUP_CONCAT(DISTINCT severity) as severities,
                           GROUP_CONCAT(DISTINCT source_ip) as source_ips,
                           MAX(timestamp) as latest
                    FROM log_entries
                    WHERE ttp_match IS NOT NULL
                    GROUP BY ttp_match
                    ORDER BY count DESC
                ''')
                
                ttp_analysis = {}
                for row in cursor.fetchall():
                    ttp_analysis[row['ttp_match']] = {
                        'count': row['count'],
                        'severities': row['severities'].split(',') if row['severities'] else [],
                        'source_ips': row['source_ips'].split(',')[:5] if row['source_ips'] else [],
                        'latest': row['latest']
                    }
                
                # Get source IP statistics
                cursor.execute('''
                    SELECT source_ip, COUNT(*) as count, 
                           COUNT(CASE WHEN severity='CRITICAL' THEN 1 END) as critical_count,
                           COUNT(CASE WHEN severity='HIGH' THEN 1 END) as high_count
                    FROM log_entries
                    WHERE source_ip IS NOT NULL
                    GROUP BY source_ip
                    ORDER BY count DESC
                    LIMIT 20
                ''')
                
                source_analysis = [dict(row) for row in cursor.fetchall()]
                
                # Get event type distribution
                cursor.execute('''
                    SELECT event_type, COUNT(*) as count,
                           COUNT(CASE WHEN severity='CRITICAL' THEN 1 END) as critical_count
                    FROM log_entries
                    GROUP BY event_type
                    ORDER BY count DESC
                    LIMIT 15
                ''')
                
                event_analysis = [dict(row) for row in cursor.fetchall()]
                
                # Get user activity
                cursor.execute('''
                    SELECT user, COUNT(*) as count,
                           COUNT(CASE WHEN severity IN ('CRITICAL', 'HIGH') THEN 1 END) as threat_count
                    FROM log_entries
                    WHERE user IS NOT NULL
                    GROUP BY user
                    ORDER BY count DESC
                    LIMIT 15
                ''')
                
                user_activity = [dict(row) for row in cursor.fetchall()]
                
                # Get time-based analysis
                cursor.execute('''
                    SELECT strftime('%H', timestamp) as hour, COUNT(*) as count,
                           COUNT(CASE WHEN severity='CRITICAL' THEN 1 END) as critical_count
                    FROM log_entries
                    GROUP BY hour
                    ORDER BY hour
                ''')
                
                hourly_analysis = [dict(row) for row in cursor.fetchall()]
                
                return {
                    'ttp_analysis': ttp_analysis,
                    'source_analysis': source_analysis,
                    'event_analysis': event_analysis,
                    'user_activity': user_activity,
                    'hourly_analysis': hourly_analysis
                }
        except Exception as e:
            print(f"Error getting detailed analysis: {e}")
            return {'ttp_analysis': {}, 'source_analysis': [], 'event_analysis': [], 'user_activity': [], 'hourly_analysis': []}

    def _get_runbook_recommendations(self, detailed: Dict) -> List[str]:
        """Generate recommendations from matching runbooks based on detected TTPs."""
        global PLAYBOOKS, RUNBOOKS
        
        recommendations = []
        runbook_set = set()
        
        # Match detected TTPs to playbooks
        for ttp_id in detailed['ttp_analysis'].keys():
            for playbook in PLAYBOOKS:
                # Check if playbook MITRE techniques match detected TTPs
                for mitre in playbook.get('mitre', []):
                    if mitre in ttp_id or ttp_id.startswith(mitre):
                        pb_id = playbook['id']
                        if pb_id in RUNBOOKS and pb_id not in runbook_set:
                            runbook = RUNBOOKS[pb_id]
                            runbook_set.add(pb_id)
                            
                            # Extract key recommendations from runbook steps
                            steps = runbook.get('steps', [])
                            if steps:
                                # Get the most actionable step (usually one with isolation, block, or action)
                                for step in steps:
                                    if any(keyword in step.lower() for keyword in 
                                          ['block', 'isolate', 'disable', 'remove', 'force', 'enable', 'implement']):
                                        recommendations.append(
                                            f"<b>[{pb_id}]</b> {playbook['name']}: {step.strip()}"
                                        )
                                        break
                                else:
                                    # If no action step found, use the first step
                                    if steps:
                                        recommendations.append(
                                            f"<b>[{pb_id}]</b> {playbook['name']}: {steps[0].strip()}"
                                        )
        
        return recommendations[:10]  # Return top 10 recommendations
    
    def _get_best_recommendations(self, stats: Dict, detailed: Dict) -> List[str]:
        """Generate best recommendations prioritized by severity and TTP match frequency."""
        recommendations = []
        
        total_critical = stats['severity_dist'].get('CRITICAL', 0)
        total_high = stats['severity_dist'].get('HIGH', 0)
        
        # Priority 1: Critical events
        if total_critical > 0:
            recommendations.append(
                f"<b>🔴 PRIORITY 1 - CRITICAL:</b> Immediately respond to {total_critical} critical severity events. "
                f"Isolate affected systems, preserve evidence, and initiate incident response procedures."
            )
        
        # Priority 2: High events  
        if total_high > 0:
            recommendations.append(
                f"<b>🟠 PRIORITY 2 - HIGH SEVERITY:</b> Address {total_high} high severity events within 24 hours. "
                f"Conduct rapid investigation and implement containment measures."
            )
        
        # Priority 3: Top threat pattern
        if detailed['ttp_analysis']:
            top_ttp = max(detailed['ttp_analysis'].items(), key=lambda x: x[1]['count'])
            ttp_id = top_ttp[0]
            ttp_count = top_ttp[1]['count']
            recommendations.append(
                f"<b>🟡 PRIORITY 3 - TOP THREAT:</b> Pattern {ttp_id} detected {ttp_count} times. "
                f"Deploy targeted detection rules and implement specific mitigations for this attack vector."
            )
        
        # Priority 4: Source control
        if detailed['source_analysis']:
            top_sources = [s['source_ip'] for s in detailed['source_analysis'][:3]]
            critical_sources = [s for s in detailed['source_analysis'][:5] if s['critical_count'] > 0]
            
            if critical_sources:
                recommendations.append(
                    f"<b>🔵 PRIORITY 4 - SOURCE CONTROL:</b> Block malicious IPs: {', '.join([s['source_ip'] for s in critical_sources])}. "
                    f"Implement firewall rules and update threat intelligence feeds."
                )
            else:
                recommendations.append(
                    f"<b>🔵 PRIORITY 4 - SOURCE CONTROL:</b> Monitor top {min(5, len(detailed['source_analysis']))} source IPs: "
                    f"{', '.join(top_sources)}. Implement rate limiting and additional logging."
                )
        
        # Priority 5: Runbook-based recommendations
        runbook_recs = self._get_runbook_recommendations(detailed)
        if runbook_recs:
            recommendations.append("<b>📋 RUNBOOK RECOMMENDATIONS:</b>")
            for rec in runbook_recs[:3]:
                recommendations.append(f"  • {rec}")
        
        # Priority 6: Preventive measures
        recommendations.append(
            "<b>🟢 PRIORITY 5 - PREVENTION:</b> Implement real-time alerting for CRITICAL/HIGH events, "
            "enable MFA, strengthen access controls, and conduct security awareness training."
        )
        
        # Priority 7: Continuous monitoring
        recommendations.append(
            "<b>⚪ ONGOING:</b> Establish continuous monitoring, maintain updated threat intel, "
            "perform regular security assessments, and document all findings for compliance."
        )
        
        return recommendations

    def generate_report(self, report_type: str = 'summary') -> Union[str, bytes]:
        """Generate detailed analysis report in multiple formats."""
        stats = self.get_statistics()
        detailed = self._get_detailed_threat_analysis()
        
        if report_type == 'csv':
            # Generate CSV report (optimized with chunking for memory efficiency)
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['Timestamp', 'Source', 'Severity', 'Event Type', 'Message',
                           'Source IP', 'Destination IP', 'User', 'TTP Match', 'Tags'])
            
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT timestamp, source_name, severity, event_type, message, 
                               source_ip, dest_ip, user, ttp_match, tags
                        FROM log_entries
                        ORDER BY timestamp DESC
                    ''')
                    
                    # Process in chunks for memory efficiency
                    chunk_size = 5000
                    while True:
                        rows = cursor.fetchmany(chunk_size)
                        if not rows:
                            break
                        for row in rows:
                            writer.writerow(row)
            except Exception as e:
                print(f"Error generating CSV report: {e}")
            
            return output.getvalue()
        
        elif report_type == 'pdf':
            # Generate DETAILED PDF report
            if not HAS_REPORTLAB:
                return "PDF generation not available. Install reportlab: pip install reportlab"
            
            try:
                pdf_buffer = io.BytesIO()
                doc = SimpleDocTemplate(pdf_buffer, pagesize=letter, topMargin=0.4*inch, bottomMargin=0.4*inch)
                elements = []
                styles = getSampleStyleSheet()
                
                # Custom styles
                title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=26, 
                                            textColor=colors.HexColor('#1a1a1a'), spaceAfter=6, alignment=1)
                heading2_style = ParagraphStyle('CustomHeading2', parent=styles['Heading2'], fontSize=14,
                                              textColor=colors.HexColor('#2c3e50'), spaceAfter=8, spaceBefore=10)
                heading3_style = ParagraphStyle('CustomHeading3', parent=styles['Heading3'], fontSize=11,
                                              textColor=colors.HexColor('#34495e'), spaceAfter=6)
                
                # ===== PAGE 1: TITLE & EXECUTIVE SUMMARY =====
                elements.append(Paragraph('COMPREHENSIVE LOG ANALYSIS REPORT', title_style))
                elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
                elements.append(Spacer(1, 0.2*inch))
                
                # Executive Summary
                elements.append(Paragraph('EXECUTIVE SUMMARY', heading2_style))
                total_critical = stats['severity_dist'].get('CRITICAL', 0)
                total_high = stats['severity_dist'].get('HIGH', 0)
                threat_level = 'CRITICAL' if total_critical > 0 else ('HIGH' if total_high > 0 else 'MEDIUM')
                
                summary_text = f"""
                This report provides a comprehensive analysis of {stats['total_logs']:,} log entries with {stats['ttp_matches']:,} identified threats.
                Overall Security Posture: <b>{threat_level}</b><br/>
                Critical Severity Events: {total_critical:,} | High Severity Events: {total_high:,}<br/>
                Unique Threat Patterns Detected: {len(detailed['ttp_analysis'])} | Suspicious Source IPs: {len(detailed['source_analysis'])}
                """
                elements.append(Paragraph(summary_text, styles['Normal']))
                elements.append(Spacer(1, 0.2*inch))
                
                # ===== DETAILED STATISTICS =====
                elements.append(Paragraph('DETAILED STATISTICS', heading2_style))
                summary_data = [
                    ['Metric', 'Value', 'Details'],
                    ['Total Log Entries', f"{stats['total_logs']:,}", 'All processed log entries'],
                    ['TTP Matches', f"{stats['ttp_matches']:,}", 'Entries matching threat patterns'],
                    ['Critical Events', f"{total_critical:,}", 'Highest severity incidents'],
                    ['High Events', f"{total_high:,}", 'High severity incidents'],
                    ['Medium Events', f"{stats['severity_dist'].get('MEDIUM', 0):,}", 'Medium severity events'],
                    ['Low Events', f"{stats['severity_dist'].get('LOW', 0):,}", 'Low severity events'],
                    ['Unique Sources', f"{len(detailed['source_analysis'])}", 'Distinct source IPs detected'],
                    ['Event Types', f"{len(detailed['event_analysis'])}", 'Different event categories'],
                ]
                
                summary_table = Table(summary_data, colWidths=[1.8*inch, 1.2*inch, 2.5*inch])
                summary_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                    ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                ]))
                elements.append(summary_table)
                elements.append(Spacer(1, 0.2*inch))
                
                # ===== SEVERITY DISTRIBUTION =====
                elements.append(Paragraph('SEVERITY DISTRIBUTION ANALYSIS', heading2_style))
                severity_data = [['Severity Level', 'Count', 'Percentage', 'Risk Assessment']]
                risk_map = {'CRITICAL': 'IMMEDIATE ACTION REQUIRED', 'HIGH': 'URGENT', 
                           'MEDIUM': 'ATTENTION NEEDED', 'LOW': 'MONITOR'}
                
                for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    count = stats['severity_dist'].get(severity, 0)
                    percentage = (count / stats['total_logs'] * 100) if stats['total_logs'] > 0 else 0
                    severity_data.append([severity, str(count), f"{percentage:.2f}%", risk_map[severity]])
                
                severity_table = Table(severity_data, colWidths=[1.5*inch, 1*inch, 1.2*inch, 2*inch])
                severity_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e74c3c')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                    ('BACKGROUND', (0, 1), (0, 1), colors.HexColor('#fadbd8')),
                    ('BACKGROUND', (0, 2), (0, 2), colors.HexColor('#f5b7b1')),
                    ('BACKGROUND', (0, 3), (0, 3), colors.HexColor('#f8d8d2')),
                    ('BACKGROUND', (0, 4), (0, 4), colors.HexColor('#fbefed')),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                ]))
                elements.append(severity_table)
                elements.append(PageBreak())
                
                # ===== PAGE 2: THREAT PATTERN ANALYSIS =====
                elements.append(Paragraph('THREAT PATTERN ANALYSIS (MITRE ATT&CK)', heading2_style))
                
                if detailed['ttp_analysis']:
                    ttp_data = [['TTP ID', 'Pattern Name', 'Occurrences', 'Severity Levels', 'Top Sources']]
                    for ttp_id, analysis in list(detailed['ttp_analysis'].items())[:12]:  # Top 12 TTPs
                        ttp_name = ttp_id.split('-')[-1] if '-' in ttp_id else ttp_id
                        sources = ', '.join(analysis['source_ips'][:2]) if analysis['source_ips'] else 'N/A'
                        severities = ', '.join(set(analysis['severities'])) if analysis['severities'] else 'N/A'
                        ttp_data.append([ttp_id, ttp_name, str(analysis['count']), severities, sources[:30]])
                    
                    ttp_table = Table(ttp_data, colWidths=[0.9*inch, 1.3*inch, 1*inch, 1.2*inch, 1.75*inch])
                    ttp_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#c0392b')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ffe6e6')),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ]))
                    elements.append(ttp_table)
                else:
                    elements.append(Paragraph('No threat patterns detected.', styles['Normal']))
                
                elements.append(Spacer(1, 0.2*inch))
                
                # ===== SOURCE IP ANALYSIS =====
                elements.append(Paragraph('SOURCE IP THREAT ANALYSIS', heading2_style))
                if detailed['source_analysis']:
                    source_data = [['Source IP', 'Total Events', 'Critical', 'High', 'Risk Level']]
                    for src in detailed['source_analysis'][:10]:
                        risk = 'CRITICAL' if src['critical_count'] > 0 else ('HIGH' if src['high_count'] > 0 else 'MEDIUM')
                        source_data.append([src['source_ip'][:20], str(src['count']), 
                                         str(src['critical_count']), str(src['high_count']), risk])
                    
                    source_table = Table(source_data, colWidths=[1.5*inch, 1.2*inch, 0.9*inch, 0.9*inch, 1.15*inch])
                    source_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#d35400')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#fdebd0')),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('ALIGN', (1, 1), (-1, -1), 'CENTER'),
                        ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ]))
                    elements.append(source_table)
                else:
                    elements.append(Paragraph('No source IP data available.', styles['Normal']))
                
                elements.append(Spacer(1, 0.2*inch))
                
                # ===== EVENT TYPE DISTRIBUTION =====
                elements.append(Paragraph('EVENT TYPE DISTRIBUTION', heading2_style))
                if detailed['event_analysis']:
                    event_data = [['Event Type', 'Frequency', 'Critical Count', 'Percentage']]
                    for evt in detailed['event_analysis'][:12]:
                        pct = (evt['count'] / stats['total_logs'] * 100) if stats['total_logs'] > 0 else 0
                        event_data.append([evt['event_type'][:25], str(evt['count']), 
                                        str(evt['critical_count']), f"{pct:.1f}%"])
                    
                    event_table = Table(event_data, colWidths=[1.8*inch, 1.2*inch, 1.3*inch, 1*inch])
                    event_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#27ae60')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#d5f4e6')),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('ALIGN', (1, 1), (-1, -1), 'CENTER'),
                        ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ]))
                    elements.append(event_table)
                else:
                    elements.append(Paragraph('No event type data available.', styles['Normal']))
                
                elements.append(PageBreak())
                
                # ===== PAGE 3: USER ACTIVITY & HOURLY ANALYSIS =====
                elements.append(Paragraph('USER ACTIVITY ANALYSIS', heading2_style))
                if detailed['user_activity']:
                    user_data = [['User', 'Total Events', 'Threat Events', 'Risk Status']]
                    for user in detailed['user_activity'][:12]:
                        risk = 'SUSPICIOUS' if user['threat_count'] > 0 else 'NORMAL'
                        user_data.append([user['user'][:20], str(user['count']), 
                                       str(user['threat_count']), risk])
                    
                    user_table = Table(user_data, colWidths=[1.8*inch, 1.4*inch, 1.4*inch, 1.4*inch])
                    user_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#8e44ad')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ebdef0')),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('ALIGN', (1, 1), (-1, -1), 'CENTER'),
                        ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ]))
                    elements.append(user_table)
                else:
                    elements.append(Paragraph('No user activity data available.', styles['Normal']))
                
                elements.append(Spacer(1, 0.2*inch))
                
                # ===== HOURLY ACTIVITY PATTERN =====
                elements.append(Paragraph('HOURLY ACTIVITY PATTERN', heading2_style))
                if detailed['hourly_analysis']:
                    hourly_data = [['Hour (UTC)', 'Total Events', 'Critical Events', 'Activity Level']]
                    for hour_data in detailed['hourly_analysis']:
                        hour = hour_data['hour']
                        count = hour_data['count']
                        critical = hour_data['critical_count']
                        avg_hourly = stats['total_logs'] / 24 if stats['total_logs'] > 0 else 1
                        activity = 'HIGH' if count > avg_hourly * 1.5 else ('LOW' if count < avg_hourly * 0.5 else 'NORMAL')
                        hourly_data.append([f"{hour}:00", str(count), str(critical), activity])
                    
                    hourly_table = Table(hourly_data, colWidths=[1.2*inch, 1.4*inch, 1.4*inch, 1.5*inch])
                    hourly_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2980b9')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#d6eaf8')),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('ALIGN', (1, 1), (-1, -1), 'CENTER'),
                        ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ]))
                    elements.append(hourly_table)
                
                elements.append(Spacer(1, 0.2*inch))
                
                # ===== RECOMMENDATIONS =====
                elements.append(PageBreak())
                elements.append(Paragraph('SECURITY RECOMMENDATIONS & RUNBOOK ACTIONS', heading2_style))
                
                best_recommendations = self._get_best_recommendations(stats, detailed)
                for rec in best_recommendations:
                    elements.append(Paragraph(rec, styles['Normal']))
                    elements.append(Spacer(1, 0.12*inch))
                
                elements.append(Spacer(1, 0.3*inch))
                
                # ===== RECENT CRITICAL THREATS =====
                elements.append(Paragraph('TOP CRITICAL INCIDENTS', heading2_style))
                
                threat_data = [['Time', 'Source', 'Severity', 'Pattern', 'Description']]
                for threat in stats['recent_threats'][:15]:
                    threat_data.append([
                        threat[0][:16],
                        threat[1][:18],
                        threat[2],
                        threat[4][:12] if threat[4] else 'N/A',
                        threat[3][:35] + ('...' if len(threat[3]) > 35 else '')
                    ])
                
                threat_table = Table(threat_data, colWidths=[1*inch, 1.2*inch, 0.9*inch, 1*inch, 1.9*inch])
                threat_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#7d3c0a')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f4ecf7')),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('FONTSIZE', (0, 1), (-1, -1), 7),
                ]))
                elements.append(threat_table)
                
                # ===== FOOTER =====
                elements.append(Spacer(1, 0.3*inch))
                footer_text = f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Confidential - For Authorized Use Only"
                elements.append(Paragraph(footer_text, ParagraphStyle('Footer', parent=styles['Normal'], 
                                                                     fontSize=8, textColor=colors.grey, alignment=2)))
                
                # Build PDF
                doc.build(elements)
                pdf_buffer.seek(0)
                return pdf_buffer.getvalue()
            except Exception as e:
                print(f"Error generating PDF report: {e}")
                return f"Error generating PDF: {str(e)}"
        
        else:  # HTML DETAILED report
            total_critical = stats['severity_dist'].get('CRITICAL', 0)
            total_high = stats['severity_dist'].get('HIGH', 0)
            
            html_content = f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Comprehensive Log Analysis Report</title>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                    body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; color: #333; }}
                    .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
                    .header {{ background: linear-gradient(135deg, #2c3e50, #34495e); color: white; padding: 40px 30px; border-radius: 8px; margin-bottom: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                    .header h1 {{ font-size: 32px; margin-bottom: 10px; }}
                    .header p {{ font-size: 14px; opacity: 0.9; }}
                    
                    .executive-summary {{ background: white; padding: 25px; border-radius: 8px; margin-bottom: 30px; border-left: 5px solid #3498db; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                    .executive-summary h2 {{ color: #2c3e50; margin-bottom: 15px; font-size: 20px; }}
                    .summary-text {{ line-height: 1.6; color: #555; }}
                    .threat-level {{ display: inline-block; padding: 5px 15px; border-radius: 20px; font-weight: bold; margin: 10px 0; }}
                    .threat-level.critical {{ background: #e74c3c; color: white; }}
                    .threat-level.high {{ background: #e67e22; color: white; }}
                    .threat-level.medium {{ background: #f39c12; color: white; }}
                    .threat-level.low {{ background: #27ae60; color: white; }}
                    
                    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
                    .stat-card {{ background: white; padding: 25px; border-radius: 8px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-top: 4px solid #3498db; }}
                    .stat-card h3 {{ color: #7f8c8d; font-size: 14px; margin-bottom: 15px; text-transform: uppercase; letter-spacing: 1px; }}
                    .stat-card .value {{ font-size: 36px; font-weight: bold; color: #2c3e50; margin-bottom: 5px; }}
                    .stat-card .subtext {{ font-size: 12px; color: #95a5a6; }}
                    
                    .stat-card.critical {{ border-top-color: #e74c3c; }}
                    .stat-card.critical .value {{ color: #e74c3c; }}
                    .stat-card.high {{ border-top-color: #e67e22; }}
                    .stat-card.high .value {{ color: #e67e22; }}
                    
                    section {{ background: white; padding: 30px; border-radius: 8px; margin-bottom: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                    section h2 {{ color: #2c3e50; font-size: 22px; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #3498db; }}
                    section h3 {{ color: #34495e; font-size: 16px; margin-top: 20px; margin-bottom: 15px; }}
                    
                    table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
                    table thead th {{ background: #34495e; color: white; padding: 12px; text-align: left; font-weight: 600; font-size: 13px; }}
                    table tbody tr {{ border-bottom: 1px solid #ecf0f1; }}
                    table tbody tr:hover {{ background: #f8f9fa; }}
                    table tbody td {{ padding: 12px; font-size: 13px; }}
                    table tbody tr:nth-child(even) {{ background: #f9fafb; }}
                    
                    .severity-critical {{ color: #e74c3c; font-weight: bold; }}
                    .severity-high {{ color: #e67e22; font-weight: bold; }}
                    .severity-medium {{ color: #f39c12; }}
                    .severity-low {{ color: #27ae60; }}
                    
                    .risk-critical {{ background: #fadbd8; padding: 8px 12px; border-radius: 4px; color: #a93226; font-weight: 600; }}
                    .risk-high {{ background: #fdebd0; padding: 8px 12px; border-radius: 4px; color: #ba4a00; font-weight: 600; }}
                    .risk-medium {{ background: #fef5e7; padding: 8px 12px; border-radius: 4px; color: #7d6608; }}
                    .risk-normal {{ background: #d5f4e6; padding: 8px 12px; border-radius: 4px; color: #0b5345; font-weight: 600; }}
                    .risk-suspicious {{ background: #fadbd8; padding: 8px 12px; border-radius: 4px; color: #a93226; font-weight: 600; }}
                    
                    .recommendations {{ background: #f0f3f4; padding: 20px; border-left: 4px solid #e74c3c; margin: 20px 0; border-radius: 4px; }}
                    .recommendations ol {{ margin-left: 20px; }}
                    .recommendations li {{ margin: 10px 0; line-height: 1.6; }}
                    
                    .footer {{ text-align: center; padding: 20px; color: #7f8c8d; font-size: 12px; border-top: 1px solid #ecf0f1; margin-top: 30px; }}
                    
                    @media print {{
                        body {{ background: white; }}
                        section {{ page-break-inside: avoid; }}
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <!-- HEADER -->
                    <div class="header">
                        <h1>🔐 COMPREHENSIVE LOG ANALYSIS REPORT</h1>
                        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Report Version 2.0</p>
                    </div>
                    
                    <!-- EXECUTIVE SUMMARY -->
                    <div class="executive-summary">
                        <h2>Executive Summary</h2>
                        <div class="summary-text">
                            <p>This comprehensive report analyzes <strong>{stats['total_logs']:,}</strong> log entries with <strong>{stats['ttp_matches']:,}</strong> identified threats using MITRE ATT&CK framework mappings.</p>
                            <p><strong>Overall Security Posture:</strong> 
                            <span class="threat-level {'critical' if total_critical > 0 else 'high' if total_high > 0 else 'low'}">
                                {'🔴 CRITICAL' if total_critical > 0 else '🟠 HIGH' if total_high > 0 else '🟢 LOW RISK'}
                            </span></p>
                            <p><strong>Key Metrics:</strong> {total_critical:,} critical events | {total_high:,} high events | {len(detailed['source_analysis'])} suspicious source IPs | {len(detailed['ttp_analysis'])} threat patterns detected</p>
                        </div>
                    </div>
                    
                    <!-- STATISTICS DASHBOARD -->
                    <div class="stats-grid">
                        <div class="stat-card">
                            <h3>Total Logs</h3>
                            <div class="value">{stats['total_logs']:,}</div>
                            <div class="subtext">All processed entries</div>
                        </div>
                        <div class="stat-card">
                            <h3>TTP Matches</h3>
                            <div class="value">{stats['ttp_matches']:,}</div>
                            <div class="subtext">Threat patterns detected</div>
                        </div>
                        <div class="stat-card critical">
                            <h3>Critical Events</h3>
                            <div class="value">{total_critical:,}</div>
                            <div class="subtext">Highest severity</div>
                        </div>
                        <div class="stat-card high">
                            <h3>High Events</h3>
                            <div class="value">{total_high:,}</div>
                            <div class="subtext">High severity</div>
                        </div>
                        <div class="stat-card">
                            <h3>Unique Sources</h3>
                            <div class="value">{len(detailed['source_analysis'])}</div>
                            <div class="subtext">Distinct source IPs</div>
                        </div>
                        <div class="stat-card">
                            <h3>Event Types</h3>
                            <div class="value">{len(detailed['event_analysis'])}</div>
                            <div class="subtext">Different categories</div>
                        </div>
                    </div>
                    
                    <!-- SEVERITY ANALYSIS -->
                    <section>
                        <h2>📊 Severity Distribution Analysis</h2>
                        <table>
                            <thead>
                                <tr>
                                    <th>Severity Level</th>
                                    <th>Count</th>
                                    <th>Percentage</th>
                                    <th>Risk Assessment</th>
                                </tr>
                            </thead>
                            <tbody>
            '''
            
            risk_map = {'CRITICAL': ('IMMEDIATE ACTION REQUIRED', '#e74c3c'), 
                       'HIGH': ('URGENT REVIEW', '#e67e22'),
                       'MEDIUM': ('ATTENTION NEEDED', '#f39c12'),
                       'LOW': ('MONITOR', '#27ae60')}
            
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = stats['severity_dist'].get(severity, 0)
                percentage = (count / stats['total_logs'] * 100) if stats['total_logs'] > 0 else 0
                risk_text, risk_color = risk_map[severity]
                html_content += f'''
                                <tr>
                                    <td class="severity-{severity.lower()}">{severity}</td>
                                    <td><strong>{count:,}</strong></td>
                                    <td>{percentage:.2f}%</td>
                                    <td><div class="risk-{severity.lower()}">{risk_text}</div></td>
                                </tr>
                '''
            
            html_content += '''
                            </tbody>
                        </table>
                    </section>
                    
                    <!-- THREAT PATTERN ANALYSIS -->
                    <section>
                        <h2>🎯 Threat Pattern Analysis (MITRE ATT&CK)</h2>
            '''
            
            if detailed['ttp_analysis']:
                html_content += '''
                        <table>
                            <thead>
                                <tr>
                                    <th>TTP ID</th>
                                    <th>Pattern Name</th>
                                    <th>Occurrences</th>
                                    <th>Severity Levels</th>
                                    <th>Top Source IPs</th>
                                </tr>
                            </thead>
                            <tbody>
                '''
                for ttp_id, analysis in list(detailed['ttp_analysis'].items())[:15]:
                    ttp_name = ttp_id.split('-')[-1] if '-' in ttp_id else ttp_id
                    sources = ', '.join(analysis['source_ips'][:2]) if analysis['source_ips'] else 'N/A'
                    severities = ', '.join(sorted(set(analysis['severities']))) if analysis['severities'] else 'N/A'
                    html_content += f'''
                                <tr>
                                    <td><strong>{ttp_id}</strong></td>
                                    <td>{ttp_name}</td>
                                    <td><strong>{analysis['count']:,}</strong></td>
                                    <td>{severities}</td>
                                    <td>{sources[:40]}</td>
                                </tr>
                    '''
                html_content += '''
                            </tbody>
                        </table>
                '''
            else:
                html_content += '<p><em>No threat patterns detected.</em></p>'
            
                html_content += '''
                    </section>
                    
                    <!-- SOURCE IP ANALYSIS -->
                    <section>
                        <h2>🌐 Source IP Threat Analysis (Top 15)</h2>
            '''
            
            if detailed['source_analysis']:
                html_content += '''
                        <table>
                            <thead>
                                <tr>
                                    <th>Source IP</th>
                                    <th>Total Events</th>
                                    <th>Critical</th>
                                    <th>High</th>
                                    <th>Risk Level</th>
                                </tr>
                            </thead>
                            <tbody>
                '''
                for src in detailed['source_analysis'][:15]:
                    risk = 'CRITICAL' if src['critical_count'] > 0 else ('HIGH' if src['high_count'] > 0 else 'MEDIUM')
                    html_content += f'''
                                <tr>
                                    <td><strong>{src['source_ip']}</strong></td>
                                    <td>{src['count']:,}</td>
                                    <td class="severity-critical">{src['critical_count']}</td>
                                    <td class="severity-high">{src['high_count']}</td>
                                    <td><div class="risk-{risk.lower()}">{risk}</div></td>
                                </tr>
                    '''
                html_content += '''
                            </tbody>
                        </table>
                '''
            else:
                html_content += '<p><em>No source IP data available.</em></p>'
            
            html_content += '''
                    </section>
                    
                    <!-- EVENT TYPE DISTRIBUTION -->
                    <section>
                        <h2>📋 Event Type Distribution (Top 20)</h2>
            '''
            
            if detailed['event_analysis']:
                html_content += '''
                        <table>
                            <thead>
                                <tr>
                                    <th>Event Type</th>
                                    <th>Frequency</th>
                                    <th>Critical Count</th>
                                    <th>Percentage</th>
                                </tr>
                            </thead>
                            <tbody>
                '''
                for evt in detailed['event_analysis'][:20]:
                    pct = (evt['count'] / stats['total_logs'] * 100) if stats['total_logs'] > 0 else 0
                    html_content += f'''
                                <tr>
                                    <td>{evt['event_type']}</td>
                                    <td><strong>{evt['count']:,}</strong></td>
                                    <td class="severity-critical">{evt['critical_count']}</td>
                                    <td>{pct:.2f}%</td>
                                </tr>
                    '''
                html_content += '''
                            </tbody>
                        </table>
                '''
            else:
                html_content += '<p><em>No event type data available.</em></p>'
            
            html_content += '''
                    </section>
                    
                    <!-- USER ACTIVITY ANALYSIS -->
                    <section>
                        <h2>👤 User Activity Analysis (Top 20)</h2>
            '''
            
            if detailed['user_activity']:
                html_content += '''
                        <table>
                            <thead>
                                <tr>
                                    <th>User</th>
                                    <th>Total Events</th>
                                    <th>Threat Events</th>
                                    <th>Risk Status</th>
                                </tr>
                            </thead>
                            <tbody>
                '''
                for user in detailed['user_activity'][:20]:
                    risk = 'SUSPICIOUS' if user['threat_count'] > 0 else 'NORMAL'
                    html_content += f'''
                                <tr>
                                    <td>{user['user']}</td>
                                    <td>{user['count']:,}</td>
                                    <td><strong>{user['threat_count']}</strong></td>
                                    <td><div class="risk-{risk.lower()}">{risk}</div></td>
                                </tr>
                    '''
                html_content += '''
                            </tbody>
                        </table>
                '''
            else:
                html_content += '<p><em>No user activity data available.</em></p>'
            
            html_content += '''
                    </section>
                    
                    <!-- HOURLY DISTRIBUTION -->
                    <section>
                        <h2>⏰ Hourly Activity Pattern Analysis</h2>
            '''
            
            if detailed['hourly_analysis']:
                html_content += '''
                        <table>
                            <thead>
                                <tr>
                                    <th>Hour (UTC)</th>
                                    <th>Total Events</th>
                                    <th>Critical Events</th>
                                    <th>Activity Level</th>
                                </tr>
                            </thead>
                            <tbody>
                '''
                for hour_data in detailed['hourly_analysis']:
                    hour = hour_data['hour']
                    count = hour_data['count']
                    critical = hour_data['critical_count']
                    avg_hourly = stats['total_logs'] / 24 if stats['total_logs'] > 0 else 1
                    activity = 'HIGH' if count > avg_hourly * 1.5 else ('LOW' if count < avg_hourly * 0.5 else 'NORMAL')
                    html_content += f'''
                                <tr>
                                    <td><strong>{hour}:00</strong></td>
                                    <td>{count:,}</td>
                                    <td class="severity-critical">{critical}</td>
                                    <td>{activity}</td>
                                </tr>
                    '''
                html_content += '''
                            </tbody>
                        </table>
                '''
            
            html_content += '''
                    </section>
                    
                    <!-- SECURITY RECOMMENDATIONS -->
                    <section>
                        <h2>⚠️ Security Recommendations & Runbook Actions</h2>
                        <div class="recommendations">
                            <ol>
            '''
            
            # Get best recommendations
            best_recommendations = self._get_best_recommendations(stats, detailed)
            for i, rec in enumerate(best_recommendations, 1):
                # Remove HTML tags for display purposes and escape
                rec_text = html.escape(str(rec).replace('<b>', '').replace('</b>', '').replace('<strong>', '').replace('</strong>', ''))
                # Re-add some formatting
                if 'PRIORITY' in rec_text or 'RUNBOOK' in rec_text:
                    html_content += f"<li><strong style='color: #2c3e50;'>{rec_text}</strong></li>"
                else:
                    html_content += f"<li>{rec_text}</li>"
            
            html_content += '''
                    
                    <!-- TOP INCIDENTS -->
                    <section>
                        <h2>🚨 Top Critical Incidents (Most Recent)</h2>
                        <table>
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>Source IP</th>
                                    <th>Severity</th>
                                    <th>Pattern</th>
                                    <th>Description</th>
                                </tr>
                            </thead>
                            <tbody>
            '''
            
            for threat in stats['recent_threats'][:30]:
                severity_class = f"severity-{threat[2].lower()}"
                ttp = threat[4][:15] if threat[4] else '-'
                html_content += f'''
                                <tr>
                                    <td>{threat[0]}</td>
                                    <td><strong>{threat[1]}</strong></td>
                                    <td><span class="{severity_class}">{threat[2]}</span></td>
                                    <td>{ttp}</td>
                                    <td>{threat[3][:80]}{'...' if len(threat[3]) > 80 else ''}</td>
                                </tr>
                '''
            
            html_content += '''
                            </tbody>
                        </table>
                    </section>
                    
                    <!-- FOOTER -->
                    <div class="footer">
                        <p>Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | <strong>CONFIDENTIAL</strong> - For Authorized Use Only</p>
                        <p>This report contains sensitive security information. Distribute only to authorized personnel. Retention policy: 90 days.</p>
                    </div>
                </div>
            </body>
            </html>
            '''
            
            return html_content
    
    def detect_behavioral_anomalies(self) -> Dict:
        """Detect behavioral anomalies in log data."""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Detect spike in events
                cursor.execute('''
                    SELECT strftime('%H', timestamp) as hour,
                           COUNT(*) as count
                    FROM log_entries
                    WHERE timestamp > datetime('now', '-24 hours')
                    GROUP BY hour
                    ORDER BY hour DESC
                ''')
                hourly_counts = [dict(row) for row in cursor.fetchall()]
                
                if hourly_counts:
                    avg_count = sum(h['count'] for h in hourly_counts) / len(hourly_counts)
                    spikes = [h for h in hourly_counts if h['count'] > avg_count * 2]
                else:
                    spikes = []
                
                # Detect unusual source activity
                cursor.execute('''
                    SELECT source_ip, COUNT(*) as count,
                           MIN(timestamp) as first_seen,
                           MAX(timestamp) as last_seen
                    FROM log_entries
                    WHERE source_ip IS NOT NULL
                    GROUP BY source_ip
                    HAVING count > 100
                    ORDER BY count DESC
                    LIMIT 20
                ''')
                unusual_sources = [dict(row) for row in cursor.fetchall()]
                
                return {
                    'event_spikes': spikes,
                    'unusual_sources': unusual_sources,
                    'average_hourly_events': avg_count if hourly_counts else 0
                }
        except Exception as e:
            print(f"Error detecting behavioral anomalies: {e}")
            return {}
    
    def detect_privilege_escalation(self) -> List[Dict]:
        """Detect potential privilege escalation attempts."""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Look for patterns indicative of privilege escalation
                escalation_patterns = [
                    'sudo', 'runas', 'privilege', 'escalat', 'admin', 'root', 'setuid'
                ]
                
                query_parts = []
                for pattern in escalation_patterns:
                    query_parts.append(f"LOWER(message) LIKE '%{pattern}%'")
                
                query = '''
                    SELECT timestamp, source_name, user, message, severity, ttp_match
                    FROM log_entries
                    WHERE (''' + ' OR '.join(query_parts) + ''')
                    AND severity IN ('CRITICAL', 'HIGH')
                    ORDER BY timestamp DESC
                    LIMIT 50
                '''
                
                cursor.execute(query)
                escalations = [dict(row) for row in cursor.fetchall()]
                return escalations
        except Exception as e:
            print(f"Error detecting privilege escalation: {e}")
            return []
    
    def detect_lateral_movement(self) -> List[Dict]:
        """Detect potential lateral movement patterns."""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Detect multiple connection attempts from single source to multiple destinations
                cursor.execute('''
                    SELECT source_ip, COUNT(DISTINCT source_name) as target_count,
                           GROUP_CONCAT(DISTINCT source_name) as targets,
                           COUNT(*) as total_events
                    FROM log_entries
                    WHERE source_ip IS NOT NULL
                    GROUP BY source_ip
                    HAVING target_count > 3 AND total_events > 20
                    ORDER BY total_events DESC
                    LIMIT 15
                ''')
                
                lateral_movements = [dict(row) for row in cursor.fetchall()]
                return lateral_movements
        except Exception as e:
            print(f"Error detecting lateral movement: {e}")
            return []
    
    def detect_data_exfiltration(self) -> List[Dict]:
        """Detect potential data exfiltration patterns."""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Look for exfiltration indicators
                exfil_patterns = [
                    'upload', 'download', 'transfer', 'send', 'compress', 'zip', 'archive',
                    'encrypt', 'exfil', 'ftp', 'scp', 'sftp'
                ]
                
                query_parts = []
                for pattern in exfil_patterns:
                    query_parts.append(f"LOWER(message) LIKE '%{pattern}%'")
                
                query = '''
                    SELECT timestamp, source_ip, user, message, source_name
                    FROM log_entries
                    WHERE (''' + ' OR '.join(query_parts) + ''')
                    AND severity IN ('CRITICAL', 'HIGH')
                    ORDER BY timestamp DESC
                    LIMIT 50
                '''
                
                cursor.execute(query)
                exfiltrations = [dict(row) for row in cursor.fetchall()]
                return exfiltrations
        except Exception as e:
            print(f"Error detecting data exfiltration: {e}")
            return []
    
    def get_threat_timeline(self, days: int = 7) -> List[Dict]:
        """Get threat events timeline for visualization."""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT strftime('%Y-%m-%d %H:00', timestamp) as time_bucket,
                           severity,
                           COUNT(*) as count,
                           GROUP_CONCAT(DISTINCT ttp_match) as patterns
                    FROM log_entries
                    WHERE timestamp > datetime('now', ? || ' days')
                    AND severity IN ('CRITICAL', 'HIGH')
                    GROUP BY time_bucket, severity
                    ORDER BY time_bucket DESC
                ''', (f'-{days}',))
                
                timeline = [dict(row) for row in cursor.fetchall()]
                return timeline
        except Exception as e:
            print(f"Error generating threat timeline: {e}")
            return []
    
    def generate_threat_pdf_report(self):
        """Generate a comprehensive PDF threat report."""
        if not HAS_REPORTLAB:
            return "PDF generation not available. Install reportlab: pip install reportlab"
        
        try:
            pdf_buffer = io.BytesIO()
            doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
            elements = []
            styles = getSampleStyleSheet()
            
            # Title
            elements.append(Paragraph('THREAT ANALYSIS REPORT', styles['Title']))
            elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            elements.append(Spacer(1, 0.5*inch))
            
            # Get threat data
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Executive Summary
                cursor.execute('''
                    SELECT 
                        COUNT(*) as total_threats,
                        SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical,
                        SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) as high,
                        COUNT(DISTINCT source_ip) as unique_sources,
                        COUNT(DISTINCT ttp_match) as unique_ttps
                    FROM log_entries
                    WHERE severity IN ('CRITICAL', 'HIGH', 'MEDIUM')
                    AND timestamp > datetime('now', '-30 days')
                ''')
                
                row = cursor.fetchone()
                summary = {
                    'total_threats': row[0] or 0,
                    'critical': row[1] or 0,
                    'high': row[2] or 0,
                    'unique_sources': row[3] or 0,
                    'unique_ttps': row[4] or 0
                }
                
                # Add summary section
                elements.append(Paragraph('EXECUTIVE SUMMARY', styles['Heading2']))
                summary_text = f"""
                Total Threats: {summary['total_threats'] or 0}<br/>
                Critical Events: {summary['critical'] or 0}<br/>
                High Events: {summary['high'] or 0}<br/>
                Unique Sources: {summary['unique_sources'] or 0}<br/>
                MITRE TTPs: {summary['unique_ttps'] or 0}
                """
                elements.append(Paragraph(summary_text, styles['Normal']))
                elements.append(Spacer(1, 0.2*inch))
                
                # Top Threats
                cursor.execute('''
                    SELECT source_ip, COUNT(*) as count,
                           MAX(severity) as max_severity,
                           GROUP_CONCAT(DISTINCT ttp_match) as ttps
                    FROM log_entries
                    WHERE severity IN ('CRITICAL', 'HIGH')
                    AND source_ip IS NOT NULL
                    GROUP BY source_ip
                    ORDER BY count DESC
                    LIMIT 10
                ''')
                
                top_threats = cursor.fetchall()
                
                elements.append(Paragraph('TOP THREAT SOURCES', styles['Heading2']))
                threat_data = [['Source IP', 'Event Count', 'Max Severity', 'TTPs']]
                for threat in top_threats:
                    ttps_str = threat[3][:50] + '...' if threat[3] and len(threat[3]) > 50 else threat[3] or ''
                    threat_data.append([
                        threat[0],
                        str(threat[1]),
                        threat[2],
                        ttps_str
                    ])
                
                threat_table = Table(threat_data)
                threat_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                ]))
                elements.append(threat_table)
            
            # Build PDF
            doc.build(elements)
            pdf_buffer.seek(0)
            
            # Return as Flask response
            response = make_response(pdf_buffer.getvalue())
            response.headers['Content-Disposition'] = f'attachment; filename=threat_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
            response.headers['Content-Type'] = 'application/pdf'
            return response
            
        except Exception as e:
            print(f"Error generating threat PDF: {e}")
            return jsonify({'error': f'PDF generation failed: {str(e)}'}), 500

# ============================================================================
# FILE WATCHER
# ============================================================================

class LogFileHandler(FileSystemEventHandler):
    """File system event handler for real-time log collection."""
    
    def __init__(self, log_manager: LogManager, watch_dir: str, refresh_on_watch: bool = False):
        self.log_manager = log_manager
        self.watch_dir = watch_dir
        self.refresh_on_watch = refresh_on_watch
        self.file_positions: Dict[str, float] = {}
    
    def on_modified(self, event):
        path = str(event.src_path)
        if not event.is_directory and self._is_log_file(path):
            self._process_file(path)
    
    def on_created(self, event):
        path = str(event.src_path)
        if not event.is_directory and self._is_log_file(path):
            self._process_file(path)
    
    def _is_log_file(self, file_path: str) -> bool:
        return any(file_path.endswith(ext) for ext in ['.log', '.txt', '.json', '.csv'])
    
    def _process_file(self, file_path: str):
        """Process a log file that has been modified/created."""
        try:
            filename = os.path.basename(file_path)
            source_name = f"watched_{filename}"
            
            # Check if we've already processed this file
            last_modified = os.path.getmtime(file_path)
            if file_path in self.file_positions and self.file_positions[file_path] >= last_modified:
                return
            
            # Process the file
            result = self.log_manager.process_log_file(file_path, source_name, refresh=self.refresh_on_watch)
            self.file_positions[file_path] = float(last_modified)
            
            print(f"[Watcher] Processed {filename}: {result['count']} entries, {result['critical_count']} critical")
                
        except Exception as e:
            print(f"[Watcher] Error processing {file_path}: {e}")

# ============================================================================
# FLASK APPLICATION
# ============================================================================

class LogAnalyzerApp:
    """Main application class."""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.app.secret_key = 'log-analyzer-secret-key-2024'
        self.app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB
        self.app.jinja_env.filters['safetruncate'] = self._safe_truncate
        
        # Ensure pages always reflect latest data (disable browser caching)
        @self.app.after_request
        def add_no_cache_headers(response):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            return response
        
        # Create upload directory
        self.upload_dir = 'uploads'
        os.makedirs(self.upload_dir, exist_ok=True)

        # Initialize database first so settings can be read
        self.db = Database()

        # Load external playbooks/runbooks if present
        self._load_external_playbooks()
        
        # Check for manifest.json in deployed package
        manifest = self._load_manifest_if_exists()
        
        # Determine which playbook set should be active and limit rules accordingly
        self.active_playbook_type = self._load_active_playbook_type()
        self.active_playbook_types = [self.active_playbook_type]  # Default to single type
        
        # Priority: manifest > env vars > database settings
        if manifest and 'selected_types' in manifest:
            # Package was deployed with specific playbook types
            self.active_playbook_types = manifest['selected_types']
            self.active_playbook_type = self.active_playbook_types[0]
            print(f"[System] Using manifest types: {self.active_playbook_types}")
        else:
            # Check for environment overrides (support both single and multiple types)
            env_override = os.getenv('ACTIVE_PLAYBOOK_TYPES') or os.getenv('ACTIVE_PLAYBOOK_TYPE')
            print(f"[System] Environment override: {env_override}")
            if env_override:
                if ',' in env_override:
                    # Multiple types: ACTIVE_PLAYBOOK_TYPES=windows,linux
                    types = [t.strip().lower() for t in env_override.split(',') if t.strip()]
                    valid_types = [t for t in types if t == 'all' or t in self.playbooks_by_type]
                    if valid_types:
                        self.active_playbook_types = valid_types
                        self.active_playbook_type = valid_types[0]  # Primary type for compatibility
                        print(f"[System] Using env types (multiple): {self.active_playbook_types}")
                else:
                    # Single type: ACTIVE_PLAYBOOK_TYPE=windows
                    env_choice = env_override.strip().lower()
                    if env_choice == 'all' or env_choice in self.playbooks_by_type:
                        self.active_playbook_type = env_choice
                        self.active_playbook_types = [env_choice]
                        print(f"[System] Using env type (single): {env_choice}")
        
        # Get rules for all active playbook types
        active_rules = []
        for pb_type in self.active_playbook_types:
            active_rules.extend(self._get_rules_for_type(pb_type))
        
        print(f"[System] Active playbook types: {self.active_playbook_types}")
        print(f"[System] Active rules loaded: {len(active_rules)}")

        # Initialize components
        self.log_manager = LogManager(self.db, active_rules)
        self.file_watcher = None
        
        # Setup routes
        self._setup_routes()
        
        # Start file watcher
        self._start_file_watcher()

    def _load_external_playbooks(self) -> None:
        """Load playbooks/runbooks from uploads or workspace root if JSON files exist."""
        global PLAYBOOKS, RUNBOOKS
        
        # Initialize storage for all playbook rules
        self.all_playbook_rules = []
        self.playbooks_by_type = {}
        
        try:
            workspace_root = os.path.abspath('.')
            
            # Load all specialized playbook files
            playbook_types = ['windows', 'linux', 'mac', 'osfc', 'fortinet', 'syslog', 
                             'apache', 'nginx', 'iis', 'dns', 'proxy']
            
            for ptype in playbook_types:
                playbook_file = os.path.join(workspace_root, f'playbooks_{ptype}.json')
                if os.path.exists(playbook_file):
                    try:
                        with open(playbook_file, 'r', encoding='utf-8') as f:
                            playbook_data = json.load(f)
                            if 'rules' in playbook_data:
                                rules = playbook_data['rules']
                                self.playbooks_by_type[ptype] = {
                                    'name': playbook_data.get('name', f'{ptype.upper()} Playbook'),
                                    'description': playbook_data.get('description', ''),
                                    'log_type': playbook_data.get('log_type', ptype),
                                    'rule_count': len(rules),
                                    'rules': rules
                                }
                                self.all_playbook_rules.extend(rules)
                                print(f"[System] Loaded {len(rules)} rules from {ptype} playbook")
                    except Exception as e:
                        print(f"[System] Failed to load {ptype} playbook: {e}")
            
            print(f"[System] Total playbook rules loaded: {len(self.all_playbook_rules)} from {len(self.playbooks_by_type)} playbooks")
            
            # Load legacy playbooks.json
            pb_candidates = [
                os.path.join(self.upload_dir, 'playbooks.json'),
                os.path.join(workspace_root, 'playbooks.json'),
            ]
            rb_candidates = [
                os.path.join(self.upload_dir, 'runbooks.json'),
                os.path.join(workspace_root, 'runbooks.json'),
            ]
            pb_path = next((p for p in pb_candidates if os.path.exists(p)), None)
            rb_path = next((p for p in rb_candidates if os.path.exists(p)), None)
            if pb_path:
                with open(pb_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, dict) and 'playbooks' in data:
                        PLAYBOOKS = data['playbooks']
                    elif isinstance(data, list):
                        PLAYBOOKS = data
            if rb_path:
                with open(rb_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, dict) and 'runbooks' in data:
                        RUNBOOKS = data['runbooks']
                    elif isinstance(data, dict):
                        RUNBOOKS = data
        except Exception as e:
            print(f"[System] Failed to load external playbooks: {e}")

    def _load_manifest_if_exists(self) -> Optional[Dict[str, Any]]:
        """Load manifest.json if this is a deployed package (for multi-playbook support)."""
        manifest_path = Path(__file__).parent / 'manifest.json'
        if manifest_path.exists():
            try:
                with open(manifest_path, 'r', encoding='utf-8') as f:
                    manifest = json.load(f)
                    print(f"[System] Manifest loaded: {manifest}")
                    return manifest
            except Exception as e:
                print(f"[System] Could not read manifest: {e}")
                return None
        return None

    def _load_active_playbook_type(self) -> str:
        """Fetch the persisted active playbook scope (defaults to 'all')."""
        active_type = 'all'
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT value FROM settings WHERE key = 'active_playbook_type'")
                row = cursor.fetchone()
                if row and row['value']:
                    active_type = str(row['value']).strip().lower()
        except Exception:
            active_type = 'all'

        # Fallback if the stored value is not available
        if active_type != 'all' and active_type not in self.playbooks_by_type:
            active_type = 'all'
        return active_type

    def _get_rules_for_type(self, playbook_type: str) -> List[Dict[str, Any]]:
        """Return rules for a specific playbook type or all rules."""
        if not playbook_type or playbook_type == 'all':
            return self.all_playbook_rules

        playbook_type = playbook_type.lower()
        if playbook_type not in self.playbooks_by_type:
            return self.all_playbook_rules

        playbook = self.playbooks_by_type.get(playbook_type, {})
        return playbook.get('rules', [])

    def _apply_playbook_selection(self, playbook_type: str) -> Dict[str, Any]:
        """Persist and activate the chosen playbook scope for real-time monitoring."""
        selected_type = (playbook_type or 'all').lower()
        if selected_type != 'all' and selected_type not in self.playbooks_by_type:
            raise ValueError(f"Unknown playbook type: {selected_type}")

        rules = self._get_rules_for_type(selected_type)
        self.log_manager.update_playbook_rules(rules)
        self.active_playbook_type = selected_type

        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO settings (key, value)
                VALUES (?, ?)
            """, ('active_playbook_type', selected_type))
            conn.commit()

        return {
            'active_playbook_type': selected_type,
            'rule_count': len(rules)
        }

    def _collect_logs_for_playbook(self, playbook_type: str, limit: int = 5000) -> List[Dict[str, Any]]:
        """Return recent logs filtered for a playbook type (substring match), capped for package size."""
        query = "SELECT * FROM log_entries"
        params: List[Any] = []

        if playbook_type and playbook_type != 'all':
            pattern = f"%{playbook_type.lower()}%"
            query += " WHERE LOWER(source_name) LIKE ? OR LOWER(event_type) LIKE ?"
            params.extend([pattern, pattern])

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    @staticmethod
    def _summarize_logs(logs: List[Dict[str, Any]], playbook_type: str) -> Dict[str, Any]:
        """Create a compact summary for packaged reports."""
        severity_counts: Dict[str, int] = defaultdict(int)
        for log in logs:
            sev = str(log.get('severity', 'INFO')).upper()
            severity_counts[sev] += 1

        return {
            'playbook_type': playbook_type,
            'generated_at': datetime.now().isoformat(),
            'total_logs': len(logs),
            'severity': dict(severity_counts)
        }

    def _build_playbook_package(self, playbook_type: str, playbook_payload: Dict[str, Any],
                                 logs: List[Dict[str, Any]], summary: Dict[str, Any],
                                 selected_types: Optional[List[str]] = None) -> io.BytesIO:
        """Assemble a plug-and-play ZIP with playbook rules, logs, and a summary."""
        buffer = io.BytesIO()
        if selected_types is None:
            selected_types = [playbook_type] if playbook_type != 'all' else list(self.playbooks_by_type.keys())
        
        manifest = {
            'playbook_type': playbook_type,
            'selected_types': selected_types,
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'rule_count': len(playbook_payload.get('rules', [])) if playbook_payload else 0,
            'log_count': len(logs)
        }

        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Manifest and metadata
            zf.writestr('manifest.json', json.dumps(manifest, indent=2))
            zf.writestr('report_summary.json', json.dumps(summary, indent=2))

            # Playbook content
            if playbook_payload:
                pb_filename = f"playbooks_{playbook_type}.json" if playbook_type != 'all' else 'playbooks_all.json'
                zf.writestr(pb_filename, json.dumps(playbook_payload, indent=2))

            # Logs CSV export
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['ID', 'Timestamp', 'Source', 'Severity', 'Message', 'Source IP', 'Destination IP', 'User', 'Event Type', 'TTP Match'])
            for log in logs:
                writer.writerow([
                    log.get('id', ''),
                    log.get('timestamp', ''),
                    log.get('source_name', ''),
                    log.get('severity', ''),
                    (log.get('message', '') or '')[:500],
                    log.get('source_ip', ''),
                    log.get('dest_ip', ''),
                    log.get('user', ''),
                    log.get('event_type', ''),
                    log.get('ttp_match', '')
                ])
            zf.writestr('logs.csv', output.getvalue())

            # Include source and portable runner for quick start / PyInstaller
            try:
                analyzer_path = Path(__file__).resolve()
                zf.writestr('Log_Analyzer.py', analyzer_path.read_text(encoding='utf-8'))
            except Exception:
                pass

            # Include GUI collector if available
            try:
                gui_path = Path(__file__).parent / 'LogCollector_GUI.py'
                if gui_path.exists():
                    zf.writestr('LogCollector_GUI.py', gui_path.read_text(encoding='utf-8'))
            except Exception:
                pass

            # Include Launcher
            try:
                launcher_path = Path(__file__).parent / 'Launcher.py'
                if launcher_path.exists():
                    zf.writestr('Launcher.py', launcher_path.read_text(encoding='utf-8'))
            except Exception:
                pass

            # Build environment variable setting for selected types
            # Always use selected_types (not playbook_type which might be concatenated)
            types_env = ','.join(sorted(selected_types)) if selected_types and selected_types != ['all'] else 'all'
            
            runner_script = (
                "#!/usr/bin/env python\n"
                "import os, subprocess, sys, time\n"
                f"os.environ['ACTIVE_PLAYBOOK_TYPES'] = '{types_env}'\n"
                "try:\n"
                "    from Launcher import main\n"
                "    main()\n"
                "except ImportError:\n"
                "    from Log_Analyzer import LogAnalyzerApp, HAS_DEPS\n"
                "    if not HAS_DEPS:\n"
                "        print('Installing dependencies on first run...')\n"
                "        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'])\n"
                "        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'flask', 'werkzeug', 'plotly', 'watchdog', 'reportlab'])\n"
                "        time.sleep(1)\n"
                "    app = LogAnalyzerApp()\n"
                "    print(f'\\nLog Analyzer running at http://localhost:5000')\n"
                f"    print(f'Active Playbooks: {types_env}')\n"
                "    try:\n"
                "        app.run(host='0.0.0.0', port=5000, debug=False)\n"
                "    except OSError:\n"
                "        app.run(host='0.0.0.0', port=5001, debug=False)\n"
                "except Exception as e:\n"
                "    print(f'Error: {e}')\n"
                "    sys.exit(1)\n"
            )
            zf.writestr('run_portable.py', runner_script)

            start_bat = (
                "@echo off\n"
                "setlocal\n"
                "if not exist venv (python -m venv venv)\n"
                "call venv\\Scripts\\activate.bat\n"
                "echo Installing dependencies...\n"
                "python -m pip install --upgrade pip --quiet 2>nul || true\n"
                "python -m pip install flask werkzeug plotly watchdog reportlab --quiet 2>nul\n"
                "echo Checking for optional Windows Event Log support...\n"
                "python -m pip install pywin32 --quiet 2>nul || true\n"
                "echo Starting Log Analyzer...\n"
                f"set ACTIVE_PLAYBOOK_TYPES={types_env}\n"
                "python run_portable.py\n"
                "pause\n"
            )
            zf.writestr('start_portable.bat', start_bat)

            # Include Linux/Mac launcher
            start_sh = (
                "#!/bin/bash\n"
                "set -e\n"
                "SCRIPT_DIR=\"$( cd \"$( dirname \"${BASH_SOURCE[0]}\" )\" && pwd )\"\n"
                "cd \"$SCRIPT_DIR\"\n"
                "if ! command -v python3 &> /dev/null; then\n"
                "    echo \"Error: Python 3 is not installed.\"\n"
                "    exit 1\n"
                "fi\n"
                "if [ ! -d \"venv\" ]; then\n"
                "    echo \"Creating Python virtual environment...\"\n"
                "    python3 -m venv venv\n"
                "fi\n"
                "source venv/bin/activate\n"
                "echo \"Installing dependencies...\"\n"
                "python -m pip install --upgrade pip --quiet 2>/dev/null || true\n"
                "python -m pip install flask werkzeug plotly watchdog reportlab --quiet 2>/dev/null\n"
                f"export ACTIVE_PLAYBOOK_TYPES=\"{types_env}\"\n"
                "echo \"\"\n"
                "echo \"==========================================\"\n"
                "echo \"  Log Analyzer - Portable Edition\"\n"
                "echo \"==========================================\"\n"
                "echo \"Active Playbooks: $ACTIVE_PLAYBOOK_TYPES\"\n"
                "echo \"Web UI: http://localhost:5000\"\n"
                "echo \"\"\n"
                "echo \"Press Ctrl+C to stop\"\n"
                "echo \"==========================================\"\n"
                "echo \"\"\n"
                "python run_portable.py\n"
            )
            zf.writestr('start_portable.sh', start_sh)

            reqs = "flask\nwerkzeug\nplotly\nwatchdog\nreportlab\n"
            zf.writestr('requirements.txt', reqs)

            # Include ONLY the selected playbook JSON files (not all of them)
            # This ensures the portable package only has the rules for selected types
            try:
                workspace_root = Path(__file__).parent
                for selected_type in selected_types:
                    if selected_type == 'all':
                        # Include all playbook files if 'all' is selected
                        all_types = ['windows', 'linux', 'mac', 'osfc', 'fortinet', 'syslog', 
                                   'apache', 'nginx', 'iis', 'dns', 'proxy']
                        for ptype in all_types:
                            playbook_file = workspace_root / f'playbooks_{ptype}.json'
                            if playbook_file.exists():
                                zf.write(playbook_file, f'playbooks_{ptype}.json')
                        break  # Don't process other types if 'all' is selected
                    else:
                        # Include only this specific playbook file
                        playbook_file = workspace_root / f'playbooks_{selected_type}.json'
                        if playbook_file.exists():
                            zf.write(playbook_file, f'playbooks_{selected_type}.json')
                        else:
                            print(f"[Warning] Playbook file not found: playbooks_{selected_type}.json")
            except Exception as e:
                print(f"[Warning] Failed to include playbook files: {e}")

            # Readme for quick use
            playbook_list = ', '.join(selected_types) if selected_types and selected_types != ['all'] else 'ALL'
            readme = (
                "=== Plug-and-Play Log Analyzer & Collector ===\n"
                f"Active Playbooks: {playbook_list}\n"
                f"Package Type: {playbook_type}\n\n"
                "QUICK START (Windows):\n"
                "1. Unzip this folder\n"
                "2. Double-click 'start_portable.bat'\n"
                "   (First run may take 30-60 seconds to install dependencies)\n"
                "3. Choose between:\n"
                "   - Web Interface (browser-based, port 5000)\n"
                "   - Desktop GUI (native Windows app with real-time log collection)\n\n"
                "FEATURES:\n"
                "Web Interface:\n"
                "  • Browser-based UI\n"
                "  • Upload logs from files\n"
                "  • Advanced analytics and playbook management\n"
                "  • Multi-user authentication\n\n"
                "Desktop GUI:\n"
                "  • Real-time Windows Event Log collection\n"
                "  • System & Application log monitoring\n"
                "  • Network connection tracking\n"
                "  • Live log display with severity highlighting\n"
                "  • CSV export and database viewer\n"
                "  • No web browser needed\n\n"
                "CREATE EXECUTABLE (one-time):\n"
                "1. Run 'start_portable.bat' once to verify\n"
                "2. Open PowerShell (as Admin) in this folder\n"
                "3. Run: venv\\Scripts\\activate\n"
                "4. Run: pip install pyinstaller\n"
                "5. Run: pyinstaller --onefile --noconsole --name log-analyzer Launcher.py\n"
                "6. Your exe is in dist\\log-analyzer.exe\n\n"
                "PACKAGE CONTENTS:\n"
                "- Log_Analyzer.py : Web interface source\n"
                "- LogCollector_GUI.py : Desktop GUI with system log collectors\n"
                "- Launcher.py : Choose between Web or Desktop\n"
                "- run_portable.py : Python entry point\n"
                "- start_portable.bat : Auto-setup and launch (Windows)\n"
                f"- playbooks_*.json : Detection rules for {playbook_list} playbooks\n"
                "- logs.csv : Sample logs\n"
                "- report_summary.json : Stats snapshot\n"
                "- manifest.json : Package metadata (includes selected playbook types)\n"
                "- requirements.txt : Python dependencies\n\n"
                "NOTES:\n"
                f"- This package includes ONLY the selected playbooks: {playbook_list}\n"
                "- First run auto-installs Python packages (requires internet)\n"
                "- All collected logs stay local (SQLite database)\n"
                "- Web UI runs on port 5000\n"
                "- Desktop GUI collects Windows Event Logs, System Logs, and Network info\n"
                "- For EXE: double-click log-analyzer.exe to launch the launcher menu\n"
            )
            zf.writestr('README.txt', readme)

        buffer.seek(0)
        return buffer
    
    def _setup_routes(self):
        """Setup all application routes."""
        
        # ========== AUTHENTICATION ROUTES ==========
        
        @self.app.route('/')
        def index():
            if 'user_id' not in session:
                return redirect(url_for('login'))
            return self._render_template('index.html', **self._get_base_context())
        
        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            if request.method == 'POST':
                username = request.form.get('username', '')
                password = request.form.get('password', '')
                
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
                    user = cursor.fetchone()
                    
                    if user and password and check_password_hash(user['password_hash'], password):
                        session['user_id'] = user['id']
                        session['username'] = user['username']
                        session['role'] = user['role']
                        
                        # Update last login
                        cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
                        
                        flash('Login successful!', 'success')
                        return redirect(url_for('index'))
                    else:
                        flash('Invalid username or password', 'danger')
            
            if 'user_id' in session:
                return redirect(url_for('index'))
            
            return self._render_template('login.html')
        
        @self.app.route('/logout')
        def logout():
            session.clear()
            flash('You have been logged out.', 'info')
            return redirect(url_for('login'))
        
        @self.app.route('/register', methods=['GET', 'POST'])
        def register():
            if 'user_id' in session:
                return redirect(url_for('index'))
            
            if request.method == 'POST':
                username = request.form.get('username', '')
                email = request.form.get('email', '')
                password = request.form.get('password', '')
                confirm_password = request.form.get('confirm_password', '')
                full_name = request.form.get('full_name', '')
                
                # Validation
                if not all([username, email, password, confirm_password]):
                    flash('All fields are required', 'danger')
                elif password != confirm_password:
                    flash('Passwords do not match', 'danger')
                elif len(password) < 6:
                    flash('Password must be at least 6 characters', 'danger')
                else:
                    try:
                        with self.db.get_connection() as conn:
                            cursor = conn.cursor()
                            password_hash = generate_password_hash(password)
                            cursor.execute('''
                                INSERT INTO users (username, email, password_hash, full_name)
                                VALUES (?, ?, ?, ?)
                            ''', (username, email, password_hash, full_name))
                        
                        flash('Registration successful! Please login.', 'success')
                        return redirect(url_for('login'))
                    except sqlite3.IntegrityError:
                        flash('Username or email already exists', 'danger')
            
            return self._render_template('register.html')
        
        # ========== MAIN APPLICATION ROUTES ==========
        
        @self.app.route('/dashboard')
        def dashboard():
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            stats = self.log_manager.get_statistics()
            
            # Ensure severity_dist has default severities even if empty
            if not stats.get('severity_dist'):
                stats['severity_dist'] = {
                    'CRITICAL': 0,
                    'HIGH': 0, 
                    'MEDIUM': 0,
                    'LOW': 0,
                    'INFO': 0
                }
            else:
                # Ensure all severity levels exist in the dictionary
                for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                    if severity not in stats['severity_dist']:
                        stats['severity_dist'][severity] = 0
            
            # Create charts data with proper defaults
            severity_labels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            severity_values = [stats['severity_dist'].get(label, 0) for label in severity_labels]
            
            # Prepare hourly distribution with defaults
            hourly_dist = stats.get('hourly_dist', [])
            if hourly_dist:
                hourly_labels = [str(h[0]).zfill(2) + ':00' for h in hourly_dist]
                hourly_values = [h[1] for h in hourly_dist]
            else:
                # Create empty hourly data
                hourly_labels = [f"{i:02d}:00" for i in range(24)]
                hourly_values = [0] * 24
            
            # Recent logs
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, timestamp, source_name, severity, message 
                    FROM log_entries 
                    ORDER BY timestamp DESC 
                    LIMIT 10
                ''')
                recent_logs = [dict(row) for row in cursor.fetchall()]
            
            # Top sources by threat count
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT source_name, COUNT(*) as count,
                        SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical_count,
                        SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) as high_count
                    FROM log_entries 
                    GROUP BY source_name 
                    ORDER BY critical_count DESC, high_count DESC
                    LIMIT 5
                ''')
                top_sources = [dict(row) for row in cursor.fetchall()]
            
            # Get alerts count for the header
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'new'")
                alerts_count = cursor.fetchone()[0]
            
            context = {
                'user': {
                    'username': session.get('username', 'Guest'),
                    'role': session.get('role', 'guest')
                },
                'alerts_count': alerts_count,
                'now': datetime.now(),
                'stats': stats,
                'recent_logs': recent_logs,
                'top_sources': top_sources,
                'has_data': stats.get('total_logs', 0) > 0,
                'severity_labels': json.dumps(severity_labels),
                'severity_values': json.dumps(severity_values),
                'hourly_labels': json.dumps(hourly_labels),
                'hourly_values': json.dumps(hourly_values),
            }
            
            return self._render_template('dashboard.html', **context)

        @self.app.route('/upload', methods=['GET', 'POST'])
        def upload():
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            if request.method == 'POST':
                # Support multiple files
                if 'log_files' not in request.files:
                    flash('No files selected. Please choose log files to upload.', 'danger')
                    return redirect(request.url)
                
                files = request.files.getlist('log_files')
                if not files or all(f.filename == '' for f in files):
                    flash('No files selected. Please choose log files to upload.', 'danger')
                    return redirect(request.url)
                
                # Get upload parameters (apply to all files)
                log_format = request.form.get('log_format', 'auto').strip()
                
                success_count = 0
                error_count = 0
                total_entries = 0
                total_ttp_matches = 0
                total_threats = 0
                errors = []
                
                max_size = 100 * 1024 * 1024  # 100MB per file
                
                try:
                    for file in files:
                        if not file.filename:
                            continue
                        
                        # Validate file size
                        file.seek(0, os.SEEK_END)
                        file_size = file.tell()
                        file.seek(0)
                        
                        if file_size > max_size:
                            error_msg = f'{file.filename}: File is too large ({formatFileSize(file_size)}). Max 100MB.'
                            errors.append(error_msg)
                            error_count += 1
                            continue
                        
                        # Use filename without extension as source name
                        safe_name = secure_filename(file.filename or '')
                        source_name = safe_name.rsplit('.', 1)[0] or 'uploaded_file'
                        
                        try:
                            # Create timestamp for unique file naming
                            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                            filename = secure_filename(file.filename or '')
                            unique_filename = f"{timestamp}_{filename}"
                            temp_path = os.path.join(self.upload_dir, unique_filename)
                            
                            # Save file with streaming for large files
                            chunk_size = 4096  # 4KB chunks
                            with open(temp_path, 'wb') as f:
                                while True:
                                    chunk = file.read(chunk_size)
                                    if not chunk:
                                        break
                                    f.write(chunk)
                            
                            # Process file
                            result = self.log_manager.process_log_file(temp_path, source_name, log_format, refresh=False)
                            
                            # Clean up temp file
                            if os.path.exists(temp_path):
                                try:
                                    os.remove(temp_path)
                                except:
                                    pass
                            
                            if result['success']:
                                success_count += 1
                                total_entries += result['count']
                                total_ttp_matches += result['ttp_matches']
                                total_threats += result.get('threats_detected', 0)
                            else:
                                error_msg = f"{file.filename}: {result.get('error', 'Unknown error')}"
                                errors.append(error_msg)
                                error_count += 1
                        
                        except Exception as e:
                            error_msg = f"{file.filename}: {str(e)}"
                            errors.append(error_msg)
                            error_count += 1
                    
                    # Display comprehensive summary
                    if success_count > 0:
                        success_msg = (
                            f"✓ Successfully processed {success_count} file(s) with {total_entries} log entries. "
                            f"Detected {total_ttp_matches} TTP matches and {total_threats} potential threats."
                        )
                        flash(success_msg, 'success')
                    
                    if error_count > 0:
                        for error in errors:
                            flash(f"⚠ {error}", 'warning')
                    
                    # Redirect to dashboard
                    return redirect(url_for('dashboard'))
                        
                except Exception as e:
                    flash(f'Upload error: {str(e)}', 'danger')
                    return redirect(request.url)
            
            context = self._get_base_context()
            return self._render_template('upload.html', **context)
        
        @self.app.route('/api/upload-multiple', methods=['POST'])
        def api_upload_multiple():
            """API endpoint for batch file upload with progress tracking"""
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            if 'files' not in request.files:
                return jsonify({'error': 'No files provided'}), 400
            
            files = request.files.getlist('files')
            log_format = request.form.get('log_format', 'auto')
            
            if not files:
                return jsonify({'error': 'No files selected'}), 400
            
            results = {
                'processed': 0,
                'failed': 0,
                'total_entries': 0,
                'total_threats': 0,
                'files': []
            }
            
            max_size = 100 * 1024 * 1024
            
            for file in files:
                if file.filename == '':
                    continue
                
                file_result = {
                    'filename': file.filename,
                    'status': 'success',
                    'entries': 0,
                    'error': None
                }
                
                try:
                    # Check file size
                    file.seek(0, os.SEEK_END)
                    file_size = file.tell()
                    file.seek(0)
                    
                    if file_size > max_size:
                        file_result['status'] = 'error'
                        file_result['error'] = f'File too large ({formatFileSize(file_size)}). Max 100MB.'
                        results['failed'] += 1
                        results['files'].append(file_result)
                        continue
                    
                    safe_name = secure_filename(file.filename or '')
                    source_name = safe_name.rsplit('.', 1)[0] or 'uploaded_file'
                    
                    # Create temp file
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = safe_name
                    unique_filename = f"{timestamp}_{filename}"
                    temp_path = os.path.join(self.upload_dir, unique_filename)
                    
                    # Save file
                    chunk_size = 4096
                    with open(temp_path, 'wb') as f:
                        while True:
                            chunk = file.read(chunk_size)
                            if not chunk:
                                break
                            f.write(chunk)
                    
                    # Process
                    result = self.log_manager.process_log_file(temp_path, source_name, log_format, refresh=False)
                    
                    # Cleanup
                    if os.path.exists(temp_path):
                        try:
                            os.remove(temp_path)
                        except:
                            pass
                    
                    if result['success']:
                        file_result['entries'] = result['count']
                        results['processed'] += 1
                        results['total_entries'] += result['count']
                        results['total_threats'] += result.get('threats_detected', 0)
                    else:
                        file_result['status'] = 'error'
                        file_result['error'] = result.get('error', 'Processing failed')
                        results['failed'] += 1
                
                except Exception as e:
                    file_result['status'] = 'error'
                    file_result['error'] = str(e)
                    results['failed'] += 1
                
                results['files'].append(file_result)
            
            return jsonify(results)
        
        @self.app.route('/api/open-folder', methods=['POST'])
        def open_uploads_folder():
            """Open the uploads folder in file explorer"""
            try:
                import subprocess
                import platform
                
                upload_path = os.path.abspath(self.upload_dir)
                
                if platform.system() == 'Windows':
                    os.startfile(upload_path)
                elif platform.system() == 'Darwin':  # macOS
                    subprocess.Popen(['open', upload_path])
                else:  # Linux
                    subprocess.Popen(['xdg-open', upload_path])
                
                return jsonify({'success': True, 'message': 'Folder opened'})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)}), 400
        
        @self.app.route('/logs')
        def logs():
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            # Get search parameters with defaults
            search_params = {
                'search_query': request.args.get('search', '').strip(),
                'severity': request.args.get('severity', 'all'),
                'source': request.args.get('source', '').strip(),
                'source_ip': request.args.get('source_ip', '').strip(),
                'user': request.args.get('user', '').strip(),
                'event_type': request.args.get('event_type', '').strip(),
                'date_from': request.args.get('date_from', ''),
                'date_to': request.args.get('date_to', ''),
                'page': int(request.args.get('page', 1)),
                'per_page': int(request.args.get('per_page', 50))
            }
            
            # Get logs with search
            logs_list, total = self.log_manager.search_logs(search_params)
            
            # Get unique values for dropdowns
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get unique sources
                cursor.execute("SELECT DISTINCT source_name FROM log_entries WHERE source_name IS NOT NULL ORDER BY source_name")
                unique_sources = [row['source_name'] for row in cursor.fetchall()]
                
                # Get unique source IPs
                cursor.execute("SELECT DISTINCT source_ip FROM log_entries WHERE source_ip IS NOT NULL AND source_ip != '' ORDER BY source_ip")
                unique_source_ips = [row['source_ip'] for row in cursor.fetchall()]
                
                # Get unique users
                cursor.execute("SELECT DISTINCT user FROM log_entries WHERE user IS NOT NULL AND user != '' ORDER BY user")
                unique_users = [row['user'] for row in cursor.fetchall()]
                
                # Get unique event types
                cursor.execute("SELECT DISTINCT event_type FROM log_entries WHERE event_type IS NOT NULL AND event_type != '' ORDER BY event_type")
                unique_event_types = [row['event_type'] for row in cursor.fetchall()]
                
                # Get unique tags
                cursor.execute("SELECT tags FROM log_entries WHERE tags IS NOT NULL AND tags != ''")
                all_tags = set()
                for row in cursor.fetchall():
                    if row['tags']:
                        tags_list = row['tags'].split(',')
                        all_tags.update(tags_list)
                unique_tags = sorted(all_tags)
            
            # Calculate pagination
            total_pages = max(1, (total + search_params['per_page'] - 1) // search_params['per_page'])
            search_params['page'] = min(search_params['page'], total_pages)
            
            context = self._get_base_context()
            context.update({
                'logs': logs_list,
                'search_params': search_params,
                'total': total,
                'total_pages': total_pages,
                'current_page': search_params['page'],
                'per_page_options': [10, 25, 50, 100, 200],
                'unique_sources': unique_sources[:50],  # Limit for dropdown
                'unique_source_ips': unique_source_ips[:50],
                'unique_users': unique_users[:50],
                'unique_event_types': unique_event_types[:50],
                'unique_tags': unique_tags[:50],
                'severity_levels': ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
                'export_formats': ['csv', 'json', 'pdf']
            })
            
            return self._render_template('logs.html', **context)
        
        @self.app.route('/api/logs/<int:log_id>')
        def api_get_log(log_id):
            """Get detailed information about a specific log entry."""
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT * FROM log_entries WHERE id = ?', (log_id,))
                    log = cursor.fetchone()
                    
                    if log:
                        log_dict = dict(log)
                        # Parse tags
                        if log_dict['tags']:
                            log_dict['tags_list'] = [t.strip() for t in log_dict['tags'].split(',') if t.strip()]
                        else:
                            log_dict['tags_list'] = []
                        
                        # Get related logs (same source IP within 1 hour)
                        cursor.execute('''
                            SELECT id, timestamp, severity, message, ttp_match 
                            FROM log_entries 
                            WHERE source_ip = ? 
                            AND timestamp BETWEEN datetime(?, '-1 hour') AND datetime(?, '+1 hour')
                            AND id != ?
                            ORDER BY timestamp DESC
                            LIMIT 10
                        ''', (log_dict['source_ip'], log_dict['timestamp'], log_dict['timestamp'], log_id))
                        
                        related_logs = [dict(row) for row in cursor.fetchall()]
                        log_dict['related_logs'] = related_logs
                        
                        return jsonify(log_dict)
                    else:
                        return jsonify({'error': 'Log not found'}), 404
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/logs/export', methods=['POST'])
        def api_export_logs():
            """Export logs in various formats."""
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                data = request.get_json(silent=True) or {}
                format_type = data.get('format', 'csv')
                search_params = data.get('search_params', {})
                raw_ids = data.get('log_ids', [])
                log_ids = [int(log_id) for log_id in raw_ids if str(log_id).strip().isdigit()]
                
                # Get logs based on search params or specific IDs
                if log_ids:
                    with sqlite3.connect(self.db.db_path) as conn:
                        conn.row_factory = sqlite3.Row
                        cursor = conn.cursor()
                        cursor.execute(
                            f"SELECT * FROM log_entries WHERE id IN ({','.join(['?']*len(log_ids))}) ORDER BY timestamp DESC",
                            log_ids
                        )
                        rows = cursor.fetchall()
                        logs_list = [dict(row) for row in rows]
                else:
                    logs_list, total = self.log_manager.search_logs(search_params)
                
                if format_type == 'csv':
                    # Generate CSV
                    output = io.StringIO()
                    writer = csv.writer(output)
                    
                    # Write header
                    writer.writerow(['ID', 'Timestamp', 'Source', 'Severity', 'Message', 
                                'Source IP', 'Destination IP', 'User', 'Event Type', 
                                'TTP Match', 'Tags', 'Anomaly Score'])
                    
                    # Write data
                    for log in logs_list:
                        writer.writerow([
                            log.get('id', ''),
                            log.get('timestamp', ''),
                            log.get('source_name', ''),
                            log.get('severity', ''),
                            log.get('message', ''),
                            log.get('source_ip', ''),
                            log.get('dest_ip', ''),
                            log.get('user', ''),
                            log.get('event_type', ''),
                            log.get('ttp_match', ''),
                            log.get('tags', ''),
                            log.get('anomaly_score', '')
                        ])
                    
                    response = make_response(output.getvalue())
                    response.headers['Content-Disposition'] = f'attachment; filename=logs_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
                    response.headers['Content-Type'] = 'text/csv'
                    return response
                    
                elif format_type == 'json':
                    # Generate JSON
                    response = make_response(json.dumps(logs_list, indent=2, default=str))
                    response.headers['Content-Disposition'] = f'attachment; filename=logs_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
                    response.headers['Content-Type'] = 'application/json'
                    return response

                elif format_type == 'pdf':
                    if not HAS_REPORTLAB:
                        return jsonify({'error': 'PDF export requires reportlab dependency'}), 400
                    buffer = io.BytesIO()
                    doc = SimpleDocTemplate(buffer, pagesize=A4)
                    table_data = [['ID', 'Timestamp', 'Source', 'Severity', 'Message', 'Source IP', 'Dest IP', 'User']]
                    for log in logs_list:
                        table_data.append([
                            str(log.get('id', '')),
                            str(log.get('timestamp', '')),
                            str(log.get('source_name', '')),
                            str(log.get('severity', '')),
                            str(log.get('message', ''))[:120],
                            str(log.get('source_ip', '')),
                            str(log.get('dest_ip', '')),
                            str(log.get('user', '')),
                        ])
                    table = Table(table_data, repeatRows=1)
                    table.setStyle(TableStyle([
                        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2c3e50')),
                        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0,0), (-1,0), 9),
                        ('GRID', (0,0), (-1,-1), 0.25, colors.grey),
                        ('VALIGN', (0,0), (-1,-1), 'TOP'),
                        ('FONTSIZE', (0,1), (-1,-1), 8),
                    ]))
                    elements: list = [table]
                    doc.build(elements)
                    buffer.seek(0)
                    response = make_response(buffer.getvalue())
                    response.headers['Content-Disposition'] = f'attachment; filename=logs_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
                    response.headers['Content-Type'] = 'application/pdf'
                    return response
                    
                else:
                    return jsonify({'error': 'Unsupported format'}), 400
                    
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/logs/bulk-actions', methods=['POST'])
        def api_logs_bulk_actions():
            """Perform bulk actions on logs (delete, tag, etc.)"""
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                data = request.get_json(silent=True) or {}
                action = data.get('action')
                raw_log_ids = data.get('log_ids', [])
                log_ids = [int(log_id) for log_id in raw_log_ids if str(log_id).strip().isdigit()]
                
                if not action or not log_ids:
                    return jsonify({'error': 'Missing action or log IDs'}), 400
                
                with sqlite3.connect(self.db.db_path) as conn:
                    cursor = conn.cursor()
                    
                    if action == 'delete':
                        cursor.execute(f"DELETE FROM log_entries WHERE id IN ({','.join(['?']*len(log_ids))})", log_ids)
                        conn.commit()
                        return jsonify({'status': 'success', 'message': f'Deleted {cursor.rowcount} logs'}), 200
                    
                    elif action == 'add_tags':
                        tags_to_add = data.get('tags', '')
                        
                        for log_id in log_ids:
                            cursor.execute("SELECT tags FROM log_entries WHERE id = ?", (log_id,))
                            row = cursor.fetchone()
                            if row:
                                existing_tags = row[0] or ''
                                # Merge and deduplicate tags
                                tag_set = set([t.strip() for t in existing_tags.split(',') if t.strip()])
                                tag_set.update([t.strip() for t in tags_to_add.split(',') if t.strip()])
                                new_tags = ', '.join(sorted(tag_set))
                                cursor.execute("UPDATE log_entries SET tags = ? WHERE id = ?", (new_tags, log_id))
                        conn.commit()
                        return jsonify({'status': 'success', 'message': f'Updated tags for {len(log_ids)} logs'}), 200
                    
                    else:
                        return jsonify({'error': 'Invalid action'}), 400
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/threats')
        def threats():
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            context = self._get_base_context()
            return self._render_template('threats.html', **context)
        
        # ========== THREAT API ENDPOINTS ==========
        
        @self.app.route('/api/threats/summary')
        def api_threats_summary():
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # Get active threats (last 24 hours)
                    cursor.execute('''
                        SELECT COUNT(*) as count
                        FROM log_entries
                        WHERE timestamp > datetime('now', '-24 hours')
                        AND severity IN ('CRITICAL', 'HIGH')
                    ''')
                    active_threats = cursor.fetchone()[0] or 0
                    
                    # Get critical events
                    cursor.execute('''
                        SELECT COUNT(*) as count
                        FROM log_entries
                        WHERE severity = 'CRITICAL'
                        AND timestamp > datetime('now', '-7 days')
                    ''')
                    critical_events = cursor.fetchone()[0] or 0
                    
                    # Get unique TTPs
                    cursor.execute('''
                        SELECT COUNT(DISTINCT ttp_match) as count
                        FROM log_entries
                        WHERE ttp_match IS NOT NULL
                        AND ttp_match != ''
                    ''')
                    unique_ttps = cursor.fetchone()[0] or 0
                    
                    # Get top source IP
                    cursor.execute('''
                        SELECT source_ip, COUNT(*) as count
                        FROM log_entries
                        WHERE severity IN ('CRITICAL', 'HIGH')
                        AND source_ip IS NOT NULL
                        GROUP BY source_ip
                        ORDER BY count DESC
                        LIMIT 1
                    ''')
                    top_source = cursor.fetchone()
                    top_source_ip = top_source['source_ip'] if top_source else '-'
                    
                    # Get severity distribution
                    cursor.execute('''
                        SELECT severity, COUNT(*) as count
                        FROM log_entries
                        WHERE timestamp > datetime('now', '-7 days')
                        GROUP BY severity
                    ''')
                    severity_rows = cursor.fetchall()
                    severity_data = {row['severity'].lower(): row['count'] for row in severity_rows}
                    
                    # Get total threats
                    cursor.execute('''
                        SELECT COUNT(*) as count
                        FROM log_entries
                        WHERE severity IN ('CRITICAL', 'HIGH', 'MEDIUM')
                    ''')
                    total_threats = cursor.fetchone()[0] or 0
                    
                    # Get unique sources
                    cursor.execute('''
                        SELECT COUNT(DISTINCT source_ip) as count
                        FROM log_entries
                        WHERE source_ip IS NOT NULL
                        AND severity IN ('CRITICAL', 'HIGH')
                    ''')
                    unique_sources = cursor.fetchone()[0] or 0
                    
                    # Get affected users
                    cursor.execute('''
                        SELECT COUNT(DISTINCT user) as count
                        FROM log_entries
                        WHERE user IS NOT NULL
                        AND severity IN ('CRITICAL', 'HIGH')
                    ''')
                    affected_users = cursor.fetchone()[0] or 0
                    
                    return jsonify({
                        'success': True,
                        'active_threats': active_threats,
                        'critical_events': critical_events,
                        'unique_ttps': unique_ttps,
                        'top_source_ip': top_source_ip,
                        'severity_distribution': {
                            'critical': severity_data.get('critical', 0),
                            'high': severity_data.get('high', 0),
                            'medium': severity_data.get('medium', 0),
                            'low': severity_data.get('low', 0),
                            'info': severity_data.get('info', 0)
                        },
                        'total_threats': total_threats,
                        'unique_sources': unique_sources,
                        'affected_users': affected_users,
                        'avg_severity': 'HIGH' if critical_events > 0 else ('MEDIUM' if active_threats > 0 else 'LOW')
                    })
                    
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/threats/recent')
        def api_threats_recent():
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT timestamp, severity, message, source_ip, source_name, ttp_match
                        FROM log_entries
                        WHERE severity IN ('CRITICAL', 'HIGH', 'MEDIUM')
                        ORDER BY timestamp DESC
                        LIMIT 50
                    ''')
                    
                    threats = [dict(row) for row in cursor.fetchall()]
                    return jsonify(threats)
                    
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/threats/ttp-detections')
        def api_threats_ttp_detections():
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT ttp_match, COUNT(*) as count,
                               MAX(severity) as severity,
                               MIN(timestamp) as first_seen,
                               MAX(timestamp) as last_seen,
                               GROUP_CONCAT(DISTINCT source_ip) as source_ips
                        FROM log_entries
                        WHERE ttp_match IS NOT NULL AND ttp_match != ''
                        GROUP BY ttp_match
                        ORDER BY count DESC
                    ''')
                    
                    ttps = []
                    for row in cursor.fetchall():
                        ttp_match = row['ttp_match']
                        ttp_parts = ttp_match.split(':', 1)
                        ttps.append({
                            'id': ttp_parts[0] if len(ttp_parts) > 0 else 'Unknown',
                            'name': ttp_parts[1] if len(ttp_parts) > 1 else ttp_match,
                            'description': f"MITRE ATT&CK Technique {ttp_parts[0]}" if ttp_parts[0] else 'Unknown technique',
                            'count': row['count'],
                            'severity': row['severity'],
                            'first_seen': row['first_seen'],
                            'last_seen': row['last_seen'],
                            'source_ips': row['source_ips']
                        })
                    
                    return jsonify(ttps)
                    
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/threats/timeline')
        def api_threats_timeline():
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT strftime('%Y-%m-%d', timestamp) as date,
                               COUNT(*) as count
                        FROM log_entries
                        WHERE timestamp > datetime('now', '-7 days')
                        AND severity IN ('CRITICAL', 'HIGH', 'MEDIUM')
                        GROUP BY date
                        ORDER BY date
                    ''')
                    
                    timeline = [dict(row) for row in cursor.fetchall()]
                    return jsonify(timeline)
                    
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/threats/intelligence')
        def api_threats_intelligence():
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT DISTINCT source_ip, COUNT(*) as count, MAX(severity) as max_severity
                        FROM log_entries
                        WHERE source_ip IS NOT NULL
                        AND severity IN ('CRITICAL', 'HIGH')
                        GROUP BY source_ip
                        ORDER BY count DESC
                        LIMIT 5
                    ''')
                    
                    top_threats = cursor.fetchall()
                    intelligence = []
                    
                    for threat in top_threats:
                        intelligence.append({
                            'title': f'Threat Actor: {threat["source_ip"]}',
                            'description': f'Detected {threat["count"]} high severity events from this IP',
                            'source': 'Internal Detection',
                            'date': datetime.now().strftime('%Y-%m-%d'),
                            'severity': threat['max_severity']
                        })
                    
                    # Add MITRE ATT&CK intelligence
                    cursor.execute('''
                        SELECT ttp_match, COUNT(*) as count
                        FROM log_entries
                        WHERE ttp_match IS NOT NULL
                        GROUP BY ttp_match
                        ORDER BY count DESC
                        LIMIT 3
                    ''')
                    
                    top_ttps = cursor.fetchall()
                    for ttp in top_ttps:
                        intelligence.append({
                            'title': f'Active TTP: {ttp["ttp_match"]}',
                            'description': f'Detected {ttp["count"]} times in your environment',
                            'source': 'MITRE ATT&CK',
                            'date': datetime.now().strftime('%Y-%m-%d'),
                            'severity': 'HIGH'
                        })
                    
                    return jsonify(intelligence)
                    
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/threats/hunt', methods=['POST'])
        def api_threats_hunt():
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                found_threats = 0
                
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # Hunt for brute force patterns
                    cursor.execute('''
                        SELECT source_ip, COUNT(*) as attempts
                        FROM log_entries
                        WHERE (message LIKE '%failed%login%'
                           OR message LIKE '%authentication%failed%'
                           OR message LIKE '%invalid%password%')
                        AND source_ip IS NOT NULL
                        GROUP BY source_ip
                        HAVING attempts > 5
                    ''')
                    brute_force = cursor.fetchall()
                    found_threats += len(brute_force)
                    
                    # Hunt for port scanning
                    cursor.execute('''
                        SELECT source_ip, COUNT(DISTINCT dest_ip) as targets
                        FROM log_entries
                        WHERE source_ip IS NOT NULL AND dest_ip IS NOT NULL
                        GROUP BY source_ip
                        HAVING targets > 10
                    ''')
                    port_scans = cursor.fetchall()
                    found_threats += len(port_scans)
                    
                    # Create alerts for found threats
                    if found_threats > 0:
                        cursor.execute('''
                            INSERT INTO alerts (title, description, severity, threat_type)
                            VALUES (?, ?, ?, ?)
                        ''', (
                            f'Threat Hunt Results',
                            f'Found {found_threats} potential threats during automated hunt',
                            'HIGH',
                            'THREAT_HUNTING'
                        ))
                
                return jsonify({
                    'success': True,
                    'found': found_threats,
                    'message': f'Threat hunt completed: {found_threats} threats found'
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/threats/export')
        def api_threats_export():
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                format_type = request.args.get('format', 'csv')
                
                if format_type == 'pdf' and HAS_REPORTLAB:
                    # Generate PDF threat report
                    return self.log_manager.generate_threat_pdf_report()
                else:
                    # Default to CSV export
                    output = io.StringIO()
                    writer = csv.writer(output)
                    
                    # Write header
                    writer.writerow(['Threat Report', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
                    writer.writerow([])
                    writer.writerow(['Timestamp', 'Severity', 'Source IP', 'TTP Match', 'Message'])
                    
                    # Write data
                    with self.db.get_connection() as conn:
                        cursor = conn.cursor()
                        cursor.execute('''
                            SELECT timestamp, severity, source_ip, ttp_match, message
                            FROM log_entries
                            WHERE severity IN ('CRITICAL', 'HIGH')
                            ORDER BY timestamp DESC
                        ''')
                        
                        for row in cursor.fetchall():
                            writer.writerow([
                                row['timestamp'],
                                row['severity'],
                                row['source_ip'] or '',
                                row['ttp_match'] or '',
                                row['message'][:100]
                            ])
                    
                    response = make_response(output.getvalue())
                    response.headers['Content-Disposition'] = f'attachment; filename=threat_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
                    response.headers['Content-Type'] = 'text/csv'
                    return response
                    
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/threats/report', methods=['POST'])
        def api_threats_generate_report():
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                report_id = f"THREAT_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO reports (report_id, report_type, generated_by, status)
                        VALUES (?, ?, ?, ?)
                    ''', (report_id, 'threat', session.get('username'), 'generated'))
                
                return jsonify({
                    'success': True,
                    'report_id': report_id,
                    'message': 'Threat report generation started'
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/threats/isolate', methods=['POST'])
        def api_threats_isolate():
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                data = request.get_json()
                source_ip = data.get('source_ip')
                
                if not source_ip:
                    return jsonify({'error': 'Source IP required'}), 400
                
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # Create isolation rule
                    cursor.execute('''
                        INSERT INTO custom_rules (name, description, rule_type, field, pattern, severity, tags)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        f'Isolate {source_ip}',
                        f'Auto-generated isolation rule for malicious IP {source_ip}',
                        'signature',
                        'source_ip',
                        f'^{source_ip}$',
                        'CRITICAL',
                        'isolation,blocked,threat'
                    ))
                    
                    # Create alert
                    cursor.execute('''
                        INSERT INTO alerts (title, description, severity, source_ips, threat_type)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        f'IP Isolation: {source_ip}',
                        f'Source IP {source_ip} has been isolated due to threat activity',
                        'HIGH',
                        source_ip,
                        'THREAT_ISOLATION'
                    ))
                
                return jsonify({
                    'success': True,
                    'message': f'Source IP {source_ip} has been isolated'
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/threats/clear', methods=['POST'])
        def api_threats_clear():
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # Clear resolved alerts
                    cursor.execute('DELETE FROM alerts WHERE status = "resolved"')
                    
                    # Update last threat check timestamp
                    cursor.execute('''
                        INSERT OR REPLACE INTO settings (key, value)
                        VALUES ('last_threat_check', ?)
                    ''', (datetime.now().isoformat(),))
                
                return jsonify({
                    'success': True,
                    'message': 'Threat data cleared successfully'
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/threats/ttp/<ttp_id>/create-rule', methods=['POST'])
        def api_threats_create_rule_from_ttp(ttp_id):
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT ttp_match, COUNT(*) as count
                        FROM log_entries
                        WHERE ttp_match LIKE ?
                        GROUP BY ttp_match
                        ORDER BY count DESC
                        LIMIT 1
                    ''', (f'%{ttp_id}%',))
                    
                    ttp_data = cursor.fetchone()
                    
                    if not ttp_data:
                        return jsonify({'error': 'TTP not found'}), 404
                    
                    # Create custom rule from TTP
                    rule_name = f"TTP Detection: {ttp_id}"
                    rule_description = f"Auto-generated rule for MITRE ATT&CK TTP {ttp_id}"
                    pattern = ttp_data['ttp_match'].split(':', 1)[1] if ':' in ttp_data['ttp_match'] else ttp_data['ttp_match']
                    
                    cursor.execute('''
                        INSERT INTO custom_rules (name, description, rule_type, field, pattern, severity, tags)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        rule_name,
                        rule_description,
                        'signature',
                        'message',
                        re.escape(pattern),
                        'HIGH',
                        f'mitre,ttp,{ttp_id},auto-generated'
                    ))
                
                return jsonify({
                    'success': True,
                    'message': f'Custom rule created for TTP {ttp_id}'
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/playbooks')
        def playbooks():
            if 'user_id' not in session:
                return redirect(url_for('login'))
            context = self._get_base_context()
            context.update({'playbooks': PLAYBOOKS})
            return self._render_template('playbooks.html', **context)
        
        @self.app.route('/view_rules')
        def view_rules():
            """Display all loaded playbook rules with statistics."""
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            # Check if viewing specific playbook
            playbook_type = request.args.get('playbook')
            
            if playbook_type and playbook_type in self.playbooks_by_type:
                # Show specific playbook editor
                playbook = self.playbooks_by_type[playbook_type]
                context = self._get_base_context()
                context.update({
                    'playbook_type': playbook_type,
                    'playbook': playbook,
                    'playbook_json': json.dumps(playbook, indent=2)
                })
                return self._render_template('edit_playbook.html', **context)
            
            # Get playbook statistics - showing ACTIVE playbooks only
            active_types = getattr(self, 'active_playbook_types', ['all'])
            playbook_stats = []
            
            for ptype, playbook in self.playbooks_by_type.items():
                # Only show if 'all' or if this type is in active list
                if 'all' not in active_types and ptype not in active_types:
                    continue
                    
                stats = {
                    'type': ptype,
                    'name': playbook['name'],
                    'description': playbook['description'],
                    'rule_count': playbook['rule_count'],
                    'log_type': playbook['log_type'],
                    'severity_breakdown': {
                        'Critical': sum(1 for r in playbook['rules'] if r.get('severity') == 'Critical'),
                        'High': sum(1 for r in playbook['rules'] if r.get('severity') == 'High'),
                        'Medium': sum(1 for r in playbook['rules'] if r.get('severity') == 'Medium'),
                        'Low': sum(1 for r in playbook['rules'] if r.get('severity') == 'Low')
                    },
                    'enabled_count': sum(1 for r in playbook['rules'] if r.get('enabled', True))
                }
                playbook_stats.append(stats)
            
            context = self._get_base_context()
            context.update({
                'playbook_stats': playbook_stats,
                'total_rules': len(self.log_manager.playbook_rules),
                'total_playbooks': len(playbook_stats),
                'active_playbook_types': active_types,
                'playbooks_by_type': self.playbooks_by_type,
                'active_playbook_type': getattr(self, 'active_playbook_type', 'all')
            })
            return self._render_template('view_rules.html', **context)

        @self.app.route('/api/playbooks/active', methods=['GET', 'POST'])
        def api_active_playbook():
            """Get or set the active playbook scope for real-time monitoring."""
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401

            # Only admins can change the active scope; everyone can read it
            is_admin = False
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],))
                    row = cursor.fetchone()
                    is_admin = row and row['role'] == 'admin'
            except Exception:
                is_admin = False

            if request.method == 'GET':
                available = ['all'] + sorted(self.playbooks_by_type.keys())
                return jsonify({
                    'success': True,
                    'active_playbook_type': getattr(self, 'active_playbook_type', 'all'),
                    'active_playbook_types': getattr(self, 'active_playbook_types', ['all']),
                    'available_types': available,
                    'active_rules': len(self.log_manager.playbook_rules),
                    'playbooks': {k: {'rule_count': len(v.get('rules', []))} for k, v in self.playbooks_by_type.items()}
                })

            # POST branch: update selection (admin only)
            if not is_admin:
                return jsonify({'error': 'Admin access required'}), 403

            try:
                data = request.get_json(silent=True) or {}
                requested_type = data.get('playbook_type', 'all')
                result = self._apply_playbook_selection(requested_type)
                result['success'] = True
                return jsonify(result)
            except ValueError as ve:
                return jsonify({'error': str(ve)}), 400
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/playbooks/package', methods=['GET', 'POST'])
        def api_playbook_package():
            """Generate a plug-and-play ZIP for selected playbook types with logs and summary."""
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401

            try:
                # Handle both GET and POST (POST for multiple selections)
                if request.method == 'POST':
                    data = request.get_json() or {}
                    selected_types = data.get('selected_types', [])
                    if isinstance(selected_types, str):
                        selected_types = [selected_types]
                    selected_types = [t.lower() for t in selected_types if t]
                else:
                    requested_type = request.args.get('type', getattr(self, 'active_playbook_type', 'all'))
                    selected_types = [requested_type.lower()] if requested_type else ['all']

                # Validate selected types
                for ptype in selected_types:
                    if ptype != 'all' and ptype not in self.playbooks_by_type:
                        return jsonify({'error': f'Invalid playbook type: {ptype}'}), 400

                # Build combined playbook payload
                if 'all' in selected_types or len(selected_types) == len(self.playbooks_by_type):
                    playbook_payload = {'playbooks': self.playbooks_by_type, 'rules': self.all_playbook_rules}
                    package_type = 'all'
                else:
                    selected_playbooks = {k: v for k, v in self.playbooks_by_type.items() if k in selected_types}
                    combined_rules = []
                    for pb_type in selected_types:
                        if pb_type in self.playbooks_by_type:
                            combined_rules.extend(self.playbooks_by_type[pb_type].get('rules', []))
                    playbook_payload = {'playbooks': selected_playbooks, 'rules': combined_rules}
                    package_type = '+'.join(sorted(selected_types))

                logs = self._collect_logs_for_playbook('+'.join(selected_types))
                summary = self._summarize_logs(logs, package_type)
                bundle = self._build_playbook_package(package_type, playbook_payload, logs, summary, selected_types)

                filename = f"plug_and_play_{package_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
                return send_file(bundle, mimetype='application/zip', as_attachment=True, download_name=filename)

            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/playbooks/logs', methods=['GET'])
        def api_playbook_logs():
            """Download logs CSV filtered by the selected playbook type (or all)."""
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401

            requested_type = request.args.get('type', getattr(self, 'active_playbook_type', 'all'))
            requested_type = (requested_type or 'all').lower()
            if requested_type != 'all' and requested_type not in self.playbooks_by_type:
                return jsonify({'error': 'Invalid playbook type'}), 400

            logs = self._collect_logs_for_playbook(requested_type)

            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['ID', 'Timestamp', 'Source', 'Severity', 'Message', 'Source IP', 'Destination IP', 'User', 'Event Type', 'TTP Match'])
            for log in logs:
                writer.writerow([
                    log.get('id', ''),
                    log.get('timestamp', ''),
                    log.get('source_name', ''),
                    log.get('severity', ''),
                    (log.get('message', '') or '')[:500],
                    log.get('source_ip', ''),
                    log.get('dest_ip', ''),
                    log.get('user', ''),
                    log.get('event_type', ''),
                    log.get('ttp_match', '')
                ])

            response = make_response(output.getvalue())
            response.headers['Content-Disposition'] = f"attachment; filename=logs_{requested_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            response.headers['Content-Type'] = 'text/csv'
            return response

        @self.app.route('/runbooks/<pb_id>')
        def runbook(pb_id: str):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            pb = next((p for p in PLAYBOOKS if p['id'] == pb_id), None)
            rb = RUNBOOKS.get(pb_id)
            if not pb or not rb:
                flash('Runbook not found', 'danger')
                return redirect(url_for('playbooks'))
            context = self._get_base_context()
            context.update({'playbook': pb, 'runbook': rb})
            return self._render_template('runbook.html', **context)
        
        @self.app.route('/alerts')
        def alerts():
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            alerts_list = self.log_manager.get_alerts()
            
            context = self._get_base_context()
            context.update({
                'alerts': alerts_list,
            })
            
            return self._render_template('alerts.html', **context)
        
        @self.app.route('/reports')
        def reports():
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            report_type = request.args.get('type', 'html')
            
            if report_type == 'csv':
                # Generate CSV report
                csv_content = self.log_manager.generate_report('csv')
                return Response(
                    csv_content,
                    mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment;filename=report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
                )
            
            elif report_type == 'pdf':
                # Generate PDF report
                pdf_content = self.log_manager.generate_report('pdf')
                if isinstance(pdf_content, bytes):
                    return Response(
                        pdf_content,
                        mimetype='application/pdf',
                        headers={'Content-Disposition': f'attachment;filename=report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'}
                    )
                else:
                    flash(f'PDF Generation Error: {pdf_content}', 'danger')
                    report_content = self.log_manager.generate_report()
            else:
                # HTML report (default)
                report_content = self.log_manager.generate_report()
            
            context = self._get_base_context()
            context.update({
                'report_content': report_content,
            })
            
            return self._render_template('reports.html', **context)
        
        @self.app.route('/api/stats')
        def api_stats():
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            stats = self.log_manager.get_statistics()
            return jsonify(stats)
        
        @self.app.route('/api/logs/recent')
        def api_recent_logs():
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT timestamp, source_name, severity, message 
                    FROM log_entries 
                    ORDER BY timestamp DESC 
                    LIMIT 20
                ''')
                
                logs = [{
                    'timestamp': row['timestamp'],
                    'source': row['source_name'],
                    'severity': row['severity'],
                    'message': row['message'][:100]
                } for row in cursor.fetchall()]
            
            return jsonify(logs)

        @self.app.route('/rules', methods=['GET', 'POST'])
        def custom_rules():
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            if request.method == 'POST':
                # Get JSON rule from textarea
                json_rule = request.form.get('json_rule', '').strip()
                
                if not json_rule:
                    flash('JSON rule cannot be empty.', 'danger')
                else:
                    try:
                        # Parse JSON
                        rule_data = json.loads(json_rule)
                        
                        # Validate required fields
                        name = rule_data.get('name')
                        pattern = rule_data.get('pattern')
                        
                        if not name or not pattern:
                            flash('JSON must include "name" and "pattern" fields.', 'danger')
                        elif len(name) < 3:
                            flash('Rule name must be at least 3 characters long.', 'danger')
                        elif len(pattern) < 2:
                            flash('Pattern must be at least 2 characters long.', 'danger')
                        else:
                            # Validate regex pattern
                            try:
                                re.compile(pattern)
                            except re.error as e:
                                flash(f'Invalid regex pattern: {e}', 'danger')
                                context = self._get_base_context()
                                context.update({
                                    'rules': self.log_manager.get_custom_rules(include_disabled=True)
                                })
                                return self._render_template('rules.html', **context)
                            
                            # Extract optional fields with defaults
                            description = rule_data.get('description', '')
                            rule_type = rule_data.get('rule_type', 'signature')
                            field = rule_data.get('field', 'message')
                            severity = rule_data.get('severity', 'MEDIUM').upper()
                            tags_raw = rule_data.get('tags', [])
                            enabled = rule_data.get('enabled', True)
                            
                            # Handle tags as array or comma-separated string
                            if isinstance(tags_raw, str):
                                tags = [t.strip() for t in tags_raw.split(',') if t.strip()]
                            elif isinstance(tags_raw, list):
                                tags = [str(t).strip() for t in tags_raw if str(t).strip()]
                            else:
                                tags = []
                            
                            rule = CustomRule(
                                id=None,
                                name=name.strip(),
                                description=description.strip() if description else '',
                                rule_type=rule_type,
                                field=field,
                                pattern=pattern.strip(),
                                severity=severity,
                                tags=tags,
                                enabled=enabled
                            )
                            try:
                                self.log_manager.add_custom_rule(rule)
                                flash(f'✓ Custom rule "{name}" saved and activated successfully!', 'success')
                                return redirect(url_for('custom_rules'))
                            except Exception as exc:
                                flash(f'Failed to save rule: {exc}', 'danger')
                    
                    except json.JSONDecodeError as e:
                        flash(f'Invalid JSON format: {e}', 'danger')
                    except Exception as e:
                        flash(f'Error processing rule: {e}', 'danger')
            
            context = self._get_base_context()
            context.update({
                'rules': self.log_manager.get_custom_rules(include_disabled=True)
            })
            return self._render_template('rules.html', **context)

        @self.app.route('/api/alerts/resolve/<int:alert_id>', methods=['POST'])
        def api_resolve_alert(alert_id):
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('UPDATE alerts SET status = ? WHERE id = ?', ('resolved', alert_id))
                    conn.commit()
                    
                    if cursor.rowcount > 0:
                        return jsonify({'success': True, 'message': 'Alert marked as resolved'})
                    else:
                        return jsonify({'error': 'Alert not found'}), 404
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/alerts/delete/<int:alert_id>', methods=['DELETE'])
        def api_delete_alert(alert_id):
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('DELETE FROM alerts WHERE id = ?', (alert_id,))
                    conn.commit()
                    
                    if cursor.rowcount > 0:
                        return jsonify({'success': True, 'message': 'Alert deleted successfully'})
                    else:
                        return jsonify({'error': 'Alert not found'}), 404
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/alerts/mark-all-read', methods=['POST'])
        def api_mark_all_read():
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('UPDATE alerts SET status = ? WHERE status = ?', ('resolved', 'new'))
                    conn.commit()
                    
                    return jsonify({'success': True, 'message': f'{cursor.rowcount} alerts marked as read'})
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/alerts/<int:alert_id>', methods=['GET'])
        def api_get_alert(alert_id):
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT * FROM alerts WHERE id = ?', (alert_id,))
                    alert = cursor.fetchone()
                    
                    if alert:
                        return jsonify(dict(alert))
                    else:
                        return jsonify({'error': 'Alert not found'}), 404
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/playbooks/delete/<playbook_id>', methods=['DELETE'])
        def api_delete_playbook(playbook_id):
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                success = self.log_manager.delete_playbook_rule(playbook_id)
                
                if success:
                    return jsonify({'success': True, 'message': 'Playbook deleted successfully'})
                else:
                    return jsonify({'error': 'Failed to delete playbook'}), 500
                    
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/playbook/save', methods=['POST'])
        def api_save_playbook():
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                data = request.get_json()
                playbook_type = data.get('playbook_type')
                content = data.get('content')
                
                if not playbook_type or not content:
                    return jsonify({'error': 'Missing playbook_type or content'}), 400
                
                # Validate playbook type
                valid_types = ['windows', 'linux', 'mac', 'osfc', 'fortinet', 'syslog', 'apache', 'nginx', 'iis', 'dns', 'proxy']
                if playbook_type not in valid_types:
                    return jsonify({'error': 'Invalid playbook type'}), 400
                
                # Determine filename
                filename = f'playbooks_{playbook_type}.json'
                
                # Validate JSON format
                try:
                    playbook_data = json.loads(content)
                except json.JSONDecodeError as e:
                    return jsonify({'error': f'Invalid JSON format: {str(e)}'}), 400
                
                # Save to file
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                # Reload playbook in memory
                self.playbooks_by_type[playbook_type] = playbook_data
                
                # Update all_playbook_rules
                self.all_playbook_rules = []
                for pb_type, pb in self.playbooks_by_type.items():
                    if 'rules' in pb:
                        self.all_playbook_rules.extend(pb['rules'])
                
                # Update LogManager with new rules
                if hasattr(self, 'log_manager'):
                    scoped_rules = self._get_rules_for_type(getattr(self, 'active_playbook_type', 'all'))
                    self.log_manager.update_playbook_rules(scoped_rules)
                
                return jsonify({
                    'success': True, 
                    'message': f'Successfully saved {filename}',
                    'total_rules': len(self.all_playbook_rules),
                    'active_playbook_type': getattr(self, 'active_playbook_type', 'all')
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/rules/test', methods=['POST'])
        def api_test_rule():
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            try:
                # Accept JSON body for spec-compliant testing
                payload = request.get_json(silent=True) or {}
                pattern = payload.get('pattern') or request.form.get('pattern', '')
                target_field = payload.get('target_field') or request.form.get('field', 'raw')
                sample_logs = payload.get('sample_logs')
                if sample_logs is None:
                    # Fallback to form textarea/file upload
                    sample_text = request.form.get('sample_text', '')
                    file = request.files.get('sample_file')
                    if sample_text:
                        sample_logs = [l for l in sample_text.splitlines() if l.strip()]
                    elif file:
                        content = file.read().decode('utf-8', errors='ignore')
                        sample_logs = [l for l in content.splitlines() if l.strip()]
                    else:
                        sample_logs = []

                # Implement spec: validate inputs
                if not sample_logs:
                    return jsonify({
                        'valid_regex': False,
                        'error': 'No sample logs provided.',
                        'matches': [],
                        'total_matches': 0
                    }), 400
                if not pattern:
                    return jsonify({
                        'valid_regex': False,
                        'error': 'Pattern is required.',
                        'matches': [],
                        'total_matches': 0
                    }), 400

                # Validate regex
                try:
                    compiled = re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    return jsonify({
                        'valid_regex': False,
                        'error': f'Invalid regex: {str(e)}',
                        'matches': [],
                        'total_matches': 0
                    }), 200

                # Limit to 2000 lines
                sample_logs = sample_logs[:2000]

                def extract_field(log_line: str, field: str) -> str:
                    if field.lower() == 'raw':
                        return log_line
                    elif field.lower() == 'message':
                        if ': ' in log_line:
                            return log_line.split(': ', 1)[1]
                        return log_line
                    else:
                        return log_line

                results = []
                match_count = 0
                for idx, line in enumerate(sample_logs, start=1):
                    field_text = extract_field(line, target_field)
                    m = compiled.search(field_text)
                    if m:
                        results.append({
                            'line_number': idx,
                            'text': line,
                            'matched': True,
                            'matched_text': m.group(0)
                        })
                        match_count += 1
                    else:
                        results.append({
                            'line_number': idx,
                            'text': line,
                            'matched': False,
                            'matched_text': ''
                        })

                return jsonify({
                    'valid_regex': True,
                    'error': '',
                    'matches': results,
                    'total_matches': match_count
                })
            except Exception as e:
                return jsonify({
                    'valid_regex': False,
                    'error': str(e),
                    'matches': [],
                    'total_matches': 0
                }), 500
        
        @self.app.route('/settings', methods=['GET', 'POST'])
        def settings():
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            if request.method == 'POST':
                # Update settings
                pass
            
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM settings')
                settings_list = {row['key']: row['value'] for row in cursor.fetchall()}
            
            context = self._get_base_context()
            context.update({
                'settings': settings_list,
                'available_playbook_types': ['all'] + sorted(self.playbooks_by_type.keys()),
                'active_playbook_type': getattr(self, 'active_playbook_type', 'all')
            })
            
            return self._render_template('settings.html', **context)
        
        @self.app.route('/analytics')
        def analytics():
            """Advanced analytics and threat intelligence dashboard"""
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # 1. EVENT TRENDS (24-hour)
                    cursor.execute('''
                        SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour,
                               COUNT(*) as count,
                               SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical,
                               SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) as high,
                               SUM(CASE WHEN severity='MEDIUM' THEN 1 ELSE 0 END) as medium,
                               SUM(CASE WHEN severity='LOW' THEN 1 ELSE 0 END) as low
                        FROM log_entries
                        WHERE timestamp > datetime('now', '-24 hours')
                        GROUP BY hour
                        ORDER BY hour DESC
                    ''')
                    trends = [dict(row) for row in cursor.fetchall()]
                    
                    # 2. SEVERITY DISTRIBUTION PIE CHART
                    cursor.execute('''
                        SELECT severity, COUNT(*) as count
                        FROM log_entries
                        WHERE timestamp > datetime('now', '-7 days')
                        GROUP BY severity
                    ''')
                    severity_dist = [dict(row) for row in cursor.fetchall()]
                    
                    # 3. TOP SOURCE IPs WITH THREAT SCORES
                    cursor.execute('''
                        SELECT source_ip, COUNT(*) as total_events,
                               SUM(CASE WHEN severity='CRITICAL' THEN 5 WHEN severity='HIGH' THEN 3 ELSE 1 END) as threat_score,
                               SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical_count,
                               SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) as high_count,
                               GROUP_CONCAT(DISTINCT ttp_match) as ttp_patterns,
                               MAX(timestamp) as last_seen
                        FROM log_entries
                        WHERE source_ip IS NOT NULL AND timestamp > datetime('now', '-7 days')
                        GROUP BY source_ip
                        ORDER BY threat_score DESC
                        LIMIT 25
                    ''')
                    source_dist = [dict(row) for row in cursor.fetchall()]
                    
                    # 4. EVENT TYPE DISTRIBUTION
                    cursor.execute('''
                        SELECT event_type, COUNT(*) as count,
                               SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical_count,
                               SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) as high_count
                        FROM log_entries
                        WHERE event_type IS NOT NULL AND timestamp > datetime('now', '-7 days')
                        GROUP BY event_type
                        ORDER BY count DESC
                        LIMIT 20
                    ''')
                    event_dist = [dict(row) for row in cursor.fetchall()]
                    
                    # 5. USER ACTIVITY ANALYSIS
                    cursor.execute('''
                        SELECT user, COUNT(*) as count,
                               SUM(CASE WHEN severity IN ('CRITICAL', 'HIGH') THEN 1 ELSE 0 END) as threat_count,
                               COUNT(DISTINCT source_ip) as source_ips,
                               COUNT(DISTINCT event_type) as event_types,
                               MAX(timestamp) as last_activity
                        FROM log_entries
                        WHERE user IS NOT NULL AND user != '' AND timestamp > datetime('now', '-7 days')
                        GROUP BY user
                        ORDER BY threat_count DESC, count DESC
                        LIMIT 20
                    ''')
                    user_activity = [dict(row) for row in cursor.fetchall()]
                    
                    # 6. MITRE ATTACK MAPPING (Top TTPs)
                    cursor.execute('''
                        SELECT ttp_match, COUNT(*) as count,
                               SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical,
                               GROUP_CONCAT(DISTINCT source_ip) as sources
                        FROM log_entries
                        WHERE ttp_match IS NOT NULL AND ttp_match != '' AND timestamp > datetime('now', '-7 days')
                        GROUP BY ttp_match
                        ORDER BY count DESC
                        LIMIT 15
                    ''')
                    ttp_mapping = [dict(row) for row in cursor.fetchall()]
                    
                    # 7. TEMPORAL ANALYSIS (Hour of Day)
                    cursor.execute('''
                        SELECT strftime('%H', timestamp) as hour_of_day,
                               COUNT(*) as count,
                               SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical
                        FROM log_entries
                        WHERE timestamp > datetime('now', '-7 days')
                        GROUP BY hour_of_day
                        ORDER BY CAST(hour_of_day AS INTEGER)
                    ''')
                    hourly_dist = [dict(row) for row in cursor.fetchall()]
                    
                    # 8. ANOMALY SCORE TRACKING
                    cursor.execute('''
                        SELECT strftime('%Y-%m-%d', timestamp) as day,
                               COUNT(*) as event_count,
                               COUNT(DISTINCT source_ip) as unique_sources,
                               COUNT(DISTINCT user) as unique_users,
                               SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical_count
                        FROM log_entries
                        WHERE timestamp > datetime('now', '-30 days')
                        GROUP BY day
                        ORDER BY day DESC
                    ''')
                    daily_stats = [dict(row) for row in cursor.fetchall()]
                    
                    # 9. ALERT SEVERITY TIMELINE
                    cursor.execute('''
                        SELECT strftime('%Y-%m-%d %H:00', timestamp) as time_bucket,
                               severity,
                               COUNT(*) as count
                        FROM log_entries
                        WHERE timestamp > datetime('now', '-7 days')
                        GROUP BY time_bucket, severity
                        ORDER BY time_bucket DESC
                    ''')
                    alert_timeline = [dict(row) for row in cursor.fetchall()]
                    
                    # 10. SOURCE IP vs DESTINATION ANALYSIS
                    cursor.execute('''
                        SELECT source_ip, source_name, COUNT(*) as count,
                               COUNT(DISTINCT event_type) as event_variety,
                               AVG(CASE WHEN severity='CRITICAL' THEN 1 WHEN severity='HIGH' THEN 0.5 ELSE 0.1 END) as avg_severity
                        FROM log_entries
                        WHERE source_ip IS NOT NULL AND timestamp > datetime('now', '-7 days')
                        GROUP BY source_ip, source_name
                        ORDER BY count DESC
                        LIMIT 15
                    ''')
                    source_dest = [dict(row) for row in cursor.fetchall()]
                    
                    # 11. OVERALL STATISTICS
                    cursor.execute('''
                        SELECT 
                            COUNT(*) as total_events,
                            COUNT(DISTINCT source_ip) as unique_sources,
                            COUNT(DISTINCT user) as unique_users,
                            SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical_events,
                            SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) as high_events,
                            COUNT(DISTINCT event_type) as unique_event_types
                        FROM log_entries
                        WHERE timestamp > datetime('now', '-7 days')
                    ''')
                    overall_stats = dict(cursor.fetchone())
                    
                    # 12. ALERT COUNTS BY STATUS
                    cursor.execute('''
                        SELECT status, COUNT(*) as count,
                               SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical
                        FROM alerts
                        WHERE created_at > datetime('now', '-7 days')
                        GROUP BY status
                    ''')
                    alert_status = [dict(row) for row in cursor.fetchall()]
                    
                    # 13. TOP THREATS (by frequency)
                    cursor.execute('''
                        SELECT ttp_match as threat, COUNT(*) as frequency,
                               SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical_count,
                               MAX(timestamp) as last_occurrence
                        FROM log_entries
                        WHERE ttp_match IS NOT NULL AND ttp_match != ''
                        GROUP BY ttp_match
                        ORDER BY frequency DESC
                        LIMIT 10
                    ''')
                    top_threats = [dict(row) for row in cursor.fetchall()]
                
                context = self._get_base_context()
                context.update({
                    'trends': json.dumps(trends[:12]),
                    'severity_dist': severity_dist,
                    'source_dist': source_dist,
                    'event_dist': event_dist,
                    'user_activity': user_activity,
                    'ttp_mapping': ttp_mapping,
                    'hourly_dist': hourly_dist,
                    'daily_stats': daily_stats,
                    'alert_timeline': json.dumps(alert_timeline),
                    'source_dest': source_dest,
                    'overall_stats': overall_stats,
                    'alert_status': alert_status,
                    'top_threats': top_threats,
                })
                
                return self._render_template('analytics.html', **context)
            except Exception as e:
                flash(f'Error loading analytics: {str(e)}', 'danger')
                return redirect(url_for('dashboard'))
        
        @self.app.route('/ioc_detection')
        def ioc_detection():
            """IOC (Indicators of Compromise) Detection Dashboard - Real-time Behavioral Analysis"""
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # 1. DYNAMIC MALICIOUS IP DETECTION - Behavioral Analysis
                    # Calculate threat score based on multiple behavioral factors
                    cursor.execute('''
                        WITH ip_behavior AS (
                            SELECT 
                                source_ip,
                                COUNT(*) as total_events,
                                COUNT(*) as occurrences,
                                COUNT(DISTINCT event_type) as unique_event_types,
                                COUNT(DISTINCT dest_ip) as unique_destinations,
                                COUNT(DISTINCT strftime('%H', timestamp)) as active_hours,
                                SUM(CASE WHEN severity='CRITICAL' THEN 10 
                                    WHEN severity='HIGH' THEN 5 
                                    WHEN severity='MEDIUM' THEN 2 ELSE 1 END) as severity_score,
                                COUNT(DISTINCT user) as unique_users,
                                MIN(timestamp) as first_seen,
                                MAX(timestamp) as last_seen,
                                GROUP_CONCAT(DISTINCT severity) as severities,
                                GROUP_CONCAT(DISTINCT event_type) as event_types,
                                SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical_count,
                                SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) as high_count
                            FROM log_entries
                            WHERE source_ip IS NOT NULL
                                AND timestamp > datetime('now', '-7 days')
                            GROUP BY source_ip
                        )
                        SELECT *,
                               (severity_score * 0.4 + 
                                total_events * 0.1 + 
                                unique_event_types * 5 + 
                                unique_destinations * 2 +
                                (CASE WHEN active_hours > 20 THEN 20 ELSE 0 END)) as threat_score,
                               CASE 
                                   WHEN critical_count > 5 OR severity_score > 100 THEN 'CRITICAL'
                                   WHEN high_count > 10 OR severity_score > 50 THEN 'HIGH'
                                   WHEN total_events > 100 THEN 'MEDIUM'
                                   ELSE 'LOW'
                               END as threat_level
                        FROM ip_behavior
                        WHERE total_events > 10 OR severity_score > 20
                        ORDER BY threat_score DESC
                        LIMIT 50
                    ''')
                    malicious_ips = [dict(row) for row in cursor.fetchall()]
                    
                    # 2. REAL-TIME SUSPICIOUS URL/DOMAIN EXTRACTION
                    # Extract URLs from messages and analyze patterns
                    cursor.execute('''
                        WITH url_patterns AS (
                            SELECT 
                                message,
                                source_name,
                                source_ip,
                                timestamp,
                                severity,
                                CASE 
                                    WHEN message LIKE '%http://%' THEN substr(message, instr(message, 'http://'), 100)
                                    WHEN message LIKE '%https://%' THEN substr(message, instr(message, 'https://'), 100)
                                    ELSE NULL
                                END as extracted_url,
                                CASE
                                    WHEN message LIKE '%:80%' OR message LIKE '%:443%' THEN 0
                                    WHEN message LIKE '%:8080%' OR message LIKE '%:8443%' OR message LIKE '%:4444%' THEN 5
                                    WHEN message LIKE '%:3389%' OR message LIKE '%:22%' THEN 3
                                    ELSE 0
                                END as suspicious_port_score
                            FROM log_entries
                            WHERE (message LIKE '%http://%' OR message LIKE '%https://%' OR message LIKE '%.com%' OR message LIKE '%.net%')
                                AND timestamp > datetime('now', '-7 days')
                        )
                        SELECT *,
                               LENGTH(extracted_url) - LENGTH(REPLACE(extracted_url, '/', '')) as url_depth,
                               CASE
                                   WHEN extracted_url LIKE '%.onion%' THEN 10
                                   WHEN extracted_url LIKE '%bit.ly%' OR extracted_url LIKE '%tinyurl%' THEN 7
                                   WHEN extracted_url LIKE '%pastebin%' OR extracted_url LIKE '%paste.%' THEN 6
                                   WHEN suspicious_port_score > 0 THEN suspicious_port_score
                                   WHEN severity IN ('CRITICAL', 'HIGH') THEN 5
                                   ELSE 1
                               END as url_risk_score
                        FROM url_patterns
                        WHERE extracted_url IS NOT NULL
                        ORDER BY url_risk_score DESC, timestamp DESC
                        LIMIT 50
                    ''')
                    suspicious_urls = [dict(row) for row in cursor.fetchall()]
                    
                    # 3. DYNAMIC FILE HASH EXTRACTION AND ANALYSIS
                    cursor.execute('''
                        WITH hash_patterns AS (
                            SELECT 
                                message,
                                source_name,
                                source_ip,
                                timestamp,
                                severity,
                                CASE
                                    WHEN message LIKE '%md5%:%' THEN substr(message, instr(lower(message), 'md5'), 40)
                                    WHEN message LIKE '%sha256%:%' THEN substr(message, instr(lower(message), 'sha256'), 70)
                                    WHEN message LIKE '%sha1%:%' THEN substr(message, instr(lower(message), 'sha1'), 50)
                                    ELSE NULL
                                END as hash_value,
                                CASE
                                    WHEN message LIKE '%md5%' THEN 'MD5'
                                    WHEN message LIKE '%sha256%' THEN 'SHA256'
                                    WHEN message LIKE '%sha1%' THEN 'SHA1'
                                    ELSE 'UNKNOWN'
                                END as hash_type
                            FROM log_entries
                            WHERE (message LIKE '%md5%' OR message LIKE '%sha%' OR message LIKE '%hash%')
                                AND timestamp > datetime('now', '-7 days')
                        )
                        SELECT *, 
                               COUNT(*) OVER (PARTITION BY hash_value) as hash_frequency
                        FROM hash_patterns
                        WHERE hash_value IS NOT NULL
                        ORDER BY severity DESC, timestamp DESC
                        LIMIT 30
                    ''')
                    file_hashes = [dict(row) for row in cursor.fetchall()]
                    
                    # 4. INTELLIGENT PORT SCANNING DETECTION
                    # Detect rapid connections to multiple ports or services
                    cursor.execute('''
                        WITH port_activity AS (
                            SELECT 
                                source_ip,
                                dest_ip,
                                strftime('%Y-%m-%d %H:%M', timestamp) as time_window,
                                COUNT(DISTINCT CASE 
                                    WHEN message LIKE '%port%' OR message LIKE '%:%' 
                                    THEN substr(message, -10, 5) 
                                END) as unique_patterns,
                                COUNT(DISTINCT CASE 
                                    WHEN message LIKE '%port%' OR message LIKE '%:%' 
                                    THEN substr(message, -10, 5) 
                                END) as unique_ports,
                                COUNT(*) as total_attempts,
                                MIN(timestamp) as first_seen,
                                MAX(timestamp) as last_seen,
                                (julianday(MAX(timestamp)) - julianday(MIN(timestamp))) * 86400 as duration_seconds
                            FROM log_entries
                            WHERE source_ip IS NOT NULL
                                AND timestamp > datetime('now', '-24 hours')
                            GROUP BY source_ip, dest_ip, time_window
                        )
                        SELECT *,
                               CASE
                                   WHEN unique_patterns > 20 AND duration_seconds < 60 THEN 'CRITICAL'
                                   WHEN unique_patterns > 10 AND duration_seconds < 300 THEN 'HIGH'
                                   WHEN unique_patterns > 5 THEN 'MEDIUM'
                                   ELSE 'LOW'
                               END as scan_severity,
                               ROUND(unique_patterns / NULLIF(duration_seconds, 0) * 60, 2) as scan_rate_per_minute
                        FROM port_activity
                        WHERE unique_patterns >= 5
                        ORDER BY unique_patterns DESC, duration_seconds ASC
                        LIMIT 30
                    ''')
                    port_scans = [dict(row) for row in cursor.fetchall()]
                    
                    # 5. BEHAVIORAL BRUTE FORCE DETECTION
                    # Detect authentication failures with timing analysis
                    cursor.execute('''
                        WITH auth_failures AS (
                            SELECT 
                                source_ip,
                                COALESCE(user, 'unknown') as user,
                                COUNT(*) as attempts,
                                MIN(timestamp) as first_attempt,
                                MAX(timestamp) as last_attempt,
                                (julianday(MAX(timestamp)) - julianday(MIN(timestamp))) * 86400 as duration_seconds,
                                COUNT(DISTINCT user) as unique_users_targeted,
                                GROUP_CONCAT(DISTINCT event_type) as event_types
                            FROM log_entries
                            WHERE (message LIKE '%fail%' AND (message LIKE '%login%' OR message LIKE '%auth%'))
                                OR (message LIKE '%denied%' AND message LIKE '%access%')
                                OR (message LIKE '%invalid%' AND (message LIKE '%password%' OR message LIKE '%credentials%'))
                                OR severity IN ('HIGH', 'CRITICAL')
                            GROUP BY source_ip, user
                        )
                        SELECT *,
                               ROUND(attempts / NULLIF(duration_seconds, 0) * 60, 2) as attempts_per_minute,
                               CASE
                                   WHEN attempts > 50 THEN 'CRITICAL'
                                   WHEN attempts > 20 OR unique_users_targeted > 5 THEN 'HIGH'
                                   WHEN attempts > 10 THEN 'MEDIUM'
                                   ELSE 'LOW'
                               END as attack_severity
                        FROM auth_failures
                        WHERE attempts >= 5
                        ORDER BY attempts DESC, duration_seconds ASC
                        LIMIT 30
                    ''')
                    brute_force = [dict(row) for row in cursor.fetchall()]
                    
                    # 6. DATA EXFILTRATION BEHAVIORAL ANALYSIS
                    cursor.execute('''
                        WITH transfer_patterns AS (
                            SELECT 
                                source_ip,
                                dest_ip,
                                COUNT(*) as transfer_count,
                                SUM(CASE WHEN message LIKE '%upload%' OR message LIKE '%PUT%' OR message LIKE '%POST%' THEN 1 ELSE 0 END) as upload_count,
                                SUM(CASE WHEN message LIKE '%download%' OR message LIKE '%GET%' THEN 1 ELSE 0 END) as download_count,
                                GROUP_CONCAT(DISTINCT substr(message, 1, 100)) as patterns,
                                MIN(timestamp) as first_transfer,
                                MAX(timestamp) as last_transfer,
                                COUNT(DISTINCT strftime('%H', timestamp)) as active_hours
                            FROM log_entries
                            WHERE (message LIKE '%transfer%' OR message LIKE '%upload%' OR message LIKE '%download%'
                                   OR message LIKE '%scp%' OR message LIKE '%ftp%' OR message LIKE '%sftp%'
                                   OR message LIKE '%http%' OR message LIKE '%curl%' OR message LIKE '%wget%')
                                AND timestamp > datetime('now', '-7 days')
                            GROUP BY source_ip, dest_ip
                        )
                        SELECT *,
                               CASE
                                   WHEN upload_count > 20 AND active_hours > 12 THEN 'CRITICAL'
                                   WHEN upload_count > 10 THEN 'HIGH'
                                   WHEN transfer_count > 50 THEN 'MEDIUM'
                                   ELSE 'LOW'
                               END as exfiltration_risk
                        FROM transfer_patterns
                        WHERE transfer_count > 5
                        ORDER BY upload_count DESC, transfer_count DESC
                        LIMIT 30
                    ''')
                    exfiltration = [dict(row) for row in cursor.fetchall()]
                    
                    # 7. DYNAMIC MALWARE SIGNATURE DETECTION
                    # Pattern-based detection using actual log content
                    cursor.execute('''
                        WITH malware_indicators AS (
                            SELECT 
                                message,
                                source_name,
                                source_ip,
                                timestamp,
                                severity,
                                CASE
                                    WHEN message LIKE '%ransom%' OR message LIKE '%encrypt%files%' THEN 'Ransomware'
                                    WHEN message LIKE '%trojan%' OR message LIKE '%backdoor%' THEN 'Trojan/Backdoor'
                                    WHEN message LIKE '%worm%' OR message LIKE '%spread%' THEN 'Worm'
                                    WHEN message LIKE '%keylog%' OR message LIKE '%capture%keystroke%' THEN 'Keylogger'
                                    WHEN message LIKE '%rootkit%' OR message LIKE '%privilege%escal%' THEN 'Rootkit'
                                    WHEN message LIKE '%botnet%' OR message LIKE '%c2%' OR message LIKE '%command%control%' THEN 'Botnet/C2'
                                    WHEN message LIKE '%malware%' OR message LIKE '%virus%' OR message LIKE '%malicious%' THEN 'Generic Malware'
                                    WHEN message LIKE '%suspicious%file%' OR message LIKE '%unknown%process%' THEN 'Suspicious Activity'
                                    ELSE 'Unknown Threat'
                                END as malware_type,
                                CASE
                                    WHEN severity = 'CRITICAL' THEN 10
                                    WHEN severity = 'HIGH' THEN 7
                                    WHEN severity = 'MEDIUM' THEN 4
                                    ELSE 2
                                END as risk_score
                            FROM log_entries
                            WHERE (message LIKE '%malware%' OR message LIKE '%virus%' OR message LIKE '%trojan%'
                                   OR message LIKE '%ransom%' OR message LIKE '%worm%' OR message LIKE '%rootkit%'
                                   OR message LIKE '%keylog%' OR message LIKE '%botnet%' OR message LIKE '%suspicious%'
                                   OR message LIKE '%malicious%' OR message LIKE '%infected%')
                                AND timestamp > datetime('now', '-7 days')
                        )
                        SELECT *, COUNT(*) OVER (PARTITION BY malware_type) as type_frequency
                        FROM malware_indicators
                        ORDER BY risk_score DESC, timestamp DESC
                        LIMIT 50
                    ''')
                    malware_signatures = [dict(row) for row in cursor.fetchall()]
                    
                    # 8. DYNAMIC IOC STATISTICS
                    cursor.execute('''
                        SELECT 
                            COUNT(DISTINCT source_ip) as unique_malicious_ips,
                            COUNT(DISTINCT CASE WHEN message LIKE '%http%' OR message LIKE '%.com%' THEN source_ip END) as suspicious_url_count,
                            SUM(CASE WHEN message LIKE '%fail%' AND message LIKE '%login%' THEN 1 ELSE 0 END) as failed_login_attempts,
                            SUM(CASE WHEN message LIKE '%malware%' OR message LIKE '%virus%' OR message LIKE '%trojan%' THEN 1 ELSE 0 END) as malware_detections,
                            AVG(CASE WHEN severity='CRITICAL' THEN 10 WHEN severity='HIGH' THEN 5 ELSE 1 END) as avg_severity_score
                        FROM log_entries
                        WHERE timestamp > datetime('now', '-7 days')
                    ''')
                    ioc_stats = dict(cursor.fetchone())
                
                context = self._get_base_context()
                context.update({
                    'malicious_ips': malicious_ips,
                    'suspicious_urls': suspicious_urls,
                    'file_hashes': file_hashes,
                    'port_scans': port_scans,
                    'brute_force': brute_force,
                    'exfiltration': exfiltration,
                    'malware_signatures': malware_signatures,
                    'ioc_stats': ioc_stats,
                })
                
                return self._render_template('ioc_detection.html', **context)
            except Exception as e:
                flash(f'Error loading IOC detection: {str(e)}', 'danger')
                return redirect(url_for('dashboard'))
        
        @self.app.route('/ttp_detection')
        def ttp_detection():
            """TTP (Tactics, Techniques, and Procedures) Detection - Real-time MITRE ATT&CK Analysis"""
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # 1. DYNAMIC TTP DETECTION WITH BEHAVIORAL SCORING
                    cursor.execute('''
                        WITH ttp_analysis AS (
                            SELECT 
                                ttp_match,
                                COUNT(*) as detection_count,
                                COUNT(DISTINCT source_ip) as unique_sources,
                                COUNT(DISTINCT dest_ip) as unique_targets,
                                GROUP_CONCAT(DISTINCT source_ip) as source_ips,
                                GROUP_CONCAT(DISTINCT source_name) as sources,
                                MIN(timestamp) as first_detected,
                                MAX(timestamp) as last_detected,
                                SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical_detections,
                                SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) as high_detections,
                                (julianday(MAX(timestamp)) - julianday(MIN(timestamp))) * 24 as duration_hours,
                                COUNT(DISTINCT strftime('%Y-%m-%d', timestamp)) as active_days
                            FROM log_entries
                            WHERE ttp_match IS NOT NULL AND ttp_match != ''
                                AND timestamp > datetime('now', '-30 days')
                            GROUP BY ttp_match
                        )
                        SELECT *,
                               ROUND(detection_count / NULLIF(duration_hours, 0), 2) as detections_per_hour,
                               CASE
                                   WHEN critical_detections > 10 THEN 'CRITICAL'
                                   WHEN high_detections > 20 OR detection_count > 100 THEN 'HIGH'
                                   WHEN detection_count > 50 THEN 'MEDIUM'
                                   ELSE 'LOW'
                               END as ttp_severity,
                               (detection_count * 0.3 + 
                                unique_sources * 5 + 
                                unique_targets * 3 + 
                                critical_detections * 10 +
                                high_detections * 5) as ttp_threat_score
                        FROM ttp_analysis
                        ORDER BY ttp_threat_score DESC, detection_count DESC
                    ''')
                    ttp_detections = [dict(row) for row in cursor.fetchall()]
                    
                    # 2. REAL-TIME TTP ACTIVITY WITH CONTEXT
                    cursor.execute('''
                        SELECT 
                            timestamp,
                            ttp_match,
                            message,
                            source_name,
                            source_ip,
                            dest_ip,
                            user,
                            severity,
                            event_type,
                            CASE
                                WHEN LAG(ttp_match) OVER (PARTITION BY source_ip ORDER BY timestamp) = ttp_match 
                                THEN 'REPEATED'
                                ELSE 'NEW'
                            END as pattern_type
                        FROM log_entries
                        WHERE ttp_match IS NOT NULL AND ttp_match != ''
                            AND timestamp > datetime('now', '-48 hours')
                        ORDER BY timestamp DESC
                        LIMIT 100
                    ''')
                    recent_ttps = [dict(row) for row in cursor.fetchall()]
                    
                    # 3. INTELLIGENT TTP CORRELATION (Temporal and Spatial)
                    cursor.execute('''
                        WITH ttp_pairs AS (
                            SELECT 
                                l1.ttp_match as ttp1,
                                l2.ttp_match as ttp2,
                                COUNT(*) as correlation_count,
                                AVG(ABS(strftime('%s', l1.timestamp) - strftime('%s', l2.timestamp))) as avg_time_delta,
                                COUNT(DISTINCT l1.source_ip) as unique_attackers,
                                MIN(l1.timestamp) as first_correlation,
                                MAX(l2.timestamp) as last_correlation
                            FROM log_entries l1
                            JOIN log_entries l2 
                                ON l1.source_ip = l2.source_ip 
                                AND l1.id < l2.id
                                AND ABS(strftime('%s', l1.timestamp) - strftime('%s', l2.timestamp)) < 600
                            WHERE l1.ttp_match IS NOT NULL 
                                AND l2.ttp_match IS NOT NULL
                                AND l1.ttp_match != l2.ttp_match
                                AND l1.timestamp > datetime('now', '-7 days')
                            GROUP BY l1.ttp_match, l2.ttp_match
                        )
                        SELECT *,
                               CASE
                                   WHEN avg_time_delta < 60 THEN 'IMMEDIATE'
                                   WHEN avg_time_delta < 300 THEN 'RAPID'
                                   ELSE 'DELAYED'
                               END as correlation_timing,
                               CASE
                                   WHEN correlation_count > 20 THEN 'STRONG'
                                   WHEN correlation_count > 10 THEN 'MODERATE'
                                   ELSE 'WEAK'
                               END as correlation_strength
                        FROM ttp_pairs
                        WHERE correlation_count >= 3
                        ORDER BY correlation_count DESC, avg_time_delta ASC
                        LIMIT 50
                    ''')
                    ttp_correlations = [dict(row) for row in cursor.fetchall()]
                    
                    # 4. ATTACK CHAIN RECONSTRUCTION
                    cursor.execute('''
                        WITH ordered_ttps AS (
                            SELECT 
                                source_ip,
                                ttp_match,
                                timestamp,
                                message,
                                severity,
                                ROW_NUMBER() OVER (PARTITION BY source_ip ORDER BY timestamp) as sequence_num
                            FROM log_entries
                            WHERE ttp_match IS NOT NULL 
                                AND source_ip IS NOT NULL
                                AND timestamp > datetime('now', '-7 days')
                        )
                        SELECT 
                            source_ip,
                            GROUP_CONCAT(ttp_match || ' (' || strftime('%H:%M:%S', timestamp) || ')', ' → ') as attack_chain,
                            COUNT(DISTINCT ttp_match) as ttp_count,
                            COUNT(*) as total_events,
                            MIN(timestamp) as chain_start,
                            MAX(timestamp) as chain_end,
                            (julianday(MAX(timestamp)) - julianday(MIN(timestamp))) * 86400 as chain_duration_seconds,
                            SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical_in_chain,
                            GROUP_CONCAT(DISTINCT severity) as severities_in_chain
                        FROM ordered_ttps
                        GROUP BY source_ip
                        HAVING ttp_count >= 2
                        ORDER BY ttp_count DESC, chain_duration_seconds ASC
                        LIMIT 20
                    ''')
                    attack_chains = [dict(row) for row in cursor.fetchall()]
                    
                    # 5. TTP SEVERITY MATRIX WITH TREND ANALYSIS
                    cursor.execute('''
                        WITH ttp_severity_trends AS (
                            SELECT 
                                severity,
                                ttp_match,
                                COUNT(*) as count,
                                strftime('%Y-%m-%d', timestamp) as detection_date,
                                COUNT(*) - LAG(COUNT(*)) OVER (
                                    PARTITION BY ttp_match, severity 
                                    ORDER BY strftime('%Y-%m-%d', timestamp)
                                ) as daily_change
                            FROM log_entries
                            WHERE ttp_match IS NOT NULL
                                AND timestamp > datetime('now', '-7 days')
                            GROUP BY severity, ttp_match, detection_date
                        )
                        SELECT 
                            severity,
                            ttp_match,
                            SUM(count) as total_count,
                            AVG(count) as avg_daily_count,
                            MAX(count) as peak_daily_count,
                            SUM(CASE WHEN daily_change > 0 THEN daily_change ELSE 0 END) as increasing_trend,
                            CASE
                                WHEN AVG(daily_change) > 5 THEN 'ESCALATING'
                                WHEN AVG(daily_change) > 0 THEN 'INCREASING'
                                WHEN AVG(daily_change) < -5 THEN 'DECLINING'
                                ELSE 'STABLE'
                            END as trend_status
                        FROM ttp_severity_trends
                        GROUP BY severity, ttp_match
                        ORDER BY 
                            CASE severity 
                                WHEN 'CRITICAL' THEN 1 
                                WHEN 'HIGH' THEN 2 
                                WHEN 'MEDIUM' THEN 3 
                                ELSE 4 
                            END,
                            total_count DESC
                    ''')
                    ttp_by_severity = [dict(row) for row in cursor.fetchall()]
                    
                    # 6. TARGETED ASSET ANALYSIS WITH ATTACK PROFILE
                    cursor.execute('''
                        WITH asset_attacks AS (
                            SELECT 
                                dest_ip,
                                COUNT(DISTINCT ttp_match) as unique_ttps,
                                COUNT(*) as total_attacks,
                                COUNT(DISTINCT source_ip) as unique_attackers,
                                GROUP_CONCAT(DISTINCT ttp_match) as attack_techniques,
                                MIN(timestamp) as first_attack,
                                MAX(timestamp) as last_attack,
                                SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical_attacks,
                                COUNT(DISTINCT strftime('%Y-%m-%d', timestamp)) as attack_days
                            FROM log_entries
                            WHERE ttp_match IS NOT NULL 
                                AND dest_ip IS NOT NULL
                                AND timestamp > datetime('now', '-7 days')
                            GROUP BY dest_ip
                        )
                        SELECT *,
                               ROUND(total_attacks / NULLIF(attack_days, 0), 2) as attacks_per_day,
                               CASE
                                   WHEN unique_ttps >= 10 AND critical_attacks > 5 THEN 'CRITICAL'
                                   WHEN unique_ttps >= 5 OR critical_attacks > 2 THEN 'HIGH'
                                   WHEN unique_ttps >= 3 THEN 'MEDIUM'
                                   ELSE 'LOW'
                               END as asset_risk_level
                        FROM asset_attacks
                        ORDER BY unique_ttps DESC, total_attacks DESC
                        LIMIT 30
                    ''')
                    targeted_assets = [dict(row) for row in cursor.fetchall()]
                    
                    # 7. ATTACK VELOCITY AND INTENSITY ANALYSIS
                    cursor.execute('''
                        SELECT 
                            strftime('%Y-%m-%d %H:00', timestamp) as hour,
                            COUNT(DISTINCT ttp_match) as unique_ttps,
                            COUNT(*) as total_detections,
                            COUNT(DISTINCT source_ip) as unique_sources,
                            SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical_events,
                            GROUP_CONCAT(DISTINCT ttp_match) as ttps_detected,
                            CASE
                                WHEN COUNT(DISTINCT ttp_match) > 10 THEN 'HIGH INTENSITY'
                                WHEN COUNT(DISTINCT ttp_match) > 5 THEN 'MODERATE'
                                ELSE 'LOW'
                            END as attack_intensity
                        FROM log_entries
                        WHERE ttp_match IS NOT NULL 
                            AND timestamp > datetime('now', '-24 hours')
                        GROUP BY hour
                        ORDER BY hour DESC
                    ''')
                    attack_velocity = [dict(row) for row in cursor.fetchall()]
                    
                    # 8. COMPREHENSIVE TTP STATISTICS WITH TRENDS
                    cursor.execute('''
                        SELECT 
                            COUNT(DISTINCT ttp_match) as unique_ttps,
                            COUNT(*) as total_ttp_detections,
                            COUNT(DISTINCT source_ip) as attacking_ips,
                            COUNT(DISTINCT dest_ip) as targeted_assets,
                            ROUND(AVG(CASE WHEN severity='CRITICAL' THEN 10 
                                          WHEN severity='HIGH' THEN 5 
                                          ELSE 1 END), 2) as avg_severity_score,
                            SUM(CASE WHEN timestamp > datetime('now', '-24 hours') THEN 1 ELSE 0 END) as last_24h_detections,
                            SUM(CASE WHEN timestamp BETWEEN datetime('now', '-48 hours') AND datetime('now', '-24 hours') THEN 1 ELSE 0 END) as previous_24h_detections
                        FROM log_entries
                        WHERE ttp_match IS NOT NULL
                            AND timestamp > datetime('now', '-7 days')
                    ''')
                    ttp_stats_raw = dict(cursor.fetchone())
                    
                    # Calculate trend
                    ttp_stats = ttp_stats_raw.copy()
                    if ttp_stats_raw['previous_24h_detections'] and ttp_stats_raw['previous_24h_detections'] > 0:
                        trend = ((ttp_stats_raw['last_24h_detections'] - ttp_stats_raw['previous_24h_detections']) / 
                                ttp_stats_raw['previous_24h_detections'] * 100)
                        ttp_stats['trend_percentage'] = round(trend, 1)
                        ttp_stats['trend_direction'] = 'UP' if trend > 0 else 'DOWN' if trend < 0 else 'STABLE'
                    else:
                        ttp_stats['trend_percentage'] = 0
                        ttp_stats['trend_direction'] = 'STABLE'
                    
                    # Map TTP detections to MITRE ATT&CK framework metadata
                    for ttp in ttp_detections:
                        ttp_id = ttp['ttp_match'].split(':')[0].strip() if ttp['ttp_match'] else ''
                        # Find matching playbooks
                        ttp['playbooks'] = [pb for pb in PLAYBOOKS if any(m in ttp_id for m in pb.get('mitre', []))]
                
                context = self._get_base_context()
                context.update({
                    'ttp_detections': ttp_detections,
                    'recent_ttps': recent_ttps,
                    'ttp_correlations': ttp_correlations,
                    'attack_chains': attack_chains,
                    'ttp_by_severity': ttp_by_severity,
                    'targeted_assets': targeted_assets,
                    'attack_velocity': json.dumps(attack_velocity),
                    'ttp_stats': ttp_stats,
                })
                
                return self._render_template('ttp_detection.html', **context)
            except Exception as e:
                flash(f'Error loading TTP detection: {str(e)}', 'danger')
                return redirect(url_for('dashboard'))
        
        # ========================================
        # NEW: ADVANCED ADMIN ENDPOINTS
        # ========================================
        
        @self.app.route('/api/admin/users', methods=['GET', 'POST'])
        def api_users() -> ResponseReturnValue:
            """Manage users with real database operations"""
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            # Check if admin
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],))
                user = cursor.fetchone()
                if not user or user['role'] != 'admin':
                    return jsonify({'error': 'Admin access required'}), 403
            
            if request.method == 'GET':
                # List all users with activity
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT id, username, email, role, last_login, created_at
                        FROM users
                        ORDER BY created_at DESC
                    ''')
                    users = [dict(row) for row in cursor.fetchall()]
                return jsonify({'success': True, 'users': users})
            
            elif request.method == 'POST':
                data = request.get_json()
                action = data.get('action')
                
                if action == 'create':
                    username = data.get('username', '').strip()
                    email = data.get('email', '').strip()
                    password = data.get('password', '').strip()
                    role = data.get('role', 'analyst')
                    
                    if not all([username, email, password]):
                        return jsonify({'error': 'Missing required fields'}), 400
                    
                    try:
                        with self.db.get_connection() as conn:
                            cursor = conn.cursor()
                            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
                            if cursor.fetchone():
                                return jsonify({'error': 'Username already exists'}), 400
                            
                            hashed = generate_password_hash(password)
                            cursor.execute('''
                                INSERT INTO users (username, email, password_hash, role)
                                VALUES (?, ?, ?, ?)
                            ''', (username, email, hashed, role))
                            conn.commit()
                        return jsonify({'success': True, 'message': 'User created'})
                    except Exception as e:
                        return jsonify({'error': str(e)}), 500
                
                if action == 'update_role':
                    user_id = data.get('user_id')
                    new_role = data.get('role')
                    
                    try:
                        with self.db.get_connection() as conn:
                            cursor = conn.cursor()
                            cursor.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
                            conn.commit()
                        return jsonify({'success': True, 'message': 'User role updated'})
                    except Exception as e:
                        return jsonify({'error': str(e)}), 500

                if action == 'delete':
                    user_id = data.get('user_id')
                    if user_id == session['user_id']:
                        return jsonify({'error': 'Cannot delete yourself'}), 400
                    
                    try:
                        with self.db.get_connection() as conn:
                            cursor = conn.cursor()
                            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
                            conn.commit()
                        return jsonify({'success': True, 'message': 'User deleted'})
                    except Exception as e:
                        return jsonify({'error': str(e)}), 500

                return jsonify({'error': 'Invalid action'}), 400

            return jsonify({'error': 'Method not allowed'}), 405
        
        @self.app.route('/api/admin/database', methods=['GET', 'POST'])
        def api_database() -> ResponseReturnValue:
            """Database management endpoints"""
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            # Verify admin
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],))
                user = cursor.fetchone()
                if not user or user['role'] != 'admin':
                    return jsonify({'error': 'Admin access required'}), 403
            
            if request.method == 'GET':
                try:
                    with self.db.get_connection() as conn:
                        cursor = conn.cursor()
                        
                        # Get database stats
                        cursor.execute('SELECT COUNT(*) as count FROM log_entries')
                        log_count = cursor.fetchone()['count']
                        
                        cursor.execute('SELECT COUNT(*) as count FROM alerts')
                        alert_count = cursor.fetchone()['count']
                        
                        cursor.execute('SELECT COUNT(*) as count FROM users')
                        user_count = cursor.fetchone()['count']
                        
                        # Get database file size
                        db_path = self.db.db_path
                        db_size = os.path.getsize(db_path) if os.path.exists(db_path) else 0
                        
                        return jsonify({
                            'success': True,
                            'stats': {
                                'log_entries': log_count,
                                'alerts': alert_count,
                                'users': user_count,
                                'database_size_mb': db_size / (1024*1024),
                                'database_path': db_path
                            }
                        })
                except Exception as e:
                    return jsonify({'error': str(e)}), 500
            
            elif request.method == 'POST':
                action = request.get_json().get('action')
                
                if action == 'backup':
                    try:
                        import shutil
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        backup_name = f"backup_{timestamp}.db"
                        backup_path = os.path.join('backups', backup_name)
                        os.makedirs('backups', exist_ok=True)
                        
                        shutil.copy2(self.db.db_path, backup_path)
                        return jsonify({'success': True, 'backup_file': backup_name})
                    except Exception as e:
                        return jsonify({'error': str(e)}), 500
                
                elif action == 'optimize':
                    try:
                        with self.db.get_connection() as conn:
                            conn.execute('VACUUM')
                            conn.execute('ANALYZE')
                            conn.commit()
                        return jsonify({'success': True, 'message': 'Database optimized'})
                    except Exception as e:
                        return jsonify({'error': str(e)}), 500
                
                elif action == 'clear_old_logs':
                    try:
                        days = int(request.get_json().get('days', 30))
                        with self.db.get_connection() as conn:
                            cursor = conn.cursor()
                            # Delete logs older than specified days
                            cutoff = datetime.now() - timedelta(days=days)
                            cursor.execute('''
                                DELETE FROM log_entries 
                                WHERE timestamp < ?
                            ''', (cutoff.isoformat(),))
                            deleted = cursor.rowcount
                            conn.commit()
                        return jsonify({'success': True, 'deleted': deleted})
                    except Exception as e:
                        return jsonify({'error': str(e)}), 500
                
                return jsonify({'error': 'Invalid action'}), 400

            return jsonify({'error': 'Method not allowed'}), 405
        
        @self.app.route('/api/admin/settings', methods=['GET', 'POST'])
        def api_settings() -> ResponseReturnValue:
            """System settings management"""
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],))
                user = cursor.fetchone()
                if not user or user['role'] != 'admin':
                    return jsonify({'error': 'Admin access required'}), 403
            
            if request.method == 'GET':
                try:
                    with self.db.get_connection() as conn:
                        cursor = conn.cursor()
                        cursor.execute('SELECT key, value FROM settings')
                        settings_dict = {row['key']: row['value'] for row in cursor.fetchall()}
                    return jsonify({'success': True, 'settings': settings_dict})
                except Exception as e:
                    return jsonify({'error': str(e)}), 500

            if request.method == 'POST':
                try:
                    data = request.get_json() or {}
                    requested_playbook_type = data.get('active_playbook_type')

                    with self.db.get_connection() as conn:
                        cursor = conn.cursor()
                        for key, value in data.items():
                            cursor.execute('''
                                INSERT OR REPLACE INTO settings (key, value)
                                VALUES (?, ?)
                            ''', (key, str(value)))
                        conn.commit()
                    if requested_playbook_type is not None:
                        try:
                            self._apply_playbook_selection(requested_playbook_type)
                        except Exception as e:
                            return jsonify({'error': f'Failed to apply playbook selection: {e}'}), 400

                    return jsonify({
                        'success': True,
                        'message': 'Settings updated',
                        'active_playbook_type': getattr(self, 'active_playbook_type', 'all')
                    })
                except Exception as e:
                    return jsonify({'error': str(e)}), 500

            return jsonify({'error': 'Method not allowed'}), 405
        
        @self.app.route('/api/anomaly-detection', methods=['GET'])
        def api_anomaly_detection():
            """Detect anomalies in log patterns"""
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # Detect anomalies: IPs with unusual activity
                    cursor.execute('''
                        SELECT source_ip, COUNT(*) as count, 
                               GROUP_CONCAT(DISTINCT severity) as severities
                        FROM log_entries
                        WHERE source_ip IS NOT NULL
                        GROUP BY source_ip
                        HAVING count > 50
                        ORDER BY count DESC
                        LIMIT 20
                    ''')
                    ip_anomalies = [dict(row) for row in cursor.fetchall()]
                    
                    # Time-based anomalies
                    cursor.execute('''
                        SELECT strftime('%H', timestamp) as hour,
                               COUNT(*) as count,
                               AVG(CASE WHEN severity IN ('CRITICAL', 'HIGH') THEN 1 ELSE 0 END) * 100 as threat_percentage
                        FROM log_entries
                        GROUP BY hour
                        ORDER BY threat_percentage DESC
                    ''')
                    time_anomalies = [dict(row) for row in cursor.fetchall()]
                    
                    # User activity anomalies
                    cursor.execute('''
                        SELECT user, COUNT(*) as count,
                               SUM(CASE WHEN severity IN ('CRITICAL', 'HIGH') THEN 1 ELSE 0 END) as threat_events
                        FROM log_entries
                        WHERE user IS NOT NULL AND user != ''
                        GROUP BY user
                        HAVING count > 100 OR threat_events > 5
                        ORDER BY threat_events DESC
                    ''')
                    user_anomalies = [dict(row) for row in cursor.fetchall()]
                    
                    return jsonify({
                        'success': True,
                        'ip_anomalies': ip_anomalies,
                        'time_anomalies': time_anomalies,
                        'user_anomalies': user_anomalies
                    })
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/threat-intelligence', methods=['GET'])
        def api_threat_intelligence():
            """Get threat intelligence summary"""
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # Top threat patterns
                    cursor.execute('''
                        SELECT ttp_match, COUNT(*) as frequency,
                               GROUP_CONCAT(DISTINCT severity) as severities,
                               MAX(timestamp) as last_seen
                        FROM log_entries
                        WHERE ttp_match IS NOT NULL
                        GROUP BY ttp_match
                        ORDER BY frequency DESC
                        LIMIT 10
                    ''')
                    threat_patterns = [dict(row) for row in cursor.fetchall()]
                    
                    # Malicious IPs
                    cursor.execute('''
                        SELECT source_ip, COUNT(*) as event_count,
                               SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_events,
                               GROUP_CONCAT(DISTINCT ttp_match) as patterns
                        FROM log_entries
                        WHERE source_ip IS NOT NULL AND severity IN ('CRITICAL', 'HIGH')
                        GROUP BY source_ip
                        ORDER BY critical_events DESC
                        LIMIT 15
                    ''')
                    malicious_ips = [dict(row) for row in cursor.fetchall()]
                    
                    return jsonify({
                        'success': True,
                        'threat_patterns': threat_patterns,
                        'malicious_ips': malicious_ips
                    })
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/behavioral-analysis', methods=['GET'])
        def api_behavioral_analysis():
            """Get behavioral anomalies"""
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                behavioral = self.log_manager.detect_behavioral_anomalies()
                privilege_esc = self.log_manager.detect_privilege_escalation()
                lateral_mv = self.log_manager.detect_lateral_movement()
                data_exfil = self.log_manager.detect_data_exfiltration()
                
                return jsonify({
                    'success': True,
                    'behavioral_anomalies': behavioral,
                    'privilege_escalation': privilege_esc[:10],
                    'lateral_movement': lateral_mv,
                    'data_exfiltration': data_exfil[:10]
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/threat-timeline', methods=['GET'])
        def api_threat_timeline():
            """Get threat events timeline"""
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                days = request.args.get('days', 7, type=int)
                timeline = self.log_manager.get_threat_timeline(days)
                
                return jsonify({
                    'success': True,
                    'timeline': timeline
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/export/full-report', methods=['GET'])
        def api_export_full_report():
            """Export comprehensive analysis report"""
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # Get all data
                    cursor.execute('''
                        SELECT * FROM log_entries
                        ORDER BY timestamp DESC
                    ''')
                    logs = [dict(row) for row in cursor.fetchall()]
                    
                    cursor.execute('''
                        SELECT * FROM alerts
                        ORDER BY created_at DESC
                    ''')
                    alerts = [dict(row) for row in cursor.fetchall()]
                    
                    stats = self.log_manager.get_statistics()
                
                # Create comprehensive report
                report_data = {
                    'generated_at': datetime.now().isoformat(),
                    'summary': stats,
                    'logs': logs,
                    'alerts': alerts,
                    'total_records': len(logs) + len(alerts)
                }
                
                # Generate CSV export
                output = io.StringIO()
                writer = csv.writer(output)
                
                # Write summary
                writer.writerow(['LOG ANALYSIS REPORT'])
                writer.writerow(['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
                writer.writerow([])
                writer.writerow(['SUMMARY STATISTICS'])
                writer.writerow(['Total Logs', stats.get('total_logs', 0)])
                writer.writerow(['TTP Matches', stats.get('ttp_matches', 0)])
                writer.writerow([])
                writer.writerow(['LOG ENTRIES'])
                writer.writerow(['Timestamp', 'Source', 'Severity', 'Message', 'TTP Match'])
                
                for log in logs[:1000]:  # Limit to 1000 rows
                    writer.writerow([
                        log.get('timestamp', ''),
                        log.get('source_name', ''),
                        log.get('severity', ''),
                        log.get('message', '')[:100],
                        log.get('ttp_match', '')
                    ])
                
                # Return as download
                response = make_response(output.getvalue())
                response.headers['Content-Disposition'] = f'attachment; filename=report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
                response.headers['Content-Type'] = 'text/csv'
                return response
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
    
    def _start_file_watcher(self):
        """Start file watcher for real-time log monitoring."""
        try:
            # Read setting to determine whether watcher should refresh (replace) data
            refresh_on_watch = False
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT value FROM settings WHERE key = 'watcher_refresh'")
                    row = cursor.fetchone()
                    if row and str(row['value']).strip() in ('1', 'true', 'True'):
                        refresh_on_watch = True
            except Exception:
                refresh_on_watch = False

            event_handler = LogFileHandler(self.log_manager, self.upload_dir, refresh_on_watch=refresh_on_watch)
            observer = Observer()
            observer.schedule(event_handler, self.upload_dir, recursive=True)
            observer.start()
            self.file_watcher = observer
            print(f"[System] Started file watcher on {self.upload_dir}")
        except Exception as e:
            print(f"[System] Failed to start file watcher: {e}")
    
    def _get_base_context(self) -> Dict:
        """Get base template context."""
        alerts_count = 0
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'new'")
            alerts_count = cursor.fetchone()[0]
        
        return {
            'user': {
                'username': session.get('username', 'Guest'),
                'role': session.get('role', 'guest')
            },
            'alerts_count': alerts_count,
            'now': datetime.now(),
        }
    
    def _render_template(self, template_name: str, **context) -> str:
        """Render template with given context."""
        template_content = self._get_template(template_name)
        
        # Handle template inheritance manually
        if '{% extends "base.html" %}' in template_content:
            # Extract the content block
            import re
            title_match = re.search(r'{%\s*block\s+title\s*%}(.*?){%\s*endblock\s*%}', template_content, re.DOTALL)
            content_match = re.search(r'{%\s*block\s+content\s*%}(.*?){%\s*endblock\s*%}', template_content, re.DOTALL)
            scripts_match = re.search(r'{%\s*block\s+scripts\s*%}(.*?){%\s*endblock\s*%}', template_content, re.DOTALL)
            
            title = title_match.group(1).strip() if title_match else 'Dashboard'
            content = content_match.group(1).strip() if content_match else ''
            scripts = scripts_match.group(1).strip() if scripts_match else ''
            
            # Get base template and inject content
            base_template = self._get_template('base.html')
            base_template = base_template.replace('{% block title %}Dashboard{% endblock %}', title)
            base_template = base_template.replace('{% block content %}{% endblock %}', content)
            base_template = base_template.replace('{% block scripts %}{% endblock %}', scripts)
            
            return render_template_string(base_template, **context)
        else:
            return render_template_string(template_content, **context)

    @staticmethod
    def _safe_truncate(value, length: int = 50, end: str = '...') -> str:
        """Jinja filter that safely truncates any value without raising on None."""
        if value is None:
            return ''
        try:
            text = str(value)
            if len(text) <= length:
                return text
            return text[:length] + end
        except Exception:
            return ''
    
    def _get_template(self, template_name: str) -> str:
        """Get HTML template by name."""
        templates = {
            'base.html': BASE_TEMPLATE,
            'login.html': LOGIN_TEMPLATE,
            'register.html': REGISTER_TEMPLATE,
            'dashboard.html': DASHBOARD_TEMPLATE,
            'upload.html': UPLOAD_TEMPLATE,
            'logs.html': LOGS_TEMPLATE,
            'threats.html': THREATS_TEMPLATE,
            'alerts.html': ALERTS_TEMPLATE,
            'reports.html': REPORTS_TEMPLATE,
            'settings.html': SETTINGS_TEMPLATE,
            'rules.html': RULES_TEMPLATE,
            'view_rules.html': VIEW_RULES_TEMPLATE,
            'edit_playbook.html': EDIT_PLAYBOOK_TEMPLATE,
            'index.html': INDEX_TEMPLATE,
            'playbooks.html': PLAYBOOKS_TEMPLATE,
            'runbook.html': RUNBOOK_TEMPLATE,
            'analytics.html': ANALYTICS_TEMPLATE,
            'ioc_detection.html': IOC_DETECTION_TEMPLATE,
            'ttp_detection.html': TTP_DETECTION_TEMPLATE,
        }
        return templates.get(template_name, f"<h1>Template {template_name} not found</h1>")
    
    def run(self, host='0.0.0.0', port=5000, debug=True):
        """Run the application."""
        print("\n" + "="*60)
        print("    PORTABLE LOG ANALYSIS TOOL FOR ISOLATED NETWORKS")
        print("="*60)
        print("\nFeatures:")
        print("• Multi-user authentication system")
        print("• SQLite database for portability")
        print("• Multi-format log parsing (Syslog, Windows, Apache, JSON, CSV)")
        print("• MITRE ATT&CK TTP-based threat detection")
        print("• Real-time log monitoring with file watcher")
        print("• Comprehensive reporting and analytics")
        print("• Web-based interface accessible from any device")
        print("\nDefault admin credentials:")
        print("Username: admin")
        print("Password: admin123")
        print(f"\nAccess the application at: http://localhost:{port}")
        print("="*60 + "\n")
        
        self.app.run(host=host, port=port, debug=debug, use_reloader=False)

# ============================================================================
# HTML TEMPLATES
# ============================================================================

BASE_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log Analyzer - {% block title %}Dashboard{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-select@1.14.0-beta3/dist/css/bootstrap-select.min.css">
    <style>
        :root {
            --primary: #2c3e50;
            --secondary: #3498db;
            --danger: #e74c3c;
            --warning: #f39c12;
            --success: #27ae60;
            --info: #17a2b8;
            --light: #f8f9fa;
            --dark: #343a40;
        }
        
        * {
            box-sizing: border-box;
        }
        
        html, body {
            margin: 0;
            padding: 0;
            width: 100%;
            height: 100%;
            overflow-x: hidden;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f8f9fa;
        }
        
        .sidebar {
            background: linear-gradient(180deg, var(--primary), #1a252f);
            height: 100vh;
            position: fixed;
            width: 250px;
            box-shadow: 2px 0 10px rgba(0,0,0,0.1);
            z-index: 1000;
            overflow-y: auto;
            overflow-x: hidden;
        }
        
        .sidebar::-webkit-scrollbar {
            width: 6px;
        }
        
        .sidebar::-webkit-scrollbar-track {
            background: rgba(0,0,0,0.1);
        }
        
        .sidebar::-webkit-scrollbar-thumb {
            background: rgba(255,255,255,0.3);
            border-radius: 3px;
        }
        
        .sidebar-brand {
            padding: 20px;
            color: white;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        
        .sidebar-brand h4 {
            font-size: 1.2rem;
            margin: 0;
        }
        
        .sidebar-nav {
            padding: 20px 0 80px 0;
        }
        
        .nav-link {
            color: rgba(255,255,255,0.8);
            padding: 12px 20px;
            margin: 2px 10px;
            border-radius: 5px;
            transition: all 0.3s;
            display: block;
            text-decoration: none;
        }
        
        .nav-link:hover, .nav-link.active {
            background: rgba(255,255,255,0.1);
            color: white;
            text-decoration: none;
        }
        
        .nav-link i {
            width: 20px;
            margin-right: 10px;
        }
        
        .main-content {
            margin-left: 250px;
            padding: 20px;
            background: #eef1f5;
            min-height: 100vh;
            width: calc(100% - 250px);
            overflow-x: hidden;
        }
        
        .stat-card {
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            border-left: 4px solid var(--secondary);
            transition: transform 0.2s, box-shadow 0.2s;
            width: 100%;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 12px rgba(0,0,0,0.15);
        }
        
        .stat-card.critical { border-left-color: var(--danger); }
        .stat-card.high { border-left-color: var(--warning); }
        .stat-card.success { border-left-color: var(--success); }
        
        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            margin: 10px 0;
            word-break: break-word;
        }
        
        .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            display: inline-block;
            white-space: nowrap;
        }
        
        .severity-critical { background: #fee; color: var(--danger); }
        .severity-high { background: #fef6e6; color: var(--warning); }
        .severity-medium { background: #e6f7ff; color: var(--secondary); }
        .severity-low { background: #e6ffe6; color: var(--success); }
        .severity-info { background: #f0f0f0; color: #666; }
        
        .table-container {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            overflow-x: auto;
            margin-bottom: 20px;
            width: 100%;
        }
        
        .table-container h5 {
            margin-bottom: 1rem;
            color: var(--primary);
            font-weight: 600;
        }
        
        .alert-custom {
            border-radius: 10px;
            border: none;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        /* Form improvements */
        .form-control, .form-select {
            border-radius: 8px;
            border: 1px solid #ddd;
            padding: 0.6rem 1rem;
            transition: border-color 0.3s, box-shadow 0.3s;
            width: 100%;
            max-width: 100%;
        }
        
        .form-control:focus, .form-select:focus {
            border-color: var(--secondary);
            box-shadow: 0 0 0 0.2rem rgba(52, 152, 219, 0.25);
        }
        
        .form-label {
            font-weight: 500;
            color: var(--dark);
            margin-bottom: 0.5rem;
            display: block;
        }
        
        /* Button improvements */
        .btn {
            border-radius: 8px;
            padding: 0.5rem 1.5rem;
            font-weight: 500;
            transition: all 0.3s;
            white-space: nowrap;
        }
        
        .btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }
        
        /* Table improvements */
        .table {
            margin-bottom: 0;
            width: 100%;
        }
        
        .table thead th {
            background-color: var(--light);
            color: var(--dark);
            font-weight: 600;
            border-bottom: 2px solid #dee2e6;
            padding: 0.75rem;
            white-space: nowrap;
        }
        
        .table tbody tr {
            transition: background-color 0.2s;
        }
        
        .table tbody tr:hover {
            background-color: rgba(52, 152, 219, 0.05);
        }
        
        .table tbody td {
            padding: 0.75rem;
            vertical-align: middle;
        }
        
        .table-responsive {
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
        }
        
        /* Custom Rules specific styles */
        .rule-form-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 20px;
        }
        
        .rule-form-card .form-label {
            color: white;
            font-weight: 500;
        }
        
        .rule-form-card .form-control,
        .rule-form-card .form-select,
        .rule-form-card textarea {
            background: rgba(255, 255, 255, 0.95);
            border: 1px solid rgba(255, 255, 255, 0.3);
        }
        
        .rule-form-card .form-control:focus,
        .rule-form-card .form-select:focus,
        .rule-form-card textarea:focus {
            background: white;
            border-color: white;
            box-shadow: 0 0 0 0.2rem rgba(255, 255, 255, 0.3);
        }
        
        .rule-form-card .text-muted {
            color: rgba(255, 255, 255, 0.8) !important;
        }
        
        .rules-table-wrapper {
            max-height: 600px;
            overflow-y: auto;
            overflow-x: auto;
        }
        
        .rules-table-wrapper::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        
        .rules-table-wrapper::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 10px;
        }
        
        .rules-table-wrapper::-webkit-scrollbar-thumb {
            background: #888;
            border-radius: 10px;
        }
        
        .rules-table-wrapper::-webkit-scrollbar-thumb:hover {
            background: #555;
        }
        
        /* Badge improvements */
        .badge {
            padding: 0.35em 0.65em;
            font-weight: 500;
            white-space: nowrap;
        }
        
        /* Row and column fixes */
        .row {
            margin-left: -10px;
            margin-right: -10px;
        }
        
        .row > * {
            padding-left: 10px;
            padding-right: 10px;
        }
        
        /* Container fluid fix */
        .container-fluid {
            padding: 0;
            margin: 0;
            max-width: 100%;
        }
        
        /* Responsive improvements */
        @media (max-width: 768px) {
            .sidebar {
                width: 100%;
                position: static;
                height: auto;
            }
            .main-content {
                margin-left: 0;
                padding: 15px;
                width: 100%;
            }
            .stat-value {
                font-size: 1.5rem;
            }
            .table-container {
                padding: 15px;
            }
            .btn {
                font-size: 0.875rem;
                padding: 0.4rem 1rem;
            }
        }
        
        @media (max-width: 576px) {
            .sidebar-brand h4 {
                font-size: 1rem;
            }
            .stat-card {
                padding: 15px;
            }
            .rule-form-card {
                padding: 15px;
            }
        }
        
        /* Loading and animation states */
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .fade-in {
            animation: fadeIn 0.3s ease-in;
        }
        
        /* Fix overflow issues */
        img {
            max-width: 100%;
            height: auto;
        }
        
        code {
            word-break: break-all;
            white-space: pre-wrap;
        }
        
        small {
            font-size: 0.875em;
            word-break: break-word;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="sidebar d-none d-md-block">
                <div class="sidebar-brand">
                    <h4><i class="fas fa-shield-alt"></i> Log Analyzer</h4>
                    <small class="text-muted">Isolated Network Security</small>
                </div>
                
                <div class="sidebar-nav">
                    <a class="nav-link {% if request.endpoint == 'dashboard' or request.endpoint == 'index' %}active{% endif %}" 
                       href="{{ url_for('dashboard') }}">
                        <i class="fas fa-tachometer-alt"></i> Dashboard
                    </a>
                    <a class="nav-link {% if request.endpoint == 'upload' %}active{% endif %}" 
                       href="{{ url_for('upload') }}">
                        <i class="fas fa-upload"></i> Upload Logs
                    </a>
                    <a class="nav-link {% if request.endpoint == 'logs' %}active{% endif %}" 
                       href="{{ url_for('logs') }}">
                        <i class="fas fa-list"></i> View Logs
                    </a>
                    <a class="nav-link {% if request.endpoint == 'threats' %}active{% endif %}" 
                       href="{{ url_for('threats') }}">
                        <i class="fas fa-exclamation-triangle"></i> Threats
                    </a>
                    <a class="nav-link {% if request.endpoint == 'alerts' %}active{% endif %}" 
                       href="{{ url_for('alerts') }}">
                        <i class="fas fa-bell"></i> Alerts
                        {% if alerts_count > 0 %}
                        <span class="badge bg-danger float-end">{{ alerts_count }}</span>
                        {% endif %}
                    </a>
                    <a class="nav-link {% if request.endpoint == 'view_rules' %}active{% endif %}"
                       href="{{ url_for('view_rules') }}">
                        <i class="fas fa-book"></i> View Rules
                    </a>
                    <a class="nav-link {% if request.endpoint == 'reports' %}active{% endif %}" 
                       href="{{ url_for('reports') }}">
                        <i class="fas fa-chart-bar"></i> Reports
                    </a>
                    <a class="nav-link {% if request.endpoint == 'analytics' %}active{% endif %}" 
                       href="{{ url_for('analytics') }}">
                        <i class="fas fa-analytics"></i> Analytics
                    </a>
                    <a class="nav-link {% if request.endpoint == 'ioc_detection' %}active{% endif %}" 
                       href="{{ url_for('ioc_detection') }}">
                        <i class="fas fa-biohazard"></i> IOC Detection
                    </a>
                    {% if user.role == 'admin' %}
                    <a class="nav-link {% if request.endpoint == 'settings' %}active{% endif %}" 
                       href="{{ url_for('settings') }}">
                        <i class="fas fa-cog"></i> Settings
                    </a>
                    {% endif %}
                </div>
                
                <div class="position-absolute bottom-0 start-0 w-100 p-3">
                    <div class="d-flex align-items-center">
                        <div class="flex-grow-1">
                            <small class="text-muted">Logged in as</small><br>
                            <strong class="text-white">{{ user.username }}</strong>
                        </div>
                        <a href="{{ url_for('logout') }}" class="btn btn-sm btn-outline-light">
                            <i class="fas fa-sign-out-alt"></i>
                        </a>
                    </div>
                </div>
            </div>
            
            <!-- Main Content -->
            <div class="main-content">
                <!-- Flash Messages -->
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="alert alert-{{ category }} alert-custom alert-dismissible fade show" role="alert">
                                {{ message }}
                                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                            </div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                
                <!-- Page Content -->
                {% block content %}{% endblock %}
            </div>
        </div>
    </div>
    
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <script>
        // Auto-dismiss alerts after 5 seconds
        setTimeout(function() {
            $('.alert').alert('close');
        }, 5000);
    </script>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap-select@1.14.0-beta3/dist/js/bootstrap-select.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap-select@1.14.0-beta3/dist/js/i18n/defaults-*.min.js"></script>
    
    {% block scripts %}{% endblock %}
</body>
</html>
'''

INDEX_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Home{% endblock %}
{% block content %}
<div class="text-center py-5">
    <h1 class="display-4 mb-4">Welcome to Log Analyzer</h1>
    <p class="lead mb-4">Portable Security Log Analysis Tool for Isolated Networks</p>
    <div class="row mt-5">
        <div class="col-md-4 mb-4">
            <div class="stat-card">
                <i class="fas fa-upload fa-3x text-primary mb-3"></i>
                <h4>Upload Logs</h4>
                <p>Upload log files from various sources for analysis</p>
                <a href="{{ url_for('upload') }}" class="btn btn-primary">Upload Now</a>
            </div>
        </div>
        <div class="col-md-4 mb-4">
            <div class="stat-card">
                <i class="fas fa-chart-line fa-3x text-success mb-3"></i>
                <h4>View Dashboard</h4>
                <p>See statistics and analytics of your logs</p>
                <a href="{{ url_for('dashboard') }}" class="btn btn-success">Go to Dashboard</a>
            </div>
        </div>
        <div class="col-md-4 mb-4">
            <div class="stat-card">
                <i class="fas fa-exclamation-triangle fa-3x text-danger mb-3"></i>
                <h4>Threat Detection</h4>
                <p>View detected threats and security alerts</p>
                <a href="{{ url_for('threats') }}" class="btn btn-danger">View Threats</a>
            </div>
        </div>
    </div>
</div>
{% endblock %}
'''

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Log Analyzer</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #2c3e50, #4a6491);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .login-card {
            background: white;
            border-radius: 20px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 400px;
            overflow: hidden;
        }
        
        .login-header {
            background: linear-gradient(135deg, #3498db, #2c3e50);
            color: white;
            padding: 40px 30px;
            text-align: center;
        }
        
        .login-header h2 {
            margin: 0;
            font-weight: 700;
        }
        
        .login-header p {
            opacity: 0.8;
            margin: 10px 0 0 0;
        }
        
        .login-body {
            padding: 30px;
        }
        
        .form-control {
            border: 2px solid #eee;
            border-radius: 10px;
            padding: 12px 15px;
            transition: all 0.3s;
        }
        
        .form-control:focus {
            border-color: #3498db;
            box-shadow: 0 0 0 0.2rem rgba(52, 152, 219, 0.25);
        }
        
        .btn-login {
            background: linear-gradient(135deg, #3498db, #2980b9);
            border: none;
            border-radius: 10px;
            color: white;
            padding: 12px;
            font-weight: 600;
            width: 100%;
            transition: all 0.3s;
        }
        
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(52, 152, 219, 0.4);
        }
        
        .input-group-text {
            background: #f8f9fa;
            border: 2px solid #eee;
            border-right: none;
        }
        
        .floating-label {
            position: relative;
            margin-bottom: 20px;
        }
        
        .floating-label label {
            position: absolute;
            top: 50%;
            left: 45px;
            transform: translateY(-50%);
            color: #666;
            transition: all 0.3s;
            pointer-events: none;
        }
        
        .floating-label input:focus + label,
        .floating-label input:not(:placeholder-shown) + label {
            top: 0;
            left: 15px;
            font-size: 12px;
            background: white;
            padding: 0 5px;
            color: #3498db;
        }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="login-header">
            <h2><i class="fas fa-shield-alt"></i> Log Analyzer</h2>
            <p>Isolated Network Security Platform</p>
        </div>
        
        <div class="login-body">
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                            {{ message }}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <form method="POST" action="{{ url_for('login') }}">
                <div class="floating-label">
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-user"></i></span>
                        <input type="text" class="form-control" id="username" name="username" placeholder=" " required>
                        <label for="username">Username</label>
                    </div>
                </div>
                
                <div class="floating-label">
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-lock"></i></span>
                        <input type="password" class="form-control" id="password" name="password" placeholder=" " required>
                        <label for="password">Password</label>
                    </div>
                </div>
                
                <button type="submit" class="btn btn-login mb-3">
                    <i class="fas fa-sign-in-alt me-2"></i>Login
                </button>
                
                <hr>
                
                <p class="text-center text-muted mb-0">
                    Don't have an account? 
                    <a href="{{ url_for('register') }}" class="text-decoration-none">Register here</a>
                </p>
            </form>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''

REGISTER_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - Log Analyzer</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #2c3e50, #4a6491);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .register-card {
            background: white;
            border-radius: 20px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 500px;
            overflow: hidden;
        }
        
        .register-header {
            background: linear-gradient(135deg, #27ae60, #2c3e50);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .register-header h2 {
            margin: 0;
            font-weight: 700;
        }
        
        .register-body {
            padding: 30px;
        }
        
        .form-control {
            border: 2px solid #eee;
            border-radius: 10px;
            padding: 12px 15px;
            margin-bottom: 15px;
        }
        
        .form-control:focus {
            border-color: #27ae60;
            box-shadow: 0 0 0 0.2rem rgba(39, 174, 96, 0.25);
        }
        
        .btn-register {
            background: linear-gradient(135deg, #27ae60, #219653);
            border: none;
            border-radius: 10px;
            color: white;
            padding: 12px;
            font-weight: 600;
            width: 100%;
            transition: all 0.3s;
        }
        
        .btn-register:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(39, 174, 96, 0.4);
        }
    </style>
</head>
<body>
    <div class="register-card">
        <div class="register-header">
            <h2><i class="fas fa-user-plus"></i> Create Account</h2>
            <p>Join the Log Analyzer platform</p>
        </div>
        
        <div class="register-body">
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                            {{ message }}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <form method="POST" action="{{ url_for('register') }}">
                <div class="row">
                    <div class="col-md-6">
                        <input type="text" class="form-control" name="username" placeholder="Username" required>
                    </div>
                    <div class="col-md-6">
                        <input type="email" class="form-control" name="email" placeholder="Email" required>
                    </div>
                </div>
                
                <input type="text" class="form-control" name="full_name" placeholder="Full Name" required>
                
                <div class="row">
                    <div class="col-md-6">
                        <input type="password" class="form-control" name="password" placeholder="Password" required>
                    </div>
                    <div class="col-md-6">
                        <input type="password" class="form-control" name="confirm_password" placeholder="Confirm Password" required>
                    </div>
                </div>
                
                <button type="submit" class="btn btn-register mt-3">
                    <i class="fas fa-user-plus me-2"></i>Register
                </button>
                
                <hr>
                
                <p class="text-center text-muted mb-0">
                    Already have an account? 
                    <a href="{{ url_for('login') }}" class="text-decoration-none">Login here</a>
                </p>
            </form>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''

DASHBOARD_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Dashboard{% endblock %}
{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="fas fa-tachometer-alt me-2"></i>Dashboard</h2>
    <div>
        <small class="text-muted">Last updated: {{ now.strftime('%Y-%m-%d %H:%M:%S') }}</small>
    </div>
</div>

{% if not has_data %}
<div class="alert alert-info alert-dismissible fade show" role="alert">
    <i class="fas fa-info-circle me-2"></i>
    <strong>No logs yet.</strong> Upload log files to start analyzing and monitoring threats.
    <a href="{{ url_for('upload') }}" class="btn btn-sm btn-info ms-3">Upload Logs Now</a>
    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
</div>
{% endif %}

<!-- Statistics Cards -->
<div class="row">
    <div class="col-xl-3 col-md-6 mb-4">
        <div class="stat-card">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h6 class="text-muted mb-1">Total Logs</h6>
                    <h2 class="stat-value text-primary">{{ stats.total_logs|default(0) }}</h2>
                </div>
                <i class="fas fa-file-alt fa-3x text-primary"></i>
            </div>
            <small class="text-muted">All collected log entries</small>
        </div>
    </div>
    
    <div class="col-xl-3 col-md-6 mb-4">
        <div class="stat-card success">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h6 class="text-muted mb-1">TTP Matches</h6>
                    <h2 class="stat-value text-success">{{ stats.ttp_matches|default(0) }}</h2>
                </div>
                <i class="fas fa-crosshairs fa-3x text-success"></i>
            </div>
            <small class="text-muted">MITRE ATT&CK detections</small>
        </div>
    </div>
    
    <div class="col-xl-3 col-md-6 mb-4">
        <div class="stat-card critical">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h6 class="text-muted mb-1">Critical</h6>
                    <h2 class="stat-value text-danger">{{ stats.severity_dist.CRITICAL|default(0) }}</h2>
                </div>
                <i class="fas fa-fire fa-3x text-danger"></i>
            </div>
            <small class="text-muted">Critical severity events</small>
        </div>
    </div>
    
    <div class="col-xl-3 col-md-6 mb-4">
        <div class="stat-card high">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h6 class="text-muted mb-1">High Severity</h6>
                    <h2 class="stat-value text-warning">{{ stats.severity_dist.HIGH|default(0) }}</h2>
                </div>
                <i class="fas fa-exclamation-triangle fa-3x text-warning"></i>
            </div>
            <small class="text-muted">High severity events</small>
        </div>
    </div>
</div>

<!-- Charts Row -->
<div class="row mb-4">
    <div class="col-lg-6 mb-4">
        <div class="table-container">
            <h5><i class="fas fa-chart-pie me-2"></i>Severity Distribution</h5>
            {% if has_data %}
            <div id="severityChart" style="height: 300px;"></div>
            {% else %}
            <div class="alert alert-secondary p-4 text-center" style="height: 300px; display: flex; align-items: center; justify-content: center;">
                <div>
                    <i class="fas fa-chart-pie fa-3x text-muted mb-2"></i>
                    <p class="text-muted mb-0">No severity data yet</p>
                    <small class="text-muted">Upload logs to see distribution</small>
                </div>
            </div>
            {% endif %}
        </div>
    </div>
    
    <div class="col-lg-6 mb-4">
        <div class="table-container">
            <h5><i class="fas fa-chart-line me-2"></i>Hourly Activity</h5>
            {% if has_data %}
            <div id="hourlyChart" style="height: 300px;"></div>
            {% else %}
            <div class="alert alert-secondary p-4 text-center" style="height: 300px; display: flex; align-items: center; justify-content: center;">
                <div>
                    <i class="fas fa-chart-line fa-3x text-muted mb-2"></i>
                    <p class="text-muted mb-0">No activity data yet</p>
                    <small class="text-muted">Upload logs to see hourly patterns</small>
                </div>
            </div>
            {% endif %}
        </div>
    </div>
</div>

<!-- Recent Logs and Threats -->
<div class="row">
    <div class="col-lg-6 mb-4">
        <div class="table-container">
            <h5><i class="fas fa-history me-2"></i>Recent Logs</h5>
            {% if recent_logs %}
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Source</th>
                            <th>Severity</th>
                            <th>Message</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for log in recent_logs %}
                        <tr>
                            <td><small>{{ log.timestamp }}</small></td>
                            <td><small>{{ log.source_name }}</small></td>
                            <td>
                                <span class="severity-badge severity-{{ log.severity|lower }}">
                                    {{ log.severity }}
                                </span>
                            </td>
                            <td><small>{{ log.message|safetruncate(50) }}</small></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            <a href="{{ url_for('logs') }}" class="btn btn-sm btn-outline-primary">View All Logs</a>
            {% else %}
            <div class="alert alert-info p-4 text-center">
                <i class="fas fa-inbox fa-2x text-muted mb-2"></i>
                <p class="text-muted mb-0">No recent logs</p>
            </div>
            {% endif %}
        </div>
    </div>
    
    <div class="col-lg-6 mb-4">
        <div class="table-container">
            <h5><i class="fas fa-exclamation-triangle me-2"></i>Recent Threats</h5>
            {% if stats.recent_threats %}
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Source</th>
                            <th>Severity</th>
                            <th>TTP</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for threat in stats.recent_threats %}
                        <tr>
                            <td><small>{{ threat[0] }}</small></td>
                            <td><small>{{ threat[1] }}</small></td>
                            <td>
                                <span class="severity-badge severity-{{ threat[2]|lower }}">
                                    {{ threat[2] }}
                                </span>
                            </td>
                            <td><small>{{ threat[4]|default('Unknown')|safetruncate(30) }}</small></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            <a href="{{ url_for('threats') }}" class="btn btn-sm btn-outline-danger">View All Threats</a>
            {% else %}
            <div class="alert alert-warning p-4 text-center">
                <i class="fas fa-shield-alt fa-2x text-muted mb-2"></i>
                <p class="text-muted mb-0">No threats detected yet</p>
            </div>
            {% endif %}
        </div>
    </div>
</div>

<!-- Top Sources Section -->
{% if has_data and top_sources %}
<div class="row mb-4">
    <div class="col-12">
        <div class="table-container">
            <h5><i class="fas fa-network-wired me-2"></i>Top Sources by Threats</h5>
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Source</th>
                            <th class="text-danger">Critical</th>
                            <th class="text-warning">High</th>
                            <th>Total Events</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for source in top_sources %}
                        <tr>
                            <td><strong>{{ source.source_name }}</strong></td>
                            <td class="text-danger">{{ source.critical_count|default(0) }}</td>
                            <td class="text-warning">{{ source.high_count|default(0) }}</td>
                            <td>{{ source.count }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
{% endif %}

<!-- Quick Actions -->
<div class="row">
    <div class="col-12">
        <div class="table-container">
            <h5><i class="fas fa-bolt me-2"></i>Quick Actions</h5>
            <div class="row text-center">
                <div class="col-md-3 mb-3">
                    <a href="{{ url_for('upload') }}" class="btn btn-primary w-100 py-3">
                        <i class="fas fa-upload fa-2x mb-2"></i><br>
                        Upload Logs
                    </a>
                </div>
                <div class="col-md-3 mb-3">
                    <a href="{{ url_for('reports') }}" class="btn btn-success w-100 py-3">
                        <i class="fas fa-chart-bar fa-2x mb-2"></i><br>
                        Generate Report
                    </a>
                </div>
                <div class="col-md-3 mb-3">
                    <a href="{{ url_for('alerts') }}" class="btn btn-warning w-100 py-3">
                        <i class="fas fa-bell fa-2x mb-2"></i><br>
                        View Alerts
                    </a>
                </div>
                <div class="col-md-3 mb-3">
                    <a href="{{ url_for('threats') }}" class="btn btn-danger w-100 py-3">
                        <i class="fas fa-exclamation-triangle fa-2x mb-2"></i><br>
                        View Threats
                    </a>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
// Initialize charts only if data exists
var severityLabels = {{ severity_labels|safe }};
var severityValues = {{ severity_values|safe }};
var hourlyLabels = {{ hourly_labels|safe }};
var hourlyValues = {{ hourly_values|safe }};

// Severity Distribution Chart
if (severityValues.some(v => v > 0)) {
    var severityData = [{
        values: severityValues,
        labels: severityLabels,
        type: 'pie',
        hole: 0.4,
        marker: {
            colors: ['#e74c3c', '#e67e22', '#f1c40f', '#3498db', '#95a5a6']
        }
    }];
    
    var severityLayout = {
        height: 300,
        showlegend: true,
        legend: {
            orientation: 'h',
            y: -0.1
        },
        margin: {t: 0, b: 0, l: 0, r: 0}
    };
    
    if (document.getElementById('severityChart')) {
        Plotly.newPlot('severityChart', severityData, severityLayout);
    }
}

// Hourly Activity Chart
if (hourlyValues.some(v => v > 0)) {
    var hourlyData = [{
        x: hourlyLabels,
        y: hourlyValues,
        type: 'bar',
        marker: {
            color: '#3498db'
        }
    }];
    
    var hourlyLayout = {
        height: 300,
        xaxis: {
            title: 'Hour of Day',
            tickmode: 'linear'
        },
        yaxis: {
            title: 'Number of Events'
        },
        margin: {t: 30, b: 50, l: 50, r: 20}
    };
    
    if (document.getElementById('hourlyChart')) {
        Plotly.newPlot('hourlyChart', hourlyData, hourlyLayout);
    }
}

// Auto-refresh dashboard every 60 seconds
setTimeout(function() {
    window.location.reload();
}, 60000);

// If no data yet (e.g., async processing), poll stats and reload when ready
(function(){
    try {
        var totalLogs = parseInt('{{ stats.total_logs|default(0) }}');
        if (!isNaN(totalLogs) && totalLogs === 0) {
            var attempts = 0;
            var maxAttempts = 30; // ~60 seconds at 2s interval
            var timer = setInterval(function(){
                fetch('{{ url_for('api_stats') }}', {cache: 'no-store'})
                    .then(function(r){ return r.json(); })
                    .then(function(data){
                        if (data && data.total_logs && data.total_logs > 0) {
                            clearInterval(timer);
                            window.location.reload();
                        }
                    })
                    .catch(function(){ /* ignore */ });
                attempts += 1;
                if (attempts >= maxAttempts) {
                    clearInterval(timer);
                }
            }, 2000);
        }
    } catch (e) { /* ignore */ }
})();
</script>
{% endblock %}
'''

UPLOAD_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Upload Logs{% endblock %}
{% block content %}
<style>
.file-item { padding: 10px; margin: 5px 0; background: #f8f9fa; border-radius: 5px; display: flex; justify-content: space-between; align-items: center; }
.file-item.error { background-color: #f8d7da; border-left: 4px solid #dc3545; }
.file-item.success { background-color: #d4edda; border-left: 4px solid #28a745; }
.drag-over { background-color: #e3f2fd !important; border: 2px dashed #2196F3 !important; }
</style>

<div class="dashboard-header mb-4">
    <h2><i class="fas fa-cloud-upload-alt me-2"></i>Batch Upload Log Files</h2>
</div>
<p class="text-muted mb-4">Upload multiple log files at once. System will automatically detect formats and perform batch analysis across all files.</p>

<div class="row g-4">
    <div class="col-lg-8">
        <div class="table-container">
            <h5><i class="fas fa-file-upload me-2"></i>Batch Upload</h5>
            <hr class="my-3">
            
            <form method="POST" enctype="multipart/form-data" id="uploadForm">
                <!-- Log Format Selection -->
                <div class="mb-4">
                    <label class="form-label"><i class="fas fa-list me-2"></i>Log Format (Applied to All Files)</label>
                    <select class="form-select" name="log_format" id="logFormat" required>
                        <option value="auto">🔍 Auto Detect (Recommended)</option>
                        <option value="syslog">📋 Syslog</option>
                        <option value="windows">🪟 Windows Event Log</option>
                        <option value="apache">🌐 Apache/Nginx</option>
                        <option value="ocfs">🗂️ OCFS Cluster</option>
                        <option value="ocsf">🔐 OCSF (Security Schema)</option>
                        <option value="json">{ } JSON Format</option>
                        <option value="csv">📊 CSV Format</option>
                        <option value="generic">📝 Generic/Text</option>
                    </select>
                    <div class="form-text">Select format or use Auto Detection for all files</div>
                </div>
                
                <!-- Drag & Drop Zone -->
                <div class="mb-4">
                    <label class="form-label"><i class="fas fa-folder-open me-2"></i>Log Files</label>
                    <div id="dropZone" class="border border-dashed border-2 border-info p-5 text-center rounded" style="cursor: pointer; transition: all 0.3s;">
                        <i class="fas fa-cloud-upload-alt fa-3x text-info mb-3"></i>
                        <p class="mb-2"><strong>Drag & drop files here</strong></p>
                        <p class="text-muted mb-3">or click to select files</p>
                        <button type="button" class="btn btn-outline-info btn-sm" onclick="document.getElementById('logFiles').click()">
                            <i class="fas fa-search me-2"></i>Browse Files
                        </button>
                    </div>
                    <input type="file" id="logFiles" name="log_files" multiple accept=".log,.txt,.json,.csv,.evtx,.conf" style="display: none;">
                    <div class="form-text mt-2">
                        Supported: .log, .txt, .json, .csv, .evtx, .conf | Max 100MB per file | Multiple files supported
                    </div>
                </div>
                
                <!-- Selected Files List -->
                <div id="filesList" class="mb-4" style="display: none;">
                    <h6><i class="fas fa-list-check me-2"></i>Selected Files (<span id="fileCount">0</span>)</h6>
                    <div id="selectedFilesList" class="mt-3"></div>
                </div>
                
                <div class="alert alert-info mb-4">
                    <i class="fas fa-lightbulb me-2"></i>
                    <strong>Smart Analysis:</strong> Each file will be automatically analyzed for threats, TTPs, and security insights.
                </div>
                
                <div class="d-grid gap-2 gap-md-3">
                    <button type="submit" class="btn btn-primary btn-lg" id="uploadBtn" disabled>
                        <i class="fas fa-cloud-upload-alt me-2"></i>Upload & Analyze
                    </button>
                </div>
            </form>
        </div>
    </div>
    
    <div class="col-lg-4">
        <!-- Batch Upload Benefits -->
        <div class="table-container mb-4 bg-light p-3 rounded">
            <h5><i class="fas fa-rocket me-2"></i>Batch Upload Benefits</h5>
            <ul class="small mb-0">
                <li><i class="fas fa-check text-success me-2"></i>Upload 10+ files simultaneously</li>
                <li><i class="fas fa-check text-success me-2"></i>Unified threat analysis</li>
                <li><i class="fas fa-check text-success me-2"></i>Consolidated reporting</li>
                <li><i class="fas fa-check text-success me-2"></i>Cross-file correlation</li>
                <li><i class="fas fa-check text-success me-2"></i>Automatic format detection</li>
                <li><i class="fas fa-check text-success me-2"></i>Progress tracking per file</li>
            </ul>
        </div>
        
        <!-- Supported Formats -->
        <div class="table-container mb-4">
            <h5><i class="fas fa-check-circle me-2"></i>Supported Formats</h5>
            <div class="list-group list-group-flush">
                <div class="list-group-item d-flex justify-content-between align-items-center py-2">
                    <span><i class="fas fa-circle text-warning me-2"></i>Syslog</span>
                    <span class="badge bg-warning">Enabled</span>
                </div>
                <div class="list-group-item d-flex justify-content-between align-items-center py-2">
                    <span><i class="fas fa-circle text-info me-2"></i>Windows Event</span>
                    <span class="badge bg-info">Enabled</span>
                </div>
                <div class="list-group-item d-flex justify-content-between align-items-center py-2">
                    <span><i class="fas fa-circle text-primary me-2"></i>Apache/Nginx</span>
                    <span class="badge bg-primary">Enabled</span>
                </div>
                <div class="list-group-item d-flex justify-content-between align-items-center py-2">
                    <span><i class="fas fa-circle text-muted me-2"></i>OCFS Cluster</span>
                    <span class="badge bg-muted">Enabled</span>
                </div>
                <div class="list-group-item d-flex justify-content-between align-items-center py-2">
                    <span><i class="fas fa-circle text-success me-2"></i>JSON Logs</span>
                    <span class="badge bg-success">Enabled</span>
                </div>
                <div class="list-group-item d-flex justify-content-between align-items-center py-2">
                    <span><i class="fas fa-circle text-danger me-2"></i>CSV Format</span>
                    <span class="badge bg-danger">Enabled</span>
                </div>
            </div>
        </div>
        
        <!-- Quick Actions -->
        <div class="table-container">
            <h5><i class="fas fa-bolt me-2"></i>Quick Actions</h5>
            <hr class="my-3">
            
            <div class="d-grid gap-2 mb-3">
                <button class="btn btn-outline-success" type="button" onclick="openUploadsFolder()">
                    <i class="fas fa-folder me-2"></i>Open Uploads Folder
                </button>
            </div>
            
            <!-- Analysis Summary -->
            <div class="alert alert-light border mt-3">
                <strong><i class="fas fa-chart-line me-2"></i>Analysis Includes:</strong>
                <ul class="small mb-0 mt-2">
                    <li><i class="fas fa-check text-success me-2"></i>Threat Detection</li>
                    <li><i class="fas fa-check text-success me-2"></i>MITRE ATT&CK TTP Matching</li>
                    <li><i class="fas fa-check text-success me-2"></i>Severity Classification</li>
                    <li><i class="fas fa-check text-success me-2"></i>Anomaly Detection</li>
                    <li><i class="fas fa-check text-success me-2"></i>Source IP Analysis</li>
                    <li><i class="fas fa-check text-success me-2"></i>Cross-File Correlation</li>
                </ul>
            </div>
        </div>
    </div>
</div>

<script>
// Prevent double form submission
let isSubmitting = false;

// File selection from input
document.getElementById('logFiles').addEventListener('change', function(e) {
    updateFilesList(e.target.files);
});

// Drag and drop
const dropZone = document.getElementById('dropZone');

dropZone.addEventListener('dragover', function(e) {
    e.preventDefault();
    dropZone.classList.add('drag-over');
});

dropZone.addEventListener('dragleave', function() {
    dropZone.classList.remove('drag-over');
});

dropZone.addEventListener('drop', function(e) {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    
    const files = e.dataTransfer.files;
    
    // Use DataTransfer API to properly set files
    const dataTransfer = new DataTransfer();
    for (let i = 0; i < files.length; i++) {
        dataTransfer.items.add(files[i]);
    }
    
    document.getElementById('logFiles').files = dataTransfer.files;
    updateFilesList(document.getElementById('logFiles').files);
});

// Click to select files
dropZone.addEventListener('click', function() {
    document.getElementById('logFiles').click();
});

function updateFilesList(files) {
    const filesList = document.getElementById('filesList');
    const selectedFilesList = document.getElementById('selectedFilesList');
    const fileCount = document.getElementById('fileCount');
    const uploadBtn = document.getElementById('uploadBtn');
    
    fileCount.textContent = files.length;
    selectedFilesList.innerHTML = '';
    
    if (files.length > 0) {
        filesList.style.display = 'block';
        uploadBtn.disabled = false;
        
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            const size = formatFileSize(file.size);
            const item = document.createElement('div');
            item.className = 'file-item';
            item.innerHTML = `
                <span><i class="fas fa-file me-2"></i>${file.name}</span>
                <span class="badge bg-primary">${size}</span>
            `;
            selectedFilesList.appendChild(item);
        }
    } else {
        filesList.style.display = 'none';
        uploadBtn.disabled = true;
    }
}

// Handle form submission
document.getElementById('uploadForm').addEventListener('submit', function(e) {
    // Check if files are selected
    const logFiles = document.getElementById('logFiles');
    if (!logFiles.files || logFiles.files.length === 0) {
        e.preventDefault();
        alert('Please select at least one file to upload.');
        return false;
    }
    
    // Prevent double submission
    if (isSubmitting) {
        e.preventDefault();
        return false;
    }
    
    isSubmitting = true;
    const uploadBtn = document.getElementById('uploadBtn');
    uploadBtn.disabled = true;
    uploadBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Uploading...';
});

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

function openUploadsFolder() {
    fetch('/api/open-folder', { method: 'POST' })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                alert('Uploads folder opened');
            } else {
                alert('Error: ' + data.error);
            }
        });
}
</script>
{% endblock %}
'''

LOGS_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Log Entries{% endblock %}
{% block content %}
<style>
.log-details-modal .modal-dialog { max-width: 90%; }
.log-row { cursor: pointer; transition: all 0.2s; }
.log-row:hover { background-color: #f8f9fa !important; transform: translateY(-1px); }
.bulk-select-column { width: 40px; }
.table-fixed-header thead { position: sticky; top: 0; background: white; z-index: 10; box-shadow: 0 2px 2px -1px rgba(0,0,0,0.1); }
.export-dropdown { min-width: 200px; }
.filter-tag { display: inline-block; background: #e9ecef; padding: 2px 8px; border-radius: 10px; margin: 2px; font-size: 0.85rem; }
.logs-toolbar { display: flex; flex-wrap: wrap; gap: 12px; }
.logs-toolbar .btn-group, .logs-toolbar .dropdown { flex-shrink: 0; }
.logs-toolbar .form-check { margin-bottom: 0; }
</style>

<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="fas fa-list me-2"></i>Log Entries</h2>
    <div>
        <span class="badge bg-primary me-2">Total: {{ total|default(0) }}</span>
        <a href="{{ url_for('upload') }}" class="btn btn-primary">
            <i class="fas fa-plus me-2"></i>Add Logs
        </a>
    </div>
</div>

<!-- Search & Filter Card -->
<div class="table-container mb-4">
    <h5><i class="fas fa-search me-2"></i>Advanced Search & Filter</h5>
    <form method="GET" action="{{ url_for('logs') }}" id="searchForm">
        <div class="row g-3">
            <!-- Quick Search -->
            <div class="col-md-6">
                <label class="form-label">Quick Search</label>
                <div class="input-group">
                    <span class="input-group-text"><i class="fas fa-search"></i></span>
                    <input type="text" class="form-control" name="search" value="{{ search_params.search_query }}" 
                           placeholder="Search in message, raw log, or source...">
                </div>
            </div>
            
            <!-- Severity Filter -->
            <div class="col-md-3">
                <label class="form-label">Severity</label>
                <select class="form-select" name="severity">
                    <option value="all">All Severities</option>
                    {% for severity in severity_levels %}
                    <option value="{{ severity.lower() }}" {% if search_params.severity == severity.lower() %}selected{% endif %}>
                        {{ severity }}
                    </option>
                    {% endfor %}
                </select>
            </div>
            
            <!-- Source Filter -->
            <div class="col-md-3">
                <label class="form-label">Source</label>
                <select class="form-select" name="source" data-live-search="true">
                    <option value="">All Sources</option>
                    {% for source in unique_sources %}
                    <option value="{{ source }}" {% if search_params.source == source %}selected{% endif %}>
                        {{ source|safetruncate(30) }}
                    </option>
                    {% endfor %}
                </select>
            </div>
            
            <!-- Source IP Filter -->
            <div class="col-md-4">
                <label class="form-label">Source IP</label>
                <select class="form-select" name="source_ip" data-live-search="true">
                    <option value="">All IPs</option>
                    {% for ip in unique_source_ips %}
                    <option value="{{ ip }}" {% if search_params.source_ip == ip %}selected{% endif %}>
                        {{ ip }}
                    </option>
                    {% endfor %}
                </select>
            </div>
            
            <!-- User Filter -->
            <div class="col-md-4">
                <label class="form-label">User</label>
                <select class="form-select" name="user" data-live-search="true">
                    <option value="">All Users</option>
                    {% for user in unique_users %}
                    <option value="{{ user }}" {% if search_params.user == user %}selected{% endif %}>
                        {{ user }}
                    </option>
                    {% endfor %}
                </select>
            </div>
            
            <!-- Event Type Filter -->
            <div class="col-md-4">
                <label class="form-label">Event Type</label>
                <select class="form-select" name="event_type" data-live-search="true">
                    <option value="">All Event Types</option>
                    {% for event_type in unique_event_types %}
                    <option value="{{ event_type }}" {% if search_params.event_type == event_type %}selected{% endif %}>
                        {{ event_type }}
                    </option>
                    {% endfor %}
                </select>
            </div>
            
            <!-- Date Range -->
            <div class="col-md-6">
                <label class="form-label">Date Range</label>
                <div class="row g-2">
                    <div class="col">
                        <input type="date" class="form-control" name="date_from" value="{{ search_params.date_from }}" placeholder="From">
                    </div>
                    <div class="col">
                        <input type="date" class="form-control" name="date_to" value="{{ search_params.date_to }}" placeholder="To">
                    </div>
                </div>
            </div>
            
            <!-- Items Per Page -->
            <div class="col-md-3">
                <label class="form-label">Items Per Page</label>
                <select class="form-select" name="per_page" onchange="this.form.submit()">
                    {% for option in per_page_options %}
                    <option value="{{ option }}" {% if search_params.per_page == option %}selected{% endif %}>
                        {{ option }} per page
                    </option>
                    {% endfor %}
                </select>
            </div>
            
            <!-- Action Buttons -->
            <div class="col-md-3 d-flex align-items-end">
                <button type="submit" class="btn btn-primary me-2 flex-grow-1">
                    <i class="fas fa-search me-2"></i>Search
                </button>
                <a href="{{ url_for('logs') }}" class="btn btn-outline-secondary">
                    <i class="fas fa-times me-2"></i>Clear
                </a>
            </div>
        </div>
        
        <!-- Active Filters Display -->
        {% if search_params.search_query or search_params.severity != 'all' or search_params.source or search_params.source_ip or search_params.user or search_params.event_type or search_params.date_from or search_params.date_to %}
        <div class="mt-3 pt-3 border-top">
            <small class="text-muted me-2">Active Filters:</small>
            {% if search_params.search_query %}
            <span class="filter-tag">Search: "{{ search_params.search_query }}"</span>
            {% endif %}
            {% if search_params.severity != 'all' %}
            <span class="filter-tag">Severity: {{ search_params.severity|upper }}</span>
            {% endif %}
            {% if search_params.source %}
            <span class="filter-tag">Source: {{ search_params.source }}</span>
            {% endif %}
            {% if search_params.source_ip %}
            <span class="filter-tag">IP: {{ search_params.source_ip }}</span>
            {% endif %}
            {% if search_params.user %}
            <span class="filter-tag">User: {{ search_params.user }}</span>
            {% endif %}
            {% if search_params.event_type %}
            <span class="filter-tag">Event: {{ search_params.event_type }}</span>
            {% endif %}
            {% if search_params.date_from %}
            <span class="filter-tag">From: {{ search_params.date_from }}</span>
            {% endif %}
            {% if search_params.date_to %}
            <span class="filter-tag">To: {{ search_params.date_to }}</span>
            {% endif %}
        </div>
        {% endif %}
    </form>
</div>

<!-- Bulk Actions & Export -->
<div class="table-container mb-3">
    <div class="logs-toolbar justify-content-between align-items-center">
        <div>
            <div class="form-check">
                <input class="form-check-input" type="checkbox" id="selectAllCheckbox" onclick="toggleSelectAll(this)">
                <label class="form-check-label" for="selectAllCheckbox">
                    Select All (Page)
                </label>
            </div>
        </div>
        <div class="btn-group">
            <button class="btn btn-outline-secondary btn-sm dropdown-toggle" type="button" data-bs-toggle="dropdown">
                <i class="fas fa-tags me-1"></i>Bulk Tag
            </button>
            <ul class="dropdown-menu">
                <li><a class="dropdown-item" href="#" onclick="bulkAddTag('suspicious')">Tag as Suspicious</a></li>
                <li><a class="dropdown-item" href="#" onclick="bulkAddTag('reviewed')">Tag as Reviewed</a></li>
                <li><a class="dropdown-item" href="#" onclick="bulkAddTag('false_positive')">Tag as False Positive</a></li>
                <li><hr class="dropdown-divider"></li>
                <li><input class="form-control form-control-sm m-2" type="text" id="customTagInput" placeholder="Custom tag..."></li>
                <li><button class="btn btn-sm btn-primary m-2" onclick="bulkAddCustomTag()">Apply Custom Tag</button></li>
            </ul>
            
            <div class="dropdown ms-2">
                <button class="btn btn-outline-primary btn-sm dropdown-toggle" type="button" data-bs-toggle="dropdown">
                    <i class="fas fa-download me-1"></i>Export
                </button>
                <ul class="dropdown-menu export-dropdown">
                    <li><a class="dropdown-item" href="#" onclick="exportLogs('csv')"><i class="fas fa-file-csv me-2"></i>Export as CSV</a></li>
                    <li><a class="dropdown-item" href="#" onclick="exportLogs('json')"><i class="fas fa-file-code me-2"></i>Export as JSON</a></li>
                    <li><a class="dropdown-item" href="#" onclick="exportLogs('pdf')"><i class="fas fa-file-pdf me-2"></i>Export as PDF</a></li>
                    <li><hr class="dropdown-divider"></li>
                    <li><a class="dropdown-item" href="#" onclick="exportSelectedLogs('csv')"><i class="fas fa-filter me-2"></i>Export Selected Only (CSV)</a></li>
                </ul>
            </div>
            
            <button class="btn btn-outline-danger btn-sm ms-2" onclick="deleteSelectedLogs()">
                <i class="fas fa-trash me-1"></i>Delete Selected
            </button>
        </div>
    </div>
</div>

<!-- Logs Table -->
<div class="table-container table-fixed-header">
    <div class="table-responsive" style="max-height: 600px;">
        <table class="table table-hover">
            <thead>
                <tr>
                    <th class="bulk-select-column">
                        <input type="checkbox" class="form-check-input" id="tableSelectAll" onclick="toggleTableSelectAll(this)">
                    </th>
                    <th>Time</th>
                    <th>Source</th>
                    <th>Severity</th>
                    <th>Message</th>
                    <th>IP Address</th>
                    <th>User</th>
                    <th>TTP</th>
                    <th>Tags</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {% for log in logs %}
                <tr class="log-row {% if log.severity == 'CRITICAL' %}table-danger{% elif log.severity == 'HIGH' %}table-warning{% endif %}" 
                    data-log-id="{{ log.id }}">
                    <td>
                        <input type="checkbox" class="form-check-input log-checkbox" value="{{ log.id }}">
                    </td>
                    <td>
                        <small class="text-muted">{{ log.display_time|default(log.timestamp) }}</small>
                    </td>
                    <td>
                        <small>{{ log.source_name }}</small>
                    </td>
                    <td>
                        <span class="severity-badge severity-{{ log.severity|lower }}">
                            {{ log.severity }}
                        </span>
                    </td>
                    <td>
                        <div class="log-message" style="max-width: 300px;" 
                             title="{{ log.message|escape if log.message else '' }}">
                            <small>{{ log.short_message|default(log.message) }}</small>
                        </div>
                    </td>
                    <td>
                        {% if log.source_ip %}
                        <code class="small">{{ log.source_ip }}</code>
                        {% if log.dest_ip %}
                        <br><small class="text-muted">→ {{ log.dest_ip }}</small>
                        {% endif %}
                        {% else %}
                        <span class="text-muted">N/A</span>
                        {% endif %}
                    </td>
                    <td>
                        <small>{{ log.user or 'N/A' }}</small>
                    </td>
                    <td>
                        {% if log.ttp_match %}
                        <span class="badge bg-danger" title="{{ log.ttp_match }}">
                            {{ log.ttp_match|safetruncate(20) }}
                        </span>
                        {% else %}
                        <span class="text-muted">-</span>
                        {% endif %}
                    </td>
                    <td>
                        {% if log.tags_list %}
                        <div class="d-flex flex-wrap gap-1">
                            {% for tag in log.tags_list[:3] %}
                            <span class="badge bg-info" style="font-size: 0.7rem;">{{ tag }}</span>
                            {% endfor %}
                            {% if log.tags_list|length > 3 %}
                            <span class="badge bg-secondary" style="font-size: 0.7rem;">+{{ log.tags_list|length - 3 }}</span>
                            {% endif %}
                        </div>
                        {% else %}
                        <span class="text-muted">-</span>
                        {% endif %}
                    </td>
                    <td>
                        <div class="btn-group btn-group-sm" role="group">
                            <button type="button" class="btn btn-outline-info" onclick="viewLogDetails({{ log.id }}, event)" 
                                    title="View Details">
                                <i class="fas fa-eye"></i>
                            </button>
                            <button type="button" class="btn btn-outline-secondary" onclick="copyLogToClipboard({{ log.id }})" 
                                    title="Copy to Clipboard">
                                <i class="fas fa-copy"></i>
                            </button>
                            <button type="button" class="btn btn-outline-danger" onclick="deleteLog({{ log.id }})" 
                                    title="Delete Log">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </td>
                </tr>
                {% else %}
                <tr>
                    <td colspan="10" class="text-center py-5">
                        <div class="text-muted">
                            <i class="fas fa-inbox fa-3x mb-3 d-block text-secondary"></i>
                            <strong>No logs found</strong>
                            {% if search_params.search_query or search_params.severity != 'all' or search_params.source or search_params.source_ip %}
                            <p class="mt-2">Try adjusting your search filters</p>
                            {% else %}
                            <p class="mt-2">Upload some logs to get started</p>
                            <a href="{{ url_for('upload') }}" class="btn btn-sm btn-primary mt-2">
                                <i class="fas fa-upload me-1"></i>Upload Logs
                            </a>
                            {% endif %}
                        </div>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<!-- Pagination -->
{% if total_pages > 1 %}
<nav aria-label="Page navigation" class="mt-4">
    <ul class="pagination justify-content-center">
        <li class="page-item {% if current_page == 1 %}disabled{% endif %}">
            <a class="page-link" href="{{ url_for('logs', page=current_page-1, **request.args) if current_page > 1 else '#' }}">
                <i class="fas fa-chevron-left"></i>
            </a>
        </li>
        
        {% for page_num in range(1, total_pages+1) %}
            {% if page_num >= current_page-2 and page_num <= current_page+2 %}
            <li class="page-item {% if page_num == current_page %}active{% endif %}">
                <a class="page-link" href="{{ url_for('logs', page=page_num, **request.args) }}">
                    {{ page_num }}
                </a>
            </li>
            {% elif page_num == 1 or page_num == total_pages %}
            <li class="page-item {% if page_num == current_page %}active{% endif %}">
                <a class="page-link" href="{{ url_for('logs', page=page_num, **request.args) }}">
                    {{ page_num }}
                </a>
            </li>
            {% elif page_num == current_page-3 or page_num == current_page+3 %}
            <li class="page-item disabled">
                <span class="page-link">...</span>
            </li>
            {% endif %}
        {% endfor %}
        
        <li class="page-item {% if current_page == total_pages %}disabled{% endif %}">
            <a class="page-link" href="{{ url_for('logs', page=current_page+1, **request.args) if current_page < total_pages else '#' }}">
                <i class="fas fa-chevron-right"></i>
            </a>
        </li>
    </ul>
    <div class="text-center text-muted mt-2">
        <small>Page {{ current_page }} of {{ total_pages }} • {{ total }} total records</small>
    </div>
</nav>
{% endif %}

<!-- Log Details Modal -->
<div class="modal fade" id="logDetailsModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-xl">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Log Entry Details</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body" id="logDetailsContent">
                <!-- Content will be loaded dynamically -->
                <div class="text-center py-4">
                    <div class="spinner-border" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <button type="button" class="btn btn-primary" onclick="copyModalContent()">
                    <i class="fas fa-copy me-1"></i>Copy to Clipboard
                </button>
            </div>
        </div>
    </div>
</div>

<script>
// Bulk selection functions
function toggleSelectAll(checkbox) {
    const checkboxes = document.querySelectorAll('.log-checkbox');
    checkboxes.forEach(cb => cb.checked = checkbox.checked);
}

function toggleTableSelectAll(checkbox) {
    const checkboxes = document.querySelectorAll('.log-checkbox');
    checkboxes.forEach(cb => cb.checked = checkbox.checked);
}

function getSelectedLogIds() {
    const checkboxes = document.querySelectorAll('.log-checkbox:checked');
    return Array.from(checkboxes).map(cb => cb.value);
}

// Log details viewing
function viewLogDetails(logId, event) {
    if (event) event.stopPropagation();
    
    const modal = new bootstrap.Modal(document.getElementById('logDetailsModal'));
    const contentDiv = document.getElementById('logDetailsContent');
    
    // Show loading
    contentDiv.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
        </div>
    `;
    
    modal.show();
    
    // Fetch log details
    fetch(`/api/logs/${logId}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                contentDiv.innerHTML = `
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        ${data.error}
                    </div>
                `;
                return;
            }
            
            // Format the log details
            let detailsHtml = `
                <div class="row">
                    <div class="col-md-6">
                        <table class="table table-sm">
                            <tr><th>ID</th><td>${data.id}</td></tr>
                            <tr><th>Timestamp</th><td>${data.timestamp}</td></tr>
                            <tr><th>Source</th><td>${data.source_name}</td></tr>
                            <tr><th>Severity</th><td><span class="severity-badge severity-${data.severity.toLowerCase()}">${data.severity}</span></td></tr>
                            <tr><th>Event Type</th><td>${data.event_type || 'N/A'}</td></tr>
                        </table>
                    </div>
                    <div class="col-md-6">
                        <table class="table table-sm">
                            <tr><th>Source IP</th><td>${data.source_ip || 'N/A'}</td></tr>
                            <tr><th>Destination IP</th><td>${data.dest_ip || 'N/A'}</td></tr>
                            <tr><th>User</th><td>${data.user || 'N/A'}</td></tr>
                            <tr><th>Port</th><td>${data.port || 'N/A'}</td></tr>
                            <tr><th>Protocol</th><td>${data.protocol || 'N/A'}</td></tr>
                        </table>
                    </div>
                </div>
                
                <div class="mt-3">
                    <h6>Message</h6>
                    <div class="card card-body bg-light">
                        <pre style="white-space: pre-wrap; word-break: break-word;">${escapeHtml(data.message || '')}</pre>
                    </div>
                </div>
                
                <div class="row mt-3">
                    <div class="col-md-6">
                        <h6>Tags</h6>
                        <div class="d-flex flex-wrap gap-1">
                            ${data.tags_list && data.tags_list.length > 0 
                                ? data.tags_list.map(tag => `<span class="badge bg-info">${escapeHtml(tag)}</span>`).join('')
                                : '<span class="text-muted">No tags</span>'}
                        </div>
                    </div>
                    <div class="col-md-6">
                        <h6>TTP Match</h6>
                        ${data.ttp_match 
                            ? `<span class="badge bg-danger">${escapeHtml(data.ttp_match)}</span>`
                            : '<span class="text-muted">No TTP match</span>'}
                    </div>
                </div>
                
                <div class="mt-3">
                    <h6>Raw Log</h6>
                    <div class="card card-body bg-dark text-light">
                        <pre style="white-space: pre-wrap; word-break: break-word; font-size: 0.8rem;">${escapeHtml(data.raw_log || '')}</pre>
                    </div>
                </div>
            `;
            
            // Add related logs section if available
            if (data.related_logs && data.related_logs.length > 0) {
                detailsHtml += `
                    <div class="mt-4">
                        <h6>Related Logs (Same IP, ±1 hour)</h6>
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>Severity</th>
                                        <th>Message</th>
                                        <th>TTP</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${data.related_logs.map(log => `
                                        <tr>
                                            <td><small>${log.timestamp}</small></td>
                                            <td><span class="severity-badge severity-${log.severity.toLowerCase()}">${log.severity}</span></td>
                                            <td><small>${escapeHtml(log.message?.substring(0, 100) || '')}${log.message?.length > 100 ? '...' : ''}</small></td>
                                            <td>${log.ttp_match ? `<span class="badge bg-danger">${escapeHtml(log.ttp_match.substring(0, 20))}</span>` : '-'}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                `;
            }
            
            contentDiv.innerHTML = detailsHtml;
        })
        .catch(error => {
            contentDiv.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    Error loading log details: ${error.message}
                </div>
            `;
        });
}

// Copy functions
function copyLogToClipboard(logId) {
    fetch(`/api/logs/${logId}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                alert('Error: ' + data.error);
                return;
            }
            
            const text = `Log ID: ${data.id}
Timestamp: ${data.timestamp}
Source: ${data.source_name}
Severity: ${data.severity}
Message: ${data.message}
Source IP: ${data.source_ip || 'N/A'}
Destination IP: ${data.dest_ip || 'N/A'}
User: ${data.user || 'N/A'}
TTP Match: ${data.ttp_match || 'N/A'}
Tags: ${data.tags_list ? data.tags_list.join(', ') : 'None'}`;
            
            navigator.clipboard.writeText(text).then(() => {
                showToast('✅ Log copied to clipboard!', 'success');
            });
        })
        .catch(error => {
            alert('Error: ' + error.message);
        });
}

function copyModalContent() {
    const content = document.getElementById('logDetailsContent').innerText;
    navigator.clipboard.writeText(content).then(() => {
        showToast('✅ Details copied to clipboard!', 'success');
    });
}

// Export functions
function exportLogs(format, selectedOnly = false) {
    const searchParams = {
        search_query: '{{ search_params.search_query }}',
        severity: '{{ search_params.severity }}',
        source: '{{ search_params.source }}',
        source_ip: '{{ search_params.source_ip }}',
        user: '{{ search_params.user }}',
        event_type: '{{ search_params.event_type }}',
        date_from: '{{ search_params.date_from }}',
        date_to: '{{ search_params.date_to }}'
    };

    const payload = {
        format: format,
        search_params: searchParams
    };

    if (selectedOnly) {
        const selectedIds = getSelectedLogIds();
        if (selectedIds.length === 0) {
            showToast('Please select logs to export', 'warning');
            return;
        }
        payload.log_ids = selectedIds;
    }
    
    fetch('/api/logs/export', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload)
    })
    .then(async response => {
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error || 'Export failed');
        }
        return response.blob();
    })
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `logs_export_${new Date().toISOString().split('T')[0]}.${format}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        showToast(`✅ Exported ${format.toUpperCase()} file`, 'success');
    })
    .catch(error => {
        showToast('❌ Export failed: ' + error.message, 'danger');
    });
}

function exportSelectedLogs(format = 'csv') {
    exportLogs(format, true);
}

// Bulk actions
function bulkAddTag(tag) {
    const selectedIds = getSelectedLogIds();
    if (selectedIds.length === 0) {
        showToast('Please select logs to tag', 'warning');
        return;
    }
    
    if (confirm(`Add "${tag}" tag to ${selectedIds.length} selected logs?`)) {
        fetch('/api/logs/bulk-actions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action: 'add_tags',
                log_ids: selectedIds,
                tags: tag
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success' || data.success) {
                showToast(`✅ ${data.message || 'Tags updated'}`, 'success');
                setTimeout(() => location.reload(), 1200);
            } else {
                showToast(`❌ ${data.error || 'Tagging failed'}`, 'danger');
            }
        })
        .catch(error => {
            showToast('❌ Error: ' + error.message, 'danger');
        });
    }
}

function bulkAddCustomTag() {
    const tag = document.getElementById('customTagInput').value.trim();
    if (!tag) {
        showToast('Please enter a tag', 'warning');
        return;
    }
    bulkAddTag(tag);
}

function deleteSelectedLogs() {
    const selectedIds = getSelectedLogIds();
    if (selectedIds.length === 0) {
        showToast('Please select logs to delete', 'warning');
        return;
    }
    
    if (confirm(`Permanently delete ${selectedIds.length} selected logs? This cannot be undone.`)) {
        fetch('/api/logs/bulk-actions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action: 'delete',
                log_ids: selectedIds
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success' || data.success) {
                showToast(`✅ ${data.message || 'Logs deleted'}`, 'success');
                setTimeout(() => location.reload(), 1200);
            } else {
                showToast(`❌ ${data.error || 'Delete failed'}`, 'danger');
            }
        })
        .catch(error => {
            showToast('❌ Error: ' + error.message, 'danger');
        });
    }
}

function deleteLog(logId) {
    if (confirm('Delete this log entry?')) {
        fetch('/api/logs/bulk-actions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action: 'delete',
                log_ids: [logId]
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success' || data.success) {
                showToast('✅ Log deleted', 'success');
                setTimeout(() => location.reload(), 1200);
            } else {
                showToast(`❌ ${data.error || 'Delete failed'}`, 'danger');
            }
        })
        .catch(error => {
            showToast('❌ Error: ' + error.message, 'danger');
        });
    }
}

// Utility functions
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showToast(message, type = 'info') {
    // Remove existing toasts
    document.querySelectorAll('.toast').forEach(toast => toast.remove());
    
    const toastHtml = `
        <div class="toast align-items-center text-white bg-${type} border-0" role="alert" aria-live="assertive" aria-atomic="true" style="position: fixed; top: 20px; right: 20px; z-index: 1050;">
            <div class="d-flex">
                <div class="toast-body">
                    ${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
    `;
    
    const toastContainer = document.createElement('div');
    toastContainer.innerHTML = toastHtml;
    document.body.appendChild(toastContainer.firstElementChild);
    
    const toast = new bootstrap.Toast(toastContainer.firstElementChild);
    toast.show();
    
    // Auto remove after 3 seconds
    setTimeout(() => {
        if (toastContainer.firstElementChild) {
            toastContainer.firstElementChild.remove();
        }
    }, 3000);
}

// Add row click functionality
document.addEventListener('DOMContentLoaded', function() {
    // Make rows clickable to view details
    document.querySelectorAll('.log-row').forEach(row => {
        row.addEventListener('click', function(e) {
            // Don't trigger if clicking on checkbox or action buttons
            if (e.target.type === 'checkbox' || 
                e.target.closest('button') || 
                e.target.closest('.btn-group')) {
                return;
            }
            const logId = this.dataset.logId;
            viewLogDetails(logId, e);
        });
    });
    
    // Initialize Bootstrap select for better dropdowns
    if (typeof $ !== 'undefined') {
        $('select[data-live-search="true"]').selectpicker({
            liveSearch: true,
            size: 5
        });
    }
});
</script>
{% endblock %}

'''

THREATS_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Threat Detection{% endblock %}
{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="fas fa-exclamation-triangle me-2"></i>Threat Detection</h2>
    <div>
        <a href="{{ url_for('alerts') }}" class="btn btn-warning">
            <i class="fas fa-bell me-2"></i>View Alerts
        </a>
    </div>
</div>

<!-- TTP Overview -->
<div class="row mb-4">
    <div class="col-md-6">
        <div class="stat-card">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h6 class="text-muted mb-1">Total TTP Matches</h6>
                    <h2 class="stat-value text-danger">{{ threats|length }}</h2>
                </div>
                <i class="fas fa-crosshairs fa-3x text-danger"></i>
            </div>
            <small class="text-muted">Unique MITRE ATT&CK techniques detected</small>
        </div>
    </div>
    
    <div class="col-md-6">
        <div class="stat-card">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h6 class="text-muted mb-1">Critical Events</h6>
                    <h2 class="stat-value text-danger">
                        {{ recent_critical|selectattr('severity', 'equalto', 'CRITICAL')|list|length }}
                    </h2>
                </div>
                <i class="fas fa-fire fa-3x text-danger"></i>
            </div>
            <small class="text-muted">Critical severity threats detected</small>
        </div>
    </div>
</div>

<!-- Detected TTPs -->
<div class="table-container mb-4">
    <h5><i class="fas fa-list-alt me-2"></i>Detected TTPs (MITRE ATT&CK)</h5>
    <div class="table-responsive">
        <table class="table table-hover">
            <thead>
                <tr>
                    <th>TTP ID</th>
                    <th>Technique</th>
                    <th>Occurrences</th>
                    <th>First Seen</th>
                    <th>Last Seen</th>
                    <th>Sources</th>
                </tr>
            </thead>
            <tbody>
                {% for threat in threats %}
                <tr>
                    <td>
                        <span class="badge bg-danger">
                            {{ threat.ttp_match.split(':')[0] if threat.ttp_match and ':' in threat.ttp_match else 'Unknown' }}
                        </span>
                    </td>
                    <td>
                        <strong>{{ threat.ttp_match.split(':', 1)[1] if threat.ttp_match and ':' in threat.ttp_match else threat.ttp_match }}</strong>
                    </td>
                    <td>
                        <span class="badge bg-dark">{{ threat.count }}</span>
                    </td>
                    <td><small>{{ threat.first_seen }}</small></td>
                    <td><small>{{ threat.last_seen }}</small></td>
                    <td>
                        <small>{{ threat.sources|safetruncate(50) }}</small>
                        {% if threat.related_playbooks and threat.related_playbooks|length > 0 %}
                        <div class="mt-1">
                            <small class="text-muted d-block">Playbooks:</small>
                            {% for pb in threat.related_playbooks %}
                                <a href="{{ url_for('runbook', pb_id=pb.id) }}" class="badge bg-info text-dark me-1" style="font-size: 0.7rem;">{{ pb.id }}</a>
                            {% endfor %}
                        </div>
                        {% endif %}
                    </td>
                </tr>
                {% else %}
                <tr>
                    <td colspan="6" class="text-center text-muted">
                        No TTP matches detected yet
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<!-- Recent Critical Events -->
<div class="table-container">
    <h5><i class="fas fa-history me-2"></i>Recent Critical & High Severity Events</h5>
    <div class="table-responsive">
        <table class="table table-hover">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Severity</th>
                    <th>Source</th>
                    <th>Message</th>
                    <th>TTP</th>
                </tr>
            </thead>
            <tbody>
                {% for event in recent_critical %}
                <tr>
                    <td><small>{{ event.timestamp }}</small></td>
                    <td>
                        <span class="severity-badge severity-{{ event.severity|lower }}">
                            {{ event.severity }}
                        </span>
                    </td>
                    <td><small>{{ event.source_name }}</small></td>
                    <td>
                        <small>{{ event.message|safetruncate(60) }}</small>
                    </td>
                    <td>
                        {% if event.ttp_match %}
                        <span class="badge bg-danger" title="{{ event.ttp_match }}">
                            {{ event.ttp_match|safetruncate(30) }}
                        </span>
                        {% else %}
                        <span class="text-muted">-</span>
                        {% endif %}
                    </td>
                </tr>
                {% else %}
                <tr>
                    <td colspan="6" class="text-center text-muted">
                        No critical events found
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<!-- Threat Intelligence Info -->
<div class="row mt-4">
    <div class="col-md-6">
        <div class="stat-card">
            <h5><i class="fas fa-database me-2"></i>Threat Intelligence</h5>
            <p class="text-muted">Threat intelligence will be displayed here based on real log analysis and uploaded threat feeds.</p>
            <div class="alert alert-info">
                <i class="fas fa-info-circle me-2"></i>
                <strong>Note:</strong> Upload log files to build your threat intelligence database.
            </div>
        </div>
    </div>
    
    <div class="col-md-6">
        <div class="stat-card">
            <h5><i class="fas fa-cog me-2"></i>Quick Actions</h5>
            <div class="d-grid gap-2">
                <button class="btn btn-outline-primary" onclick="alert('Custom rule creation would be implemented here')">
                    <i class="fas fa-plus me-2"></i>Add Custom Rule
                </button>
                <button class="btn btn-outline-success" onclick="alert('Threat feed update would be implemented here')">
                    <i class="fas fa-sync me-2"></i>Update Threat Feed
                </button>
                <a href="{{ url_for('reports') }}" class="btn btn-outline-danger">
                    <i class="fas fa-file-export me-2"></i>Export Threat Report
                </a>
            </div>
        </div>
    </div>
</div>
{% endblock %}
'''

PLAYBOOKS_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Playbooks{% endblock %}
{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="fas fa-book me-2"></i>Investigation Playbooks</h2>
    <div>
        <a href="{{ url_for('dashboard') }}" class="btn btn-outline-secondary">Back</a>
    </div>
    </div>
    <div class="table-container">
        <div class="table-responsive">
            <table class="table table-hover">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Category</th>
                        <th>Severity</th>
                        <th>MITRE</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for pb in playbooks %}
                    <tr>
                        <td><span class="badge bg-primary">{{ pb.id }}</span></td>
                        <td><strong>{{ pb.name }}</strong><br><small class="text-muted">{{ pb.description|safetruncate(80) }}</small></td>
                        <td>{{ pb.category }}</td>
                        <td><span class="severity-badge severity-{{ pb.severity|lower }}">{{ pb.severity }}</span></td>
                        <td><small>{{ pb.mitre|join(', ') }}</small></td>
                        <td>
                            <a href="{{ url_for('runbook', pb_id=pb.id) }}" class="btn btn-sm btn-outline-primary">
                                <i class="fas fa-clipboard-list me-1"></i>View Runbook
                            </a>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
{% endblock %}
'''

RUNBOOK_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Runbook {{ playbook.id }}{% endblock %}
{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="fas fa-clipboard-list me-2"></i>{{ playbook.name }}</h2>
    <div>
        <a href="{{ url_for('playbooks') }}" class="btn btn-outline-secondary">Back to Playbooks</a>
    </div>
</div>

<div class="row g-4">
    <div class="col-lg-8">
        <div class="table-container">
            <h5><i class="fas fa-list-ol me-2"></i>Runbook Steps</h5>
            <ol class="mt-3">
                {% for step in runbook.steps %}
                <li class="mb-2">{{ step }}</li>
                {% endfor %}
            </ol>
        </div>
    </div>
    <div class="col-lg-4">
        <div class="table-container">
            <h5><i class="fas fa-info-circle me-2"></i>Playbook Details</h5>
            <ul class="list-group list-group-flush">
                <li class="list-group-item"><strong>ID:</strong> {{ playbook.id }}</li>
                <li class="list-group-item"><strong>Category:</strong> {{ playbook.category }}</li>
                <li class="list-group-item"><strong>Severity:</strong> {{ playbook.severity }}</li>
                <li class="list-group-item"><strong>MITRE:</strong> {{ playbook.mitre|join(', ') }}</li>
                <li class="list-group-item"><strong>Event Types:</strong> {{ playbook.event_types|join(', ') }}</li>
                <li class="list-group-item"><strong>Description:</strong> {{ playbook.description }}</li>
            </ul>
        </div>
    </div>
</div>
{% endblock %}
'''

ALERTS_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Security Alerts{% endblock %}
{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="fas fa-bell me-2"></i>Security Alerts</h2>
    <div>
        <button class="btn btn-danger" onclick="markAllAsRead()">
            <i class="fas fa-check-double me-2"></i>Mark All as Read
        </button>
    </div>
</div>

<!-- Alerts Summary -->
<div class="row mb-4">
    <div class="col-md-3 mb-3">
        <div class="stat-card">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h6 class="text-muted mb-1">Total Alerts</h6>
                    <h2 class="stat-value text-primary">{{ alerts|length }}</h2>
                </div>
                <i class="fas fa-bell fa-3x text-primary"></i>
            </div>
            <small class="text-muted">All security alerts</small>
        </div>
    </div>
    
    <div class="col-md-3 mb-3">
        <div class="stat-card critical">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h6 class="text-muted mb-1">New Alerts</h6>
                    <h2 class="stat-value text-danger">{{ alerts|selectattr('status', 'equalto', 'new')|list|length }}</h2>
                </div>
                <i class="fas fa-exclamation-circle fa-3x text-danger"></i>
            </div>
            <small class="text-muted">Unresolved alerts</small>
        </div>
    </div>
    
    <div class="col-md-3 mb-3">
        <div class="stat-card high">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h6 class="text-muted mb-1">High Severity</h6>
                    <h2 class="stat-value text-warning">{{ alerts|selectattr('severity', 'equalto', 'HIGH')|list|length }}</h2>
                </div>
                <i class="fas fa-exclamation-triangle fa-3x text-warning"></i>
            </div>
            <small class="text-muted">High severity alerts</small>
        </div>
    </div>
    
    <div class="col-md-3 mb-3">
        <div class="stat-card success">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h6 class="text-muted mb-1">Resolved</h6>
                    <h2 class="stat-value text-success">{{ alerts|selectattr('status', 'equalto', 'resolved')|list|length }}</h2>
                </div>
                <i class="fas fa-check-circle fa-3x text-success"></i>
            </div>
            <small class="text-muted">Resolved alerts</small>
        </div>
    </div>
</div>

<!-- Alerts Table -->
<div class="table-container">
    <div class="table-responsive">
        <table class="table table-hover">
            <thead>
                <tr>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Threat Type</th>
                    <th>TTP</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {% for alert in alerts %}
                <tr class="{% if alert.status == 'new' %}table-warning{% endif %}">
                    <td>
                        <strong>{{ alert.title }}</strong><br>
                        <small class="text-muted">{{ alert.description|safetruncate(50) }}</small>
                    </td>
                    <td>
                        <span class="severity-badge severity-{{ alert.severity|lower }}">
                            {{ alert.severity }}
                        </span>
                    </td>
                    <td>
                        <span class="badge bg-{{ 'success' if alert.status == 'resolved' else 'warning' }}">
                            {{ alert.status|title }}
                        </span>
                    </td>
                    <td>
                        <small>{{ alert.threat_type or 'Unknown' }}</small>
                    </td>
                    <td>
                        {% if alert.ttp_match %}
                        <small class="text-danger">{{ alert.ttp_match|safetruncate(30) }}</small>
                        {% else %}
                        <span class="text-muted">-</span>
                        {% endif %}
                    </td>
                    <td>
                        <small>{{ alert.created_at }}</small>
                    </td>
                    <td>
                        <div class="btn-group btn-group-sm" role="group">
                            <button type="button" class="btn btn-sm btn-outline-info" onclick="viewAlert({{ alert.id }})" title="View Alert">
                                <i class="fas fa-eye"></i>
                            </button>
                            {% if alert.status != 'resolved' %}
                            <button type="button" class="btn btn-sm btn-outline-success" onclick="resolveAlert({{ alert.id }})" title="Mark as Resolved">
                                <i class="fas fa-check"></i>
                            </button>
                            {% endif %}
                            <button type="button" class="btn btn-sm btn-outline-danger" onclick="deleteAlert({{ alert.id }})" title="Delete Alert">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </td>
                </tr>
                {% else %}
                <tr>
                    <td colspan="7" class="text-center text-muted">
                        No alerts found
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<!-- Alert Actions -->
<div class="row mt-4">
    <div class="col-12">
        <div class="table-container">
            <h5><i class="fas fa-cog me-2"></i>Alert Management</h5>
            <div class="row text-center">
                <div class="col-md-4 mb-3">
                    <button class="btn btn-outline-primary w-100" onclick="exportAlerts()">
                        <i class="fas fa-file-export fa-2x mb-2"></i><br>
                        Export Alerts
                    </button>
                </div>
                <div class="col-md-4 mb-3">
                    <button class="btn btn-outline-success w-100" onclick="refreshAlerts()">
                        <i class="fas fa-sync fa-2x mb-2"></i><br>
                        Refresh
                    </button>
                </div>
                <div class="col-md-4 mb-3">
                    <button class="btn btn-outline-danger w-100" onclick="clearResolvedAlerts()">
                        <i class="fas fa-trash-alt fa-2x mb-2"></i><br>
                        Clear Resolved
                    </button>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
function viewAlert(alertId) {
    if (!alertId) {
        alert('❌ Error: Alert ID is missing');
        return;
    }
    fetch(`/api/alerts/${alertId}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.error) {
                alert('❌ ' + data.error);
                return;
            }
            let alertDetails = `Alert Details\n\n` +
                `Title: ${data.title}\n` +
                `Severity: ${data.severity}\n` +
                `Status: ${data.status}\n` +
                `Type: ${data.threat_type || 'Unknown'}\n` +
                `TTP: ${data.ttp_match || 'Not specified'}\n` +
                `Created: ${data.created_at}\n\n` +
                `Description:\n${data.description}`;
            alert(alertDetails);
        })
        .catch(error => {
            alert('❌ Error loading alert details: ' + error.message);
        });
}

function resolveAlert(alertId) {
    if (!alertId) {
        alert('❌ Error: Alert ID is missing');
        return;
    }
    if (confirm('Mark this alert as resolved?')) {
        fetch(`/api/alerts/resolve/${alertId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                alert('✅ Alert marked as resolved successfully!');
                setTimeout(() => window.location.reload(), 500);
            } else {
                alert('❌ Error: ' + (data.error || 'Unknown error'));
            }
        })
        .catch(error => {
            alert('❌ Error resolving alert: ' + error.message);
        });
    }
}

function deleteAlert(alertId) {
    if (!alertId) {
        alert('❌ Error: Alert ID is missing');
        return;
    }
    if (confirm('Are you sure you want to delete this alert? This action cannot be undone.')) {
        fetch(`/api/alerts/delete/${alertId}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                alert('✅ Alert deleted successfully!');
                setTimeout(() => window.location.reload(), 500);
            } else {
                alert('❌ Error: ' + (data.error || 'Unknown error'));
            }
        })
        .catch(error => {
            alert('❌ Error deleting alert: ' + error.message);
        });
    }
}

function markAllAsRead() {
    if (confirm('Mark all new alerts as read?')) {
        fetch('/api/alerts/mark-all-read', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                alert('✅ ' + data.message);
                setTimeout(() => window.location.reload(), 500);
            } else {
                alert('❌ Error: ' + (data.error || 'Unknown error'));
            }
        })
        .catch(error => {
            alert('❌ Error: ' + error.message);
        });
    }
}

function exportAlerts() {
    const table = document.querySelector('table');
    if (!table) {
        alert('No alerts to export');
        return;
    }
    
    let csv = 'Title,Severity,Status,Threat Type,TTP,Created At\n';
    
    document.querySelectorAll('table tbody tr').forEach(row => {
        const cells = row.querySelectorAll('td');
        if (cells.length >= 6) {
            const title = cells[0].textContent.split('\n')[0].trim();
            const severity = cells[1].textContent.trim();
            const status = cells[2].textContent.trim();
            const threatType = cells[3].textContent.trim();
            const ttp = cells[4].textContent.trim();
            const created = cells[5].textContent.trim();
            
            csv += `"${title}","${severity}","${status}","${threatType}","${ttp}","${created}"\n`;
        }
    });
    
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `alerts_${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
    
    alert('✅ Alerts exported successfully!');
}

function refreshAlerts() {
    window.location.reload();
}

function clearResolvedAlerts() {
    if (confirm('Delete all resolved alerts? This action cannot be undone.')) {
        let deleteCount = 0;
        const resolvedButtons = document.querySelectorAll('[onclick*="deleteAlert"]');
        const resolvedAlerts = [];
        
        // Find all resolved alerts
        document.querySelectorAll('table tbody tr').forEach(row => {
            const statusCell = row.querySelector('td:nth-child(3)');
            if (statusCell && statusCell.textContent.includes('Resolved')) {
                const firstCell = row.querySelector('td:first-child');
                const actionButtons = row.querySelectorAll('button');
                if (actionButtons.length > 0) {
                    const deleteBtn = Array.from(actionButtons).find(btn => btn.textContent.includes('fa-trash'));
                    if (deleteBtn) {
                        resolvedAlerts.push(deleteBtn);
                    }
                }
            }
        });
        
        if (resolvedAlerts.length === 0) {
            alert('No resolved alerts to delete');
            return;
        }
        
        // Delete all resolved alerts
        let completed = 0;
        resolvedAlerts.forEach(btn => {
            const alertId = btn.getAttribute('onclick').match(/\\d+/)[0];
            fetch(`/api/alerts/delete/${alertId}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                }
            })
            .then(response => response.json())
            .then(data => {
                completed++;
                if (completed === resolvedAlerts.length) {
                    alert(`✅ Deleted ${completed} resolved alerts`);
                    setTimeout(() => window.location.reload(), 500);
                }
            })
            .catch(error => console.error('Error:', error));
        });
    }
}
</script>
{% endblock %}
'''

REPORTS_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Reports & Analytics{% endblock %}
{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="fas fa-chart-bar me-2"></i>Reports & Analytics</h2>
    <div>
        <a href="{{ url_for('reports') }}?type=csv" class="btn btn-success">
            <i class="fas fa-download me-2"></i>Export CSV
        </a>
        <a href="{{ url_for('reports') }}?type=pdf" class="btn btn-danger">
            <i class="fas fa-file-pdf me-2"></i>Export PDF
        </a>
    </div>
</div>

<!-- Report Display -->
<div class="table-container mb-4">
    <h5><i class="fas fa-file-alt me-2"></i>Generated Report</h5>
    <div class="alert alert-info mb-3">
        <i class="fas fa-info-circle me-2"></i>
        Report generated on {{ now.strftime('%Y-%m-%d %H:%M:%S') }}
    </div>
    
    <div class="border rounded p-3" style="max-height: 600px; overflow-y: auto; overflow-x: auto; width: 100%;">
        <div style="word-wrap: break-word; overflow-wrap: break-word;">
            {{ report_content|safe }}
        </div>
    </div>
</div>

<!-- Report Generation Options -->
<div class="row">
    <div class="col-md-6">
        <div class="table-container">
            <h5><i class="fas fa-cogs me-2"></i>Report Options</h5>
            <form method="GET" action="{{ url_for('reports') }}">
                <div class="mb-3">
                    <label class="form-label">Report Type</label>
                    <select class="form-select" name="type">
                        <option value="html">HTML Summary Report</option>
                        <option value="csv">CSV Export</option>
                        <option value="pdf">PDF Report</option>
                    </select>
                </div>
                
                <div class="mb-3">
                    <label class="form-label">Time Range</label>
                    <select class="form-select" name="range">
                        <option value="today">Today</option>
                        <option value="yesterday">Yesterday</option>
                        <option value="last7">Last 7 Days</option>
                        <option value="last30">Last 30 Days</option>
                        <option value="all">All Time</option>
                    </select>
                </div>
                
                <button type="submit" class="btn btn-primary w-100">
                    <i class="fas fa-play me-2"></i>Generate Report
                </button>
            </form>
        </div>
    </div>
    
    <div class="col-md-6">
        <div class="table-container">
            <h5><i class="fas fa-templates me-2"></i>Quick Reports</h5>
            <div class="d-grid gap-2">
                <a href="{{ url_for('reports') }}" class="btn btn-outline-primary">
                    <i class="fas fa-shield-alt me-2"></i>Security Summary
                </a>
                <a href="{{ url_for('reports') }}?type=csv" class="btn btn-outline-success">
                    <i class="fas fa-file-csv me-2"></i>Export All Logs (CSV)
                </a>
                <a href="{{ url_for('reports') }}?type=pdf" class="btn btn-outline-danger">
                    <i class="fas fa-file-pdf me-2"></i>Export as PDF
                </a>
                <button class="btn btn-outline-warning" onclick="alert('Compliance report generation would be implemented here')">
                    <i class="fas fa-file-contract me-2"></i>Compliance Report
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Scheduled Reports -->
<div class="table-container mt-4">
    <h5><i class="fas fa-clock me-2"></i>Scheduled Reports</h5>
    <div class="alert alert-warning">
        <i class="fas fa-exclamation-triangle me-2"></i>
        Scheduled reports feature is not yet implemented. In a full implementation, this would allow setting up automatic report generation and delivery.
    </div>
    
    <table class="table table-hover">
        <thead>
            <tr>
                <th>Report Name</th>
                <th>Schedule</th>
                <th>Format</th>
                <th>Recipients</th>
                <th>Status</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td colspan="6" class="text-center text-muted">
                    No scheduled reports configured
                </td>
            </tr>
        </tbody>
    </table>
    
    <button class="btn btn-outline-primary" onclick="alert('Schedule new report dialog would open here')">
        <i class="fas fa-plus me-2"></i>Schedule New Report
    </button>
</div>
{% endblock %}
'''

RULES_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Custom Rules{% endblock %}
{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4 flex-wrap gap-2">
    <div>
        <h2 class="mb-1"><i class="fas fa-user-shield me-2"></i>Custom Detection Rules</h2>
        <small class="text-muted">Define your own signature, behavior, heuristic, and anomaly detection rules</small>
    </div>
    <span class="badge bg-primary fs-6"><i class="fas fa-shield-alt me-1"></i>{{ rules|length }} Rules</span>
</div>

<div class="row g-4">
    <div class="col-lg-5">
        <div class="rule-form-card h-100">
            <h5 class="mb-4"><i class="fas fa-plus-circle me-2"></i>Create New Rule</h5>
            <form method="POST" class="mt-3">
                <div class="mb-3">
                    <label class="form-label"><i class="fas fa-code me-1"></i>JSON Rule Definition</label>
                    <textarea name="json_rule" class="form-control font-monospace" rows="18" placeholder='Enter JSON rule definition...
Example:
{
  "name": "Suspicious PowerShell Execution",
  "description": "Detects PowerShell encoded commands",
  "rule_type": "signature",
  "field": "message",
  "pattern": "powershell.*(-enc|-encodedcommand)",
  "severity": "HIGH",
  "tags": ["powershell", "execution"],
  "enabled": true
}' required style="font-size: 0.9rem;"></textarea>
                    <small class="text-muted d-block mt-2">
                        <i class="fas fa-info-circle me-1"></i>
                        <strong>Required fields:</strong> name, pattern<br>
                        <strong>Optional fields:</strong> description, rule_type (signature|behavior|heuristic|anomaly), 
                        field (message|raw_log|source_ip|dest_ip|user|tags), 
                        severity (CRITICAL|HIGH|MEDIUM|LOW|INFO), 
                        tags (array or comma-separated string), enabled (boolean)
                    </small>
                </div>
                <button class="btn btn-light w-100 py-2" type="submit">
                    <i class="fas fa-save me-2"></i>Add Detection Rule
                </button>
            </form>
            <hr class="my-4">
            <div class="p-3 bg-light rounded">
                <h6 class="mb-2"><i class="fas fa-lightbulb me-1"></i>Quick Start Templates</h6>
                <div class="d-grid gap-2">
                    <button class="btn btn-sm btn-outline-secondary text-start" onclick="fillTemplate('powershell')">
                        <i class="fas fa-terminal me-1"></i>PowerShell Detection
                    </button>
                    <button class="btn btn-sm btn-outline-secondary text-start" onclick="fillTemplate('sql')">
                        <i class="fas fa-database me-1"></i>SQL Injection
                    </button>
                    <button class="btn btn-sm btn-outline-secondary text-start" onclick="fillTemplate('bruteforce')">
                        <i class="fas fa-user-lock me-1"></i>Brute Force Attack
                    </button>
                </div>
            </div>
        </div>
    </div>
    <div class="col-lg-7">
        <div class="table-container h-100">
            <h5 class="d-flex justify-content-between align-items-center mb-3">
                <span><i class="fas fa-list-ul me-2"></i>Active Detection Rules</span>
                <span class="badge bg-info">{{ rules|selectattr('enabled', 'equalto', True)|list|length }} Enabled</span>
            </h5>
            <div class="rules-table-wrapper">
                <div class="table-responsive">
                    <table class="table table-hover align-middle">
                        <thead class="table-light">
                            <tr>
                                <th style="width: 25%;">Name</th>
                                <th style="width: 10%;">Type</th>
                                <th style="width: 10%;">Field</th>
                                <th style="width: 10%;">Severity</th>
                                <th style="width: 25%;">Pattern</th>
                                <th style="width: 10%;">Tags</th>
                                <th style="width: 10%;">Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% if rules %}
                                {% for rule in rules %}
                                <tr class="{% if not rule.enabled %}table-secondary{% endif %}">
                                    <td>
                                        <strong class="d-block">{{ rule.name }}</strong>
                                        {% if rule.description %}
                                        <small class="text-muted">{{ rule.description|safetruncate(50) }}</small>
                                        {% endif %}
                                    </td>
                                    <td>
                                        <span class="badge bg-secondary text-uppercase" style="font-size: 0.7rem;">
                                            {{ rule.rule_type[:4] }}
                                        </span>
                                    </td>
                                    <td><small>{{ rule.field }}</small></td>
                                    <td>
                                        <span class="badge {% if rule.severity in ['CRITICAL','HIGH'] %}bg-danger{% elif rule.severity=='MEDIUM' %}bg-warning{% else %}bg-info{% endif %}">
                                            {{ rule.severity }}
                                        </span>
                                    </td>
                                    <td>
                                        <code class="small" style="font-size: 0.75rem; word-break: break-all;">
                                            {{ rule.pattern|safetruncate(35) }}
                                        </code>
                                    </td>
                                    <td>
                                        {% if rule.tags %}
                                            <small class="text-muted">{{ rule.tags|join(', ')|safetruncate(15) }}</small>
                                        {% else %}
                                            <small class="text-muted">-</small>
                                        {% endif %}
                                    </td>
                                    <td>
                                        {% if rule.enabled %}
                                            <span class="badge bg-success"><i class="fas fa-check-circle me-1"></i>Active</span>
                                        {% else %}
                                            <span class="badge bg-secondary"><i class="fas fa-pause-circle me-1"></i>Disabled</span>
                                        {% endif %}
                                    </td>
                                </tr>
                                {% endfor %}
                            {% else %}
                                <tr>
                                    <td colspan="7" class="text-center text-muted py-5">
                                        <i class="fas fa-inbox fa-3x mb-3 d-block text-secondary"></i>
                                        <strong>No custom rules defined yet</strong><br>
                                        <small>Create your first rule to start detecting custom threat patterns</small>
                                    </td>
                                </tr>
                            {% endif %}
                        </tbody>
                    </table>
                </div>
            </div>
            {% if rules %}
            <div class="mt-3 p-3 bg-light rounded">
                <div class="row text-center">
                    <div class="col-md-4">
                        <strong class="text-primary d-block">{{ rules|selectattr('rule_type', 'equalto', 'signature')|list|length }}</strong>
                        <small class="text-muted">Signature Rules</small>
                    </div>
                    <div class="col-md-4">
                        <strong class="text-success d-block">{{ rules|selectattr('rule_type', 'equalto', 'heuristic')|list|length }}</strong>
                        <small class="text-muted">Heuristic Rules</small>
                    </div>
                    <div class="col-md-4">
                        <strong class="text-warning d-block">{{ rules|selectattr('rule_type', 'equalto', 'anomaly')|list|length }}</strong>
                        <small class="text-muted">Anomaly Rules</small>
                    </div>
                </div>
            </div>
            {% endif %}
        </div>
    </div>
</div>

<!-- Help Section -->
<div class="row mt-4">
    <div class="col-12">
        <div class="table-container">
            <h5><i class="fas fa-question-circle me-2"></i>Rule Types Guide</h5>
            <div class="row">
                <div class="col-md-3">
                    <div class="p-3 bg-light rounded">
                        <h6 class="text-primary"><i class="fas fa-signature me-1"></i>Signature</h6>
                        <small class="text-muted">Matches known attack patterns using regex</small>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="p-3 bg-light rounded">
                        <h6 class="text-success"><i class="fas fa-brain me-1"></i>Behavior</h6>
                        <small class="text-muted">Detects suspicious behavioral patterns</small>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="p-3 bg-light rounded">
                        <h6 class="text-info"><i class="fas fa-search me-1"></i>Heuristic</h6>
                        <small class="text-muted">Identifies potential threats through analysis</small>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="p-3 bg-light rounded">
                        <h6 class="text-warning"><i class="fas fa-chart-line me-1"></i>Anomaly</h6>
                        <small class="text-muted">Flags unusual or abnormal activities</small>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
function fillTemplate(type) {
    const textarea = document.querySelector('textarea[name="json_rule"]');
    const templates = {
        powershell: `{
  "name": "Suspicious PowerShell Execution",
  "description": "Detects PowerShell encoded commands",
  "rule_type": "signature",
  "field": "message",
  "pattern": "powershell.*(-enc|-encodedcommand)",
  "severity": "HIGH",
  "tags": ["powershell", "execution"],
  "enabled": true
}`,
        sql: `{
  "name": "SQL Injection Attempt",
  "description": "Detects common SQL injection patterns",
  "rule_type": "signature",
  "field": "message",
  "pattern": "(union.*select|select.*from|insert.*into|drop.*table)",
  "severity": "CRITICAL",
  "tags": ["sql", "injection", "web"],
  "enabled": true
}`,
        bruteforce: `{
  "name": "Brute Force Authentication",
  "description": "Detects multiple failed login attempts",
  "rule_type": "behavior",
  "field": "message",
  "pattern": "(failed.*login|authentication.*failed|invalid.*password)",
  "severity": "HIGH",
  "tags": ["authentication", "bruteforce"],
  "enabled": true
}`
    };
    
    if (templates[type]) {
        textarea.value = templates[type];
        textarea.focus();
    }
}
</script>
{% endblock %}
'''

# Append a scripts block to Rules template to support rule testing UI
# Test rule scripts removed

VIEW_RULES_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Loaded Playbook Rules{% endblock %}
{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4 flex-wrap gap-2">
    <div>
        <h2 class="mb-1"><i class="fas fa-shield-alt me-2"></i>Detection Rules Dashboard</h2>
        <small class="text-muted">All loaded playbook rules for threat detection</small>
    </div>
    <div>
        <span class="badge bg-success fs-6 px-3 py-2">
            <i class="fas fa-check-circle me-1"></i>{{ total_playbooks }} Playbooks Loaded
        </span>
        <span class="badge bg-primary fs-6 px-3 py-2 ms-2">
            <i class="fas fa-book me-1"></i>{{ total_rules }} Total Rules
        </span>
    </div>
</div>

<!-- Summary Cards -->
<div class="row mb-4">
    <div class="col-md-3">
        <div class="card border-primary shadow-sm">
            <div class="card-body text-center">
                <i class="fas fa-book fa-2x text-primary mb-2"></i>
                <h3 class="mb-0">{{ total_playbooks }}</h3>
                <small class="text-muted">Playbooks</small>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card border-success shadow-sm">
            <div class="card-body text-center">
                <i class="fas fa-clipboard-list fa-2x text-success mb-2"></i>
                <h3 class="mb-0">{{ total_rules }}</h3>
                <small class="text-muted">Total Rules</small>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card border-danger shadow-sm">
            <div class="card-body text-center">
                <i class="fas fa-exclamation-triangle fa-2x text-danger mb-2"></i>
                <h3 class="mb-0">{{ playbook_stats|selectattr('severity_breakdown.Critical')|list|length }}</h3>
                <small class="text-muted">Playbooks with Critical Rules</small>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card border-info shadow-sm">
            <div class="card-body text-center">
                <i class="fas fa-toggle-on fa-2x text-info mb-2"></i>
                <h3 class="mb-0">{{ playbook_stats|sum(attribute='enabled_count') }}</h3>
                <small class="text-muted">Enabled Rules</small>
            </div>
        </div>
    </div>
</div>

<!-- Playbooks Table -->
<div class="card shadow-sm">
    <div class="card-header bg-dark text-white">
        <i class="fas fa-table me-2"></i>Playbook Details
    </div>
    <div class="card-body p-0">
        <div class="table-responsive">
            <table class="table table-hover mb-0">
                <thead class="table-light">
                    <tr>
                        <th><i class="fas fa-tag me-1"></i>Type</th>
                        <th><i class="fas fa-info-circle me-1"></i>Name</th>
                        <th><i class="fas fa-file-alt me-1"></i>Log Type</th>
                        <th class="text-center"><i class="fas fa-list-ol me-1"></i>Rules</th>
                        <th class="text-center"><i class="fas fa-exclamation-circle me-1"></i>Critical</th>
                        <th class="text-center"><i class="fas fa-exclamation me-1"></i>High</th>
                        <th class="text-center"><i class="fas fa-minus-circle me-1"></i>Medium</th>
                        <th class="text-center"><i class="fas fa-info-circle me-1"></i>Low</th>
                        <th class="text-center"><i class="fas fa-toggle-on me-1"></i>Enabled</th>
                    </tr>
                </thead>
                <tbody>
                    {% for stat in playbook_stats %}
                    <tr style="cursor: pointer;" onclick="window.location.href='{{ url_for('view_rules') }}?playbook={{ stat.type }}';" class="playbook-row">
                        <td>
                            <span class="badge bg-secondary">{{ stat.type }}</span>
                        </td>
                        <td>
                            <strong>{{ stat.name }}</strong>
                            <br><small class="text-muted">{{ stat.description[:80] }}...</small>
                        </td>
                        <td>
                            <span class="badge bg-info">{{ stat.log_type }}</span>
                        </td>
                        <td class="text-center">
                            <span class="badge bg-primary">{{ stat.rule_count }}</span>
                        </td>
                        <td class="text-center">
                            {% if stat.severity_breakdown.Critical > 0 %}
                            <span class="badge bg-danger">{{ stat.severity_breakdown.Critical }}</span>
                            {% else %}
                            <span class="text-muted">0</span>
                            {% endif %}
                        </td>
                        <td class="text-center">
                            {% if stat.severity_breakdown.High > 0 %}
                            <span class="badge bg-warning">{{ stat.severity_breakdown.High }}</span>
                            {% else %}
                            <span class="text-muted">0</span>
                            {% endif %}
                        </td>
                        <td class="text-center">
                            {% if stat.severity_breakdown.Medium > 0 %}
                            <span class="badge bg-secondary">{{ stat.severity_breakdown.Medium }}</span>
                            {% else %}
                            <span class="text-muted">0</span>
                            {% endif %}
                        </td>
                        <td class="text-center">
                            {% if stat.severity_breakdown.Low > 0 %}
                            <span class="badge bg-light text-dark">{{ stat.severity_breakdown.Low }}</span>
                            {% else %}
                            <span class="text-muted">0</span>
                            {% endif %}
                        </td>
                        <td class="text-center">
                            <span class="badge bg-success">{{ stat.enabled_count }}</span>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>

<!-- Rule Distribution Chart -->
<div class="row mt-4">
    <div class="col-md-6">
        <div class="card shadow-sm">
            <div class="card-header bg-dark text-white">
                <i class="fas fa-chart-pie me-2"></i>Rules by Playbook Type
            </div>
            <div class="card-body">
                <canvas id="playbookChart"></canvas>
            </div>
        </div>
    </div>
    <div class="col-md-6">
        <div class="card shadow-sm">
            <div class="card-header bg-dark text-white">
                <i class="fas fa-chart-bar me-2"></i>Severity Distribution
            </div>
            <div class="card-body">
                <canvas id="severityChart"></canvas>
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
// Playbook Distribution Chart
const playbookData = {
    labels: [
        {% for stat in playbook_stats %}
        '{{ stat.type }}',
        {% endfor %}
    ],
    datasets: [{
        label: 'Rules Count',
        data: [
            {% for stat in playbook_stats %}
            {{ stat.rule_count }},
            {% endfor %}
        ],
        backgroundColor: [
            '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF',
            '#FF9F40', '#FF6384', '#C9CBCF', '#4BC0C0', '#FF6384', '#36A2EB'
        ]
    }]
};

const playbookChart = new Chart(document.getElementById('playbookChart'), {
    type: 'pie',
    data: playbookData,
    options: {
        responsive: true,
        plugins: {
            legend: {
                position: 'bottom'
            }
        }
    }
});

// Severity Distribution Chart
const severityData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{
        label: 'Rules by Severity',
        data: [
            {{ playbook_stats|sum(attribute='severity_breakdown.Critical') }},
            {{ playbook_stats|sum(attribute='severity_breakdown.High') }},
            {{ playbook_stats|sum(attribute='severity_breakdown.Medium') }},
            {{ playbook_stats|sum(attribute='severity_breakdown.Low') }}
        ],
        backgroundColor: ['#dc3545', '#ffc107', '#6c757d', '#17a2b8']
    }]
};

const severityChart = new Chart(document.getElementById('severityChart'), {
    type: 'bar',
    data: severityData,
    options: {
        responsive: true,
        plugins: {
            legend: {
                display: false
            }
        },
        scales: {
            y: {
                beginAtZero: true
            }
        }
    }
});
</script>

<style>
.card {
    transition: transform 0.2s;
}
.card:hover {
    transform: translateY(-2px);
}
.table th {
    font-weight: 600;
    font-size: 0.85rem;
}
.badge {
    font-size: 0.85rem;
}
.playbook-row:hover {
    background-color: #f8f9fa !important;
}
.playbook-row {
    transition: background-color 0.2s;
}
</style>

{% endblock %}
'''

EDIT_PLAYBOOK_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Edit {{ playbook.name }} Playbook{% endblock %}
{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4 flex-wrap gap-2">
    <div>
        <a href="{{ url_for('view_rules') }}" class="btn btn-sm btn-outline-secondary mb-2">
            <i class="fas fa-arrow-left me-1"></i>Back to All Playbooks
        </a>
        <h2 class="mb-1"><i class="fas fa-edit me-2"></i>{{ playbook.name }}</h2>
        <small class="text-muted">{{ playbook.description }}</small>
    </div>
    <div>
        <button class="btn btn-success me-2" id="saveBtn" onclick="savePlaybook()">
            <i class="fas fa-save me-1"></i>Save Changes
        </button>
        <button class="btn btn-info" onclick="formatJSON()">
            <i class="fas fa-magic me-1"></i>Format
        </button>
    </div>
</div>

<!-- Playbook Info -->
<div class="row mb-3">
    <div class="col-md-3">
        <div class="card border-primary">
            <div class="card-body text-center">
                <i class="fas fa-tag fa-2x text-primary mb-2"></i>
                <h5>{{ playbook_type }}</h5>
                <small class="text-muted">Type</small>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card border-success">
            <div class="card-body text-center">
                <i class="fas fa-list fa-2x text-success mb-2"></i>
                <h5>{{ playbook.rule_count }}</h5>
                <small class="text-muted">Rules</small>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card border-info">
            <div class="card-body text-center">
                <i class="fas fa-file-alt fa-2x text-info mb-2"></i>
                <h5>{{ playbook.log_type }}</h5>
                <small class="text-muted">Log Type</small>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card border-warning">
            <div class="card-body text-center">
                <i class="fas fa-shield-alt fa-2x text-warning mb-2"></i>
                <h5>{{ playbook.version }}</h5>
                <small class="text-muted">Version</small>
            </div>
        </div>
    </div>
</div>

<!-- JSON Editor -->
<div class="card shadow-sm">
    <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
        <div>
            <i class="fas fa-code me-2"></i>playbooks_{{ playbook_type }}.json
        </div>
        <small id="statusMsg" class="text-light"></small>
    </div>
    <div class="card-body p-0">
        <textarea id="jsonEditor" style="width: 100%; height: 65vh; padding: 1.5rem; background: #1e1e1e; color: #d4d4d4; border: none; font-family: 'Consolas', 'Monaco', 'Courier New', monospace; font-size: 0.9rem; line-height: 1.5; resize: vertical;">{{ playbook_json }}</textarea>
    </div>
</div>

<!-- Validation Messages -->
<div id="validationAlert" class="alert alert-dismissible fade show mt-3 d-none" role="alert">
    <i class="fas fa-exclamation-triangle me-2"></i>
    <span id="validationMessage"></span>
    <button type="button" class="btn-close" onclick="hideValidation()"></button>
</div>

<script>
const playbookType = '{{ playbook_type }}';
let unsavedChanges = false;

// Track changes
document.getElementById('jsonEditor').addEventListener('input', function() {
    unsavedChanges = true;
    document.getElementById('saveBtn').classList.add('btn-warning');
    document.getElementById('saveBtn').classList.remove('btn-success');
});

// Warn before leaving with unsaved changes
window.addEventListener('beforeunload', function(e) {
    if (unsavedChanges) {
        e.preventDefault();
        e.returnValue = '';
    }
});

function formatJSON() {
    const editor = document.getElementById('jsonEditor');
    try {
        const parsed = JSON.parse(editor.value);
        editor.value = JSON.stringify(parsed, null, 2);
        showStatus('JSON formatted successfully', 'success');
    } catch (e) {
        showStatus('Invalid JSON: ' + e.message, 'danger');
    }
}

function savePlaybook() {
    const editor = document.getElementById('jsonEditor');
    const content = editor.value;
    
    // Validate JSON
    try {
        const parsed = JSON.parse(content);
        
        // Validate required fields
        if (!parsed.name || !parsed.rules || !Array.isArray(parsed.rules)) {
            showStatus('Playbook must have "name" and "rules" array', 'danger');
            return;
        }
    } catch (e) {
        showStatus('Invalid JSON format: ' + e.message, 'danger');
        showValidation('Invalid JSON format: ' + e.message);
        return;
    }
    
    // Show loading
    const saveBtn = document.getElementById('saveBtn');
    const originalHTML = saveBtn.innerHTML;
    saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Saving...';
    saveBtn.disabled = true;
    
    // Send to server
    fetch('/api/playbook/save', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            playbook_type: playbookType,
            content: content
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showStatus('Successfully saved! Total rules loaded: ' + data.total_rules, 'success');
            unsavedChanges = false;
            saveBtn.classList.remove('btn-warning');
            saveBtn.classList.add('btn-success');
        } else {
            showStatus('Error: ' + data.error, 'danger');
            showValidation(data.error);
        }
    })
    .catch(error => {
        showStatus('Error: ' + error.message, 'danger');
        showValidation('Network error: ' + error.message);
    })
    .finally(() => {
        saveBtn.innerHTML = originalHTML;
        saveBtn.disabled = false;
    });
}

function showStatus(message, type) {
    const statusMsg = document.getElementById('statusMsg');
    statusMsg.textContent = message;
    statusMsg.className = 'text-' + (type === 'success' ? 'success' : type === 'danger' ? 'danger' : 'light');
    
    if (message && type !== 'danger') {
        setTimeout(() => {
            statusMsg.textContent = '';
        }, 5000);
    }
}

function showValidation(message) {
    const alert = document.getElementById('validationAlert');
    const msgSpan = document.getElementById('validationMessage');
    msgSpan.textContent = message;
    alert.classList.remove('d-none', 'alert-success', 'alert-danger');
    alert.classList.add('alert-danger');
}

function hideValidation() {
    document.getElementById('validationAlert').classList.add('d-none');
}
</script>

<style>
#jsonEditor {
    outline: none;
}
#jsonEditor:focus {
    box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25);
}
</style>

{% endblock %}
'''

ANALYTICS_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Analytics{% endblock %}
{% block content %}
<style>
.stat-card {
    background: linear-gradient(135deg, var(--bs-primary) 0%, var(--bs-info) 100%);
    color: white;
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 15px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
}
.stat-card h6 { font-weight: 600; font-size: 12px; opacity: 0.9; text-transform: uppercase; }
.stat-card .value { font-size: 28px; font-weight: bold; margin: 10px 0; }
.stat-card.critical { background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); }
.stat-card.warning { background: linear-gradient(135deg, #ffc107 0%, #fd7e14 100%); }
.stat-card.success { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); }
.stat-card.info { background: linear-gradient(135deg, #17a2b8 0%, #0dcaf0 100%); }
</style>

<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="fas fa-chart-line me-2"></i>Advanced Analytics Dashboard</h2>
    <div>
        <button class="btn btn-primary btn-sm" onclick="refreshAnalytics()">
            <i class="fas fa-sync me-1"></i>Refresh
        </button>
        <button class="btn btn-success btn-sm" onclick="exportAnalytics()">
            <i class="fas fa-download me-1"></i>Export
        </button>
    </div>
</div>

<!-- OVERVIEW STATS -->
<div class="row mb-4">
    <div class="col-md-3">
        <div class="stat-card">
            <h6><i class="fas fa-list"></i> Total Events (7 days)</h6>
            <div class="value">{{ overall_stats.total_events or 0 }}</div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="stat-card critical">
            <h6><i class="fas fa-exclamation-circle"></i> Critical Events</h6>
            <div class="value">{{ overall_stats.critical_events or 0 }}</div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="stat-card warning">
            <h6><i class="fas fa-alert"></i> High Events</h6>
            <div class="value">{{ overall_stats.high_events or 0 }}</div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="stat-card info">
            <h6><i class="fas fa-globe"></i> Unique Sources</h6>
            <div class="value">{{ overall_stats.unique_sources or 0 }}</div>
        </div>
    </div>
</div>

<!-- 1. EVENT TRENDS (24 HOURS) -->
<div class="row mb-4">
    <div class="col-lg-12">
        <div class="table-container">
            <h5><i class="fas fa-history me-2"></i>Event Trends (24 Hours)</h5>
            <div style="height: 350px; position: relative;">
                <canvas id="trendsChart"></canvas>
            </div>
        </div>
    </div>
</div>

<!-- 2. SEVERITY PIE + 3. HOURLY DISTRIBUTION -->
<div class="row mb-4">
    <div class="col-lg-4">
        <div class="table-container">
            <h5><i class="fas fa-pie-chart me-2"></i>Severity Distribution (7 Days)</h5>
            <div style="height: 350px;">
                <canvas id="severityChart"></canvas>
            </div>
        </div>
    </div>
    
    <div class="col-lg-8">
        <div class="table-container">
            <h5><i class="fas fa-clock me-2"></i>Events by Hour of Day</h5>
            <div style="height: 350px;">
                <canvas id="hourlyChart"></canvas>
            </div>
        </div>
    </div>
</div>

<!-- 4. TOP THREATS + 5. MITRE ATTACK MAPPING -->
<div class="row mb-4">
    <div class="col-lg-6">
        <div class="table-container">
            <h5><i class="fas fa-bomb me-2"></i>Top Threats (By Frequency)</h5>
            <div class="table-responsive" style="max-height: 400px; overflow-y: auto;">
                <table class="table table-hover table-sm">
                    <thead>
                        <tr>
                            <th>Threat</th>
                            <th>Freq</th>
                            <th>Critical</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for threat in top_threats %}
                        <tr>
                            <td><small>{{ threat.threat[:40] if threat.threat else 'Unknown' }}</small></td>
                            <td><span class="badge bg-primary">{{ threat.frequency }}</span></td>
                            <td>
                                {% if threat.critical_count and threat.critical_count > 0 %}
                                <span class="badge bg-danger">{{ threat.critical_count }}</span>
                                {% else %}<span class="text-muted">0</span>{% endif %}
                            </td>
                        </tr>
                        {% else %}
                        <tr><td colspan="3" class="text-center text-muted">No data</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <div class="col-lg-6">
        <div class="table-container">
            <h5><i class="fas fa-crosshairs me-2"></i>MITRE ATT&CK TTP Mapping</h5>
            <div class="table-responsive" style="max-height: 400px; overflow-y: auto;">
                <table class="table table-hover table-sm">
                    <thead>
                        <tr>
                            <th>TTP</th>
                            <th>Count</th>
                            <th>Critical</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for ttp in ttp_mapping %}
                        <tr>
                            <td><code style="font-size: 10px;">{{ ttp.ttp_match[:25] if ttp.ttp_match else 'N/A' }}</code></td>
                            <td><span class="badge bg-info">{{ ttp.count }}</span></td>
                            <td>
                                {% if ttp.critical and ttp.critical > 0 %}
                                <span class="badge bg-danger">{{ ttp.critical }}</span>
                                {% else %}<span class="text-muted">0</span>{% endif %}
                            </td>
                        </tr>
                        {% else %}
                        <tr><td colspan="3" class="text-center text-muted">No data</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<!-- 6. TOP SOURCE IPS (THREAT SCORES) -->
<div class="row mb-4">
    <div class="col-lg-12">
        <div class="table-container">
            <h5><i class="fas fa-globe me-2"></i>Top Threat Sources (With Threat Scores)</h5>
            <div class="table-responsive" style="max-height: 400px; overflow-y: auto;">
                <table class="table table-hover table-sm">
                    <thead>
                        <tr>
                            <th>Source IP</th>
                            <th>Total Events</th>
                            <th>Threat Score</th>
                            <th>Critical</th>
                            <th>High</th>
                            <th>Last Seen</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for source in source_dist %}
                        <tr>
                            <td><code>{{ source.source_ip }}</code></td>
                            <td><span class="badge bg-primary">{{ source.total_events }}</span></td>
                            <td>
                                {% set score = source.threat_score or 0 %}
                                {% if score > 50 %}
                                <span class="badge bg-danger">{{ score }}</span>
                                {% elif score > 20 %}
                                <span class="badge bg-warning">{{ score }}</span>
                                {% else %}
                                <span class="badge bg-success">{{ score }}</span>
                                {% endif %}
                            </td>
                            <td><span class="badge bg-danger">{{ source.critical_count or 0 }}</span></td>
                            <td><span class="badge bg-warning">{{ source.high_count or 0 }}</span></td>
                            <td><small>{{ source.last_seen[:10] if source.last_seen else 'N/A' }}</small></td>
                        </tr>
                        {% else %}
                        <tr><td colspan="6" class="text-center text-muted">No source data</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<!-- 7. USER ACTIVITY ANALYSIS -->
<div class="row mb-4">
    <div class="col-lg-12">
        <div class="table-container">
            <h5><i class="fas fa-users me-2"></i>User Activity Analysis (7 Days)</h5>
            <div class="table-responsive" style="max-height: 350px; overflow-y: auto;">
                <table class="table table-hover table-sm">
                    <thead>
                        <tr>
                            <th>User</th>
                            <th>Total Events</th>
                            <th>Threats</th>
                            <th>Risk Level</th>
                            <th>Source IPs</th>
                            <th>Event Types</th>
                            <th>Last Activity</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for user in user_activity %}
                        <tr>
                            <td><strong>{{ user.user }}</strong></td>
                            <td><span class="badge bg-primary">{{ user.count }}</span></td>
                            <td><span class="badge bg-danger">{{ user.threat_count or 0 }}</span></td>
                            <td>
                                {% if user.threat_count and user.threat_count > 10 %}
                                <span class="badge bg-danger">CRITICAL</span>
                                {% elif user.threat_count and user.threat_count > 5 %}
                                <span class="badge bg-warning">HIGH</span>
                                {% elif user.threat_count and user.threat_count > 0 %}
                                <span class="badge bg-info">MEDIUM</span>
                                {% else %}
                                <span class="badge bg-success">LOW</span>
                                {% endif %}
                            </td>
                            <td><span class="text-muted">{{ user.source_ips or 0 }}</span></td>
                            <td><span class="text-muted">{{ user.event_types or 0 }}</span></td>
                            <td><small>{{ user.last_activity[:10] if user.last_activity else 'N/A' }}</small></td>
                        </tr>
                        {% else %}
                        <tr><td colspan="7" class="text-center text-muted">No user data</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<!-- 8. EVENT TYPE DISTRIBUTION -->
<div class="row mb-4">
    <div class="col-lg-12">
        <div class="table-container">
            <h5><i class="fas fa-sitemap me-2"></i>Event Type Distribution (7 Days)</h5>
            <div style="height: 350px;">
                <canvas id="eventTypeChart"></canvas>
            </div>
        </div>
    </div>
</div>

<!-- 9. SOURCE vs DESTINATION ANALYSIS -->
<div class="row mb-4">
    <div class="col-lg-12">
        <div class="table-container">
            <h5><i class="fas fa-exchange-alt me-2"></i>Source vs Destination Analysis</h5>
            <div class="table-responsive" style="max-height: 350px; overflow-y: auto;">
                <table class="table table-hover table-sm">
                    <thead>
                        <tr>
                            <th>Source IP</th>
                            <th>Destination</th>
                            <th>Event Count</th>
                            <th>Event Variety</th>
                            <th>Avg Severity</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for item in source_dest %}
                        <tr>
                            <td><code>{{ item.source_ip }}</code></td>
                            <td><small>{{ item.source_name[:30] if item.source_name else 'Unknown' }}</small></td>
                            <td><span class="badge bg-primary">{{ item.count }}</span></td>
                            <td><span class="text-muted">{{ item.event_variety or 0 }}</span></td>
                            <td>
                                {% set avg_sev = item.avg_severity or 0 %}
                                {% if avg_sev > 0.7 %}
                                <span class="badge bg-danger">Critical</span>
                                {% elif avg_sev > 0.4 %}
                                <span class="badge bg-warning">High</span>
                                {% else %}
                                <span class="badge bg-info">Low</span>
                                {% endif %}
                            </td>
                        </tr>
                        {% else %}
                        <tr><td colspan="5" class="text-center text-muted">No data</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<!-- 10. DAILY STATISTICS TREND -->
<div class="row mb-4">
    <div class="col-lg-12">
        <div class="table-container">
            <h5><i class="fas fa-calendar me-2"></i>Daily Statistics (Last 30 Days)</h5>
            <div class="table-responsive" style="max-height: 300px; overflow-y: auto;">
                <table class="table table-hover table-sm">
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>Events</th>
                            <th>Unique Sources</th>
                            <th>Unique Users</th>
                            <th>Critical</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for day in daily_stats %}
                        <tr>
                            <td><strong>{{ day.day }}</strong></td>
                            <td><span class="badge bg-primary">{{ day.event_count }}</span></td>
                            <td><span class="text-muted">{{ day.unique_sources }}</span></td>
                            <td><span class="text-muted">{{ day.unique_users }}</span></td>
                            <td>
                                {% if day.critical_count > 0 %}
                                <span class="badge bg-danger">{{ day.critical_count }}</span>
                                {% else %}<span class="text-muted">0</span>{% endif %}
                            </td>
                        </tr>
                        {% else %}
                        <tr><td colspan="5" class="text-center text-muted">No data</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<!-- 11. ALERT STATUS SUMMARY -->
<div class="row mb-4">
    <div class="col-lg-12">
        <div class="table-container">
            <h5><i class="fas fa-bell me-2"></i>Alert Status Summary (7 Days)</h5>
            <div class="row">
                {% for alert in alert_status %}
                <div class="col-md-3">
                    <div class="alert alert-info mb-0">
                        <strong>{{ alert.status|upper }}</strong>
                        <div style="font-size: 24px; font-weight: bold;">{{ alert.count }}</div>
                        <small>Critical: {{ alert.critical or 0 }}</small>
                    </div>
                </div>
                {% else %}
                <div class="col-md-12"><p class="text-muted">No alert data</p></div>
                {% endfor %}
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@3.7.0/dist/chart.min.js"></script>
<script>
const trends = {{ trends|safe }};
const severityData = {{ severity_dist|tojson }};
const hourlyData = {{ hourly_dist|tojson }};
const eventTypeData = {{ event_dist|tojson }};
const alertTimeline = {{ alert_timeline|safe }};

// 1. TRENDS CHART
const trendsCtx = document.getElementById('trendsChart').getContext('2d');
new Chart(trendsCtx, {
    type: 'line',
    data: {
        labels: trends.map(t => new Date(t.hour).toLocaleTimeString()),
        datasets: [
            {
                label: 'Total Events',
                data: trends.map(t => t.count),
                borderColor: 'rgba(54, 162, 235, 1)',
                backgroundColor: 'rgba(54, 162, 235, 0.1)',
                borderWidth: 3,
                tension: 0.3,
                fill: true,
                pointRadius: 4,
                pointBackgroundColor: 'rgba(54, 162, 235, 1)'
            },
            {
                label: 'Critical',
                data: trends.map(t => t.critical || 0),
                borderColor: 'rgba(255, 99, 132, 1)',
                backgroundColor: 'rgba(255, 99, 132, 0.1)',
                borderWidth: 2,
                borderDash: [5,5],
                pointRadius: 3
            },
            {
                label: 'High',
                data: trends.map(t => t.high || 0),
                borderColor: 'rgba(255, 193, 7, 1)',
                backgroundColor: 'rgba(255, 193, 7, 0.05)',
                borderWidth: 2,
                pointRadius: 3
            }
        ]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'top' } },
        scales: { y: { beginAtZero: true, stacked: false } }
    }
});

// 2. SEVERITY PIE CHART
const severityCtx = document.getElementById('severityChart').getContext('2d');
new Chart(severityCtx, {
    type: 'doughnut',
    data: {
        labels: severityData.map(s => s.severity),
        datasets: [{
            data: severityData.map(s => s.count),
            backgroundColor: [
                'rgba(255, 99, 132, 0.7)',   // CRITICAL - red
                'rgba(255, 193, 7, 0.7)',     // HIGH - yellow
                'rgba(255, 159, 64, 0.7)',    // MEDIUM - orange
                'rgba(54, 162, 235, 0.7)'     // LOW - blue
            ],
            borderColor: [
                'rgba(255, 99, 132, 1)',
                'rgba(255, 193, 7, 1)',
                'rgba(255, 159, 64, 1)',
                'rgba(54, 162, 235, 1)'
            ],
            borderWidth: 2
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom' } }
    }
});

// 3. HOURLY DISTRIBUTION
const hourlyCtx = document.getElementById('hourlyChart').getContext('2d');
new Chart(hourlyCtx, {
    type: 'bar',
    data: {
        labels: hourlyData.map(h => h.hour_of_day + ':00'),
        datasets: [{
            label: 'Events',
            data: hourlyData.map(h => h.count),
            backgroundColor: 'rgba(75, 192, 192, 0.6)',
            borderColor: 'rgba(75, 192, 192, 1)',
            borderWidth: 1
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: { y: { beginAtZero: true } }
    }
});

// 4. EVENT TYPE DISTRIBUTION
const eventTypeCtx = document.getElementById('eventTypeChart').getContext('2d');
new Chart(eventTypeCtx, {
    type: 'bar',
    data: {
        labels: eventTypeData.map(e => e.event_type),
        datasets: [{
            label: 'Total Events',
            data: eventTypeData.map(e => e.count),
            backgroundColor: 'rgba(153, 102, 255, 0.6)',
            borderColor: 'rgba(153, 102, 255, 1)',
            borderWidth: 1
        }, {
            label: 'Critical',
            data: eventTypeData.map(e => e.critical_count || 0),
            backgroundColor: 'rgba(255, 99, 132, 0.6)',
            borderColor: 'rgba(255, 99, 132, 1)',
            borderWidth: 1
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: 'y',
        scales: { x: { beginAtZero: true } }
    }
});

function refreshAnalytics() {
    location.reload();
}

function exportAnalytics() {
    window.location.href = '/api/export/full-report';
}
</script>
{% endblock %}
'''

SETTINGS_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Settings{% endblock %}
{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="fas fa-cog me-2"></i>Settings</h2>
    <div>
        <button class="btn btn-success" onclick="saveSettings()">
            <i class="fas fa-save me-2"></i>Save Settings
        </button>
    </div>
</div>

<!-- Application Settings -->
<div class="table-container mb-4">
    <h5><i class="fas fa-sliders-h me-2"></i>Application Settings</h5>
    <form id="settingsForm">
        <div class="row">
            <div class="col-md-6 mb-3">
                <label class="form-label">Application Name</label>
                <input type="text" class="form-control" name="app_name" value="{{ settings.app_name }}">
            </div>
            <div class="col-md-6 mb-3">
                <label class="form-label">Log Retention (days)</label>
                <input type="number" class="form-control" name="retention_days" value="{{ settings.retention_days }}" min="1" max="365">
            </div>
            <div class="col-md-6 mb-3">
                <label class="form-label">Max Upload Size (MB)</label>
                <input type="number" class="form-control" name="max_upload_size" value="{{ settings.max_upload_size }}" min="1" max="1024">
            </div>
            <div class="col-md-6 mb-3">
                <label class="form-label">Auto Monitoring</label>
                <select class="form-select" name="auto_monitor">
                    <option value="1" {% if settings.auto_monitor == '1' %}selected{% endif %}>Enabled</option>
                    <option value="0" {% if settings.auto_monitor == '0' %}selected{% endif %}>Disabled</option>
                </select>
            </div>
            <div class="col-md-6 mb-3">
                <label class="form-label">Active Playbook Scope</label>
                <select class="form-select" name="active_playbook_type" id="activePlaybookType">
                    {% for ptype in available_playbook_types %}
                        <option value="{{ ptype }}" {% if active_playbook_type == ptype %}selected{% endif %}>{{ ptype|capitalize }}</option>
                    {% endfor %}
                </select>
                <div class="form-text">Real-time monitoring and packaging will only use this playbook set.</div>
            </div>
            <div class="col-md-6 mb-3 d-flex align-items-end">
                <button class="btn btn-primary me-2" type="button" onclick="applyPlaybookSelection()">
                    <i class="fas fa-bolt me-2"></i>Apply Selection
                </button>
                <button class="btn btn-outline-secondary me-2" type="button" data-bs-toggle="modal" data-bs-target="#playbookSelectorModal">
                    <i class="fas fa-box-open me-2"></i>Custom Package
                </button>
                <button class="btn btn-outline-secondary me-2" type="button" onclick="downloadPlaybookPackage()">
                    <i class="fas fa-box-open me-2"></i>Download Plug-and-Play Package
                </button>
                <button class="btn btn-outline-dark" type="button" onclick="downloadScopedLogs()">
                    <i class="fas fa-file-csv me-2"></i>Download Logs (CSV)
                </button>
            </div>
        </div>
    </form>
</div>

<!-- Threat Detection Settings -->
<div class="table-container mb-4">
    <h5><i class="fas fa-shield-alt me-2"></i>Threat Detection Settings</h5>
    <div class="row">
        <div class="col-md-6 mb-3">
            <div class="form-check form-switch">
                <input class="form-check-input" type="checkbox" id="threatDetection" checked>
                <label class="form-check-label" for="threatDetection">Enable Threat Detection</label>
            </div>
        </div>
        <div class="col-md-6 mb-3">
            <div class="form-check form-switch">
                <input class="form-check-input" type="checkbox" id="anomalyDetection" checked>
                <label class="form-check-label" for="anomalyDetection">Enable Anomaly Detection</label>
            </div>
        </div>
        <div class="col-md-6 mb-3">
            <div class="form-check form-switch">
                <input class="form-check-input" type="checkbox" id="realTimeMonitoring" checked>
                <label class="form-check-label" for="realTimeMonitoring">Enable Real-time Monitoring</label>
            </div>
        </div>
        <div class="col-md-6 mb-3">
            <div class="form-check form-switch">
                <input class="form-check-input" type="checkbox" id="autoAlerting">
                <label class="form-check-label" for="autoAlerting">Enable Auto Alerting</label>
            </div>
        </div>
    </div>
</div>

<!-- Database Management -->
<div class="table-container mb-4">
    <h5><i class="fas fa-database me-2"></i>Database Management & Statistics</h5>
    <div id="dbStats">
        <div class="spinner-border" role="status"><span class="visually-hidden">Loading...</span></div>
    </div>
    
    <div class="row mt-4">
        <div class="col-md-4 mb-3">
            <button class="btn btn-outline-primary w-100" onclick="backupDatabase()">
                <i class="fas fa-download me-2"></i>Backup Database
            </button>
        </div>
        <div class="col-md-4 mb-3">
            <button class="btn btn-outline-warning w-100" onclick="optimizeDatabase()">
                <i class="fas fa-tools me-2"></i>Optimize Database
            </button>
        </div>
        <div class="col-md-4 mb-3">
            <button class="btn btn-outline-danger w-100" onclick="clearOldLogs()">
                <i class="fas fa-trash me-2"></i>Clear Old Logs
            </button>
        </div>
    </div>
    
    <div class="alert alert-info mt-3">
        <i class="fas fa-info-circle me-2"></i>
        Use the buttons above to manage your database. Backups are stored in the backups/ directory.
    </div>
</div>

<!-- User Management (Admin Only) -->
{% if user.role == 'admin' %}
<div class="table-container">
    <h5><i class="fas fa-users me-2"></i>User Management</h5>
    <table class="table table-hover" id="usersTable">
        <thead>
            <tr>
                <th>Username</th>
                <th>Email</th>
                <th>Role</th>
                <th>Last Login</th>
                <th>Status</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td colspan="6" class="text-center text-muted">
                    <div class="spinner-border spinner-border-sm" role="status"><span class="visually-hidden">Loading...</span></div>
                    Loading user data...
                </td>
            </tr>
        </tbody>
    </table>
    
    <button class="btn btn-outline-primary" onclick="addNewUser()">
        <i class="fas fa-user-plus me-2"></i>Add New User
    </button>
</div>
{% endif %}

<!-- Playbook Selector Modal -->
<div id="playbookSelectorModal" class="modal fade" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Select Playbooks for Custom Package</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <p><strong>Choose which playbooks to include in your portable package:</strong></p>
                <p class="text-muted">This allows you to deploy only the specific playbooks you need to your network.</p>
                <div id="playbookCheckboxes" class="row g-3">
                    <!-- Checkboxes populated by JavaScript -->
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-primary" onclick="generateSelectedPackage()">
                    <i class="fas fa-download me-2"></i>Generate Custom Package
                </button>
            </div>
        </div>
    </div>
</div>

<script>
// Load available playbooks for the selector
async function loadPlaybookSelector() {
    try {
        const response = await fetch('/api/playbooks/active');
        const data = await response.json();
        
        const container = document.getElementById('playbookCheckboxes');
        if (!container) return;
        
        container.innerHTML = '';
        
        // Add "All" option
        container.innerHTML += `
            <div class="col-md-6">
                <div class="form-check">
                    <input class="form-check-input playbook-checkbox" type="checkbox" 
                           id="playbook_all" value="all" onchange="toggleAllPlaybooks(this)">
                    <label class="form-check-label" for="playbook_all">
                        <strong>All Playbooks</strong> (Select/Deselect all)
                    </label>
                </div>
            </div>
        `;
        
        // Add individual playbook options
        data.available_types.forEach(ptype => {
            if (ptype === 'all') return;
            
            const typeLabel = ptype.charAt(0).toUpperCase() + ptype.slice(1);
            const icon = getPlaybookIcon(ptype);
            
            container.innerHTML += `
                <div class="col-md-6">
                    <div class="form-check">
                        <input class="form-check-input playbook-checkbox" type="checkbox" 
                               id="playbook_${ptype}" value="${ptype}">
                        <label class="form-check-label" for="playbook_${ptype}">
                            ${icon} ${typeLabel}
                        </label>
                    </div>
                </div>
            `;
        });
    } catch (error) {
        console.error('Error loading playbooks:', error);
    }
}

function getPlaybookIcon(ptype) {
    const icons = {
        'windows': '🪟',
        'linux': '🐧',
        'mac': '🍎',
        'apache': '🔶',
        'nginx': '⚙️',
        'iis': '🪟',
        'dns': '🔍',
        'proxy': '🛡️',
        'fortinet': '🔒',
        'syslog': '📋',
        'osfc': '🔧'
    };
    return icons[ptype] || '📦';
}

function toggleAllPlaybooks(checkbox) {
    const checkboxes = document.querySelectorAll('.playbook-checkbox');
    checkboxes.forEach(cb => {
        if (cb.id !== 'playbook_all') {
            cb.checked = checkbox.checked;
        }
    });
}

async function generateSelectedPackage() {
    const checkboxes = document.querySelectorAll('.playbook-checkbox:checked');
    const selected = Array.from(checkboxes)
        .map(cb => cb.value)
        .filter(v => v !== 'all');
    
    if (selected.length === 0) {
        alert('Please select at least one playbook');
        return;
    }
    
    try {
        const response = await fetch('/api/playbooks/package', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ selected_types: selected })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to generate package');
        }
        
        // Download the file
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `plug_and_play_${selected.join('_')}.zip`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
        
        // Close modal
        const modal = bootstrap.Modal.getInstance(document.getElementById('playbookSelectorModal'));
        if (modal) modal.hide();
        
        alert(`✅ Package created with ${selected.join(', ').toUpperCase()} playbooks!`);
    } catch (error) {
        alert('❌ Error: ' + error.message);
    }
}

// Initialize selector when page loads
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', loadPlaybookSelector);
} else {
    loadPlaybookSelector();
}
</script>
    
    fetch('/api/admin/settings', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('✅ Settings saved successfully!');
        } else {
            alert('❌ Error: ' + data.error);
        }
    })
    .catch(error => {
        alert('❌ Error saving settings: ' + error.message);
    });
}

function applyPlaybookSelection() {
    const type = document.getElementById('activePlaybookType').value;
    fetch('/api/playbooks/active', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ playbook_type: type })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert(`✅ Active playbook set to ${data.active_playbook_type} with ${data.rule_count} rules`);
        } else {
            alert('❌ Error: ' + (data.error || 'Failed to apply selection'));
        }
    })
    .catch(error => {
        alert('❌ Error applying playbook: ' + error.message);
    });
}

function downloadPlaybookPackage() {
    const type = document.getElementById('activePlaybookType').value;
    fetch(`/api/playbooks/package?type=${encodeURIComponent(type)}`)
        .then(response => {
            if (!response.ok) throw new Error('Failed to generate package');
            return response.blob();
        })
        .then(blob => {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `plug_and_play_${type}.zip`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);
        })
        .catch(error => alert('❌ Error downloading package: ' + error.message));
}

function downloadScopedLogs() {
    const type = document.getElementById('activePlaybookType').value;
    fetch(`/api/playbooks/logs?type=${encodeURIComponent(type)}`)
        .then(response => {
            if (!response.ok) throw new Error('Failed to export logs');
            return response.blob();
        })
        .then(blob => {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `logs_${type}.csv`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);
        })
        .catch(error => alert('❌ Error downloading logs: ' + error.message));
}

function backupDatabase() {
    if (confirm('Create a backup of the database? This may take a moment.')) {
        fetch('/api/admin/database', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ action: 'backup' })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('✅ Database backup created: ' + data.backup_file);
            } else {
                alert('❌ Error: ' + data.error);
            }
        })
        .catch(error => {
            alert('❌ Error creating backup: ' + error.message);
        });
    }
}

function optimizeDatabase() {
    if (confirm('Optimize database for better performance? This may take a moment.')) {
        fetch('/api/admin/database', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ action: 'optimize' })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('✅ Database optimized successfully!');
            } else {
                alert('❌ Error: ' + data.error);
            }
        })
        .catch(error => {
            alert('❌ Error optimizing database: ' + error.message);
        });
    }
}

function clearOldLogs() {
    const days = prompt('Delete logs older than how many days?', '30');
    if (days !== null && !isNaN(days) && days > 0) {
        if (confirm('This will permanently delete ' + days + ' days worth of logs. Are you sure?')) {
            fetch('/api/admin/database', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ action: 'clear_old_logs', days: parseInt(days) })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('✅ Successfully deleted ' + data.deleted + ' old log entries!');
                } else {
                    alert('❌ Error: ' + data.error);
                }
            })
            .catch(error => {
                alert('❌ Error clearing logs: ' + error.message);
            });
        }
    }
}

function loadDatabaseStats() {
    fetch('/api/admin/database', {
        method: 'GET',
        headers: {'Content-Type': 'application/json'}
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const stats = data.stats;
            document.getElementById('dbStats').innerHTML = `
                <div class="row">
                    <div class="col-md-3">
                        <div class="stat-card">
                            <h6>Log Entries</h6>
                            <h3>${stats.log_entries.toLocaleString()}</h3>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card">
                            <h6>Alerts</h6>
                            <h3>${stats.alerts.toLocaleString()}</h3>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card">
                            <h6>Users</h6>
                            <h3>${stats.users.toLocaleString()}</h3>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card">
                            <h6>Database Size</h6>
                            <h3>${stats.database_size_mb.toFixed(2)} MB</h3>
                        </div>
                    </div>
                </div>
            `;
        }
    });
}

function loadUserManagement() {
    fetch('/api/admin/users', {
        method: 'GET',
        headers: {'Content-Type': 'application/json'}
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const tbody = document.querySelector('#usersTable tbody');
            tbody.innerHTML = '';
            
            data.users.forEach(user => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${user.username}</td>
                    <td>${user.email}</td>
                    <td>
                        <select class="form-select form-select-sm" onchange="updateUserRole(${user.id}, this.value)">
                            <option value="admin" ${user.role === 'admin' ? 'selected' : ''}>Admin</option>
                            <option value="analyst" ${user.role === 'analyst' ? 'selected' : ''}>Analyst</option>
                            <option value="viewer" ${user.role === 'viewer' ? 'selected' : ''}>Viewer</option>
                        </select>
                    </td>
                    <td>${user.last_login || 'Never'}</td>
                    <td><span class="badge bg-success">Active</span></td>
                    <td>
                        <button class="btn btn-sm btn-outline-danger" onclick="deleteUser(${user.id}, '${user.username}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                `;
                tbody.appendChild(row);
            });
        }
    });
}

function updateUserRole(userId, newRole) {
    fetch('/api/admin/users', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ action: 'update_role', user_id: userId, role: newRole })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('✅ User role updated!');
        } else {
            alert('❌ Error: ' + data.error);
        }
    });
}

function deleteUser(userId, username) {
    if (confirm('Delete user ' + username + '? This action cannot be undone.')) {
        fetch('/api/admin/users', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ action: 'delete', user_id: userId })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('✅ User deleted!');
                loadUserManagement();
            } else {
                alert('❌ Error: ' + data.error);
            }
        });
    }
}

function addNewUser() {
    const username = prompt('Enter username:');
    if (!username) return;
    const email = prompt('Enter email:');
    if (!email) return;
    const password = prompt('Enter password:');
    if (!password) return;
    
    fetch('/api/admin/users', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            action: 'create',
            username: username,
            email: email,
            password: password,
            role: 'analyst'
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('✅ User created successfully!');
            loadUserManagement();
        } else {
            alert('❌ Error: ' + data.error);
        }
    });
}

// Load data on page load
document.addEventListener('DOMContentLoaded', function() {
    loadDatabaseStats();
    loadUserManagement();
    setInterval(loadDatabaseStats, 30000); // Refresh every 30 seconds
});
</script>
{% endblock %}
'''

IOC_DETECTION_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}IOC Detection{% endblock %}
{% block content %}
<div class="dashboard-header mb-4">
    <h2><i class="fas fa-biohazard me-2"></i>IOC Detection - Indicators of Compromise</h2>
    <p class="text-muted">Real-time monitoring and detection of malicious indicators across your infrastructure</p>
</div>

<!-- IOC Statistics Cards -->
<div class="row mb-4">
    <div class="col-md-3 mb-3">
        <div class="stat-card critical">
            <h6 class="text-muted mb-2">Malicious IPs</h6>
            <h3>{{ ioc_stats.unique_malicious_ips or 0 }}</h3>
            <small><i class="fas fa-network-wired me-1"></i>Unique Sources</small>
        </div>
    </div>
    <div class="col-md-3 mb-3">
        <div class="stat-card warning">
            <h6 class="text-muted mb-2">Suspicious URLs</h6>
            <h3>{{ ioc_stats.suspicious_url_count or 0 }}</h3>
            <small><i class="fas fa-link me-1"></i>Potential C2/Phishing</small>
        </div>
    </div>
    <div class="col-md-3 mb-3">
        <div class="stat-card high">
            <h6 class="text-muted mb-2">Failed Logins</h6>
            <h3>{{ ioc_stats.failed_login_attempts or 0 }}</h3>
            <small><i class="fas fa-user-lock me-1"></i>Brute Force Attempts</small>
        </div>
    </div>
    <div class="col-md-3 mb-3">
        <div class="stat-card danger">
            <h6 class="text-muted mb-2">Malware Detections</h6>
            <h3>{{ ioc_stats.malware_detections or 0 }}</h3>
            <small><i class="fas fa-virus me-1"></i>Malicious Signatures</small>
        </div>
    </div>
</div>

<!-- Malicious IP Addresses -->
<div class="table-container mb-4">
    <h5><i class="fas fa-network-wired me-2"></i>Malicious IP Addresses</h5>
    <div class="table-responsive">
        <table class="table table-hover">
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Occurrences</th>
                    <th>Severities</th>
                    <th>Event Types</th>
                    <th>First Seen</th>
                    <th>Last Seen</th>
                    <th>Critical</th>
                </tr>
            </thead>
            <tbody>
                {% for ip in malicious_ips[:20] %}
                <tr>
                    <td><span class="badge bg-danger">{{ ip.source_ip }}</span></td>
                    <td>{{ ip.occurrences }}</td>
                    <td><small>{{ ip.severities }}</small></td>
                    <td><small>{{ ip.event_types[:50] }}...</small></td>
                    <td><small>{{ ip.first_seen }}</small></td>
                    <td><small>{{ ip.last_seen }}</small></td>
                    <td><span class="badge bg-dark">{{ ip.critical_count }}</span></td>
                </tr>
                {% else %}
                <tr><td colspan="7" class="text-center text-muted">No malicious IPs detected</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<!-- Port Scanning Detection -->
<div class="table-container mb-4">
    <h5><i class="fas fa-radar me-2"></i>Port Scanning Activity</h5>
    <div class="table-responsive">
        <table class="table table-hover">
            <thead>
                <tr>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Unique Ports</th>
                    <th>Total Attempts</th>
                    <th>First Seen</th>
                    <th>Last Seen</th>
                </tr>
            </thead>
            <tbody>
                {% for scan in port_scans[:15] %}
                <tr>
                    <td><span class="badge bg-warning text-dark">{{ scan.source_ip }}</span></td>
                    <td>{{ scan.dest_ip or 'N/A' }}</td>
                    <td><span class="badge bg-primary">{{ scan.unique_ports }}</span></td>
                    <td>{{ scan.total_attempts }}</td>
                    <td><small>{{ scan.first_seen }}</small></td>
                    <td><small>{{ scan.last_seen }}</small></td>
                </tr>
                {% else %}
                <tr><td colspan="6" class="text-center text-muted">No port scanning detected</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<!-- Brute Force Indicators -->
<div class="table-container mb-4">
    <h5><i class="fas fa-user-shield me-2"></i>Brute Force Attack Indicators</h5>
    <div class="table-responsive">
        <table class="table table-hover">
            <thead>
                <tr>
                    <th>Source IP</th>
                    <th>Target User</th>
                    <th>Failed Attempts</th>
                    <th>First Attempt</th>
                    <th>Last Attempt</th>
                    <th>Threat Level</th>
                </tr>
            </thead>
            <tbody>
                {% for bf in brute_force[:15] %}
                <tr>
                    <td><span class="badge bg-danger">{{ bf.source_ip }}</span></td>
                    <td>{{ bf.user or 'Unknown' }}</td>
                    <td><strong>{{ bf.attempts }}</strong></td>
                    <td><small>{{ bf.first_attempt }}</small></td>
                    <td><small>{{ bf.last_attempt }}</small></td>
                    <td>
                        {% if bf.attempts > 20 %}
                        <span class="badge bg-danger">CRITICAL</span>
                        {% elif bf.attempts > 10 %}
                        <span class="badge bg-warning text-dark">HIGH</span>
                        {% else %}
                        <span class="badge bg-info">MEDIUM</span>
                        {% endif %}
                    </td>
                </tr>
                {% else %}
                <tr><td colspan="6" class="text-center text-muted">No brute force indicators detected</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<!-- Malware Signatures -->
<div class="table-container mb-4">
    <h5><i class="fas fa-virus me-2"></i>Malware & Ransomware Signatures</h5>
    <div class="table-responsive">
        <table class="table table-hover">
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Source</th>
                    <th>Source IP</th>
                    <th>Severity</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody>
                {% for malware in malware_signatures[:15] %}
                <tr>
                    <td><small>{{ malware.timestamp }}</small></td>
                    <td>{{ malware.source_name }}</td>
                    <td>{{ malware.source_ip or 'N/A' }}</td>
                    <td>
                        <span class="badge bg-{{ 'danger' if malware.severity == 'CRITICAL' else 'warning' }}">
                            {{ malware.severity }}
                        </span>
                    </td>
                    <td><small>{{ malware.message[:100] }}...</small></td>
                </tr>
                {% else %}
                <tr><td colspan="5" class="text-center text-muted">No malware signatures detected</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<!-- Suspicious URLs -->
<div class="table-container mb-4">
    <h5><i class="fas fa-link me-2"></i>Suspicious URLs & Domains</h5>
    <div class="table-responsive">
        <table class="table table-hover">
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Source</th>
                    <th>Severity</th>
                    <th>URL/Domain</th>
                </tr>
            </thead>
            <tbody>
                {% for url in suspicious_urls[:15] %}
                <tr>
                    <td><small>{{ url.timestamp }}</small></td>
                    <td>{{ url.source_name }}</td>
                    <td><span class="badge bg-warning text-dark">{{ url.severity }}</span></td>
                    <td><code>{{ url.message[:150] }}...</code></td>
                </tr>
                {% else %}
                <tr><td colspan="4" class="text-center text-muted">No suspicious URLs detected</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<!-- Data Exfiltration Indicators -->
<div class="table-container mb-4">
    <h5><i class="fas fa-upload me-2"></i>Data Exfiltration Indicators</h5>
    <div class="table-responsive">
        <table class="table table-hover">
            <thead>
                <tr>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Transfer Count</th>
                    <th>Last Transfer</th>
                </tr>
            </thead>
            <tbody>
                {% for exfil in exfiltration[:10] %}
                <tr>
                    <td><span class="badge bg-danger">{{ exfil.source_ip }}</span></td>
                    <td>{{ exfil.dest_ip or 'N/A' }}</td>
                    <td><strong>{{ exfil.transfer_count }}</strong></td>
                    <td><small>{{ exfil.last_transfer }}</small></td>
                </tr>
                {% else %}
                <tr><td colspan="4" class="text-center text-muted">No exfiltration indicators detected</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

{% endblock %}
'''

THREATS_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}Threat Detection{% endblock %}
{% block content %}
<style>
    .threat-card {
        background: linear-gradient(135deg, var(--bs-primary) 0%, var(--bs-info) 100%);
        color: white;
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 15px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        transition: transform 0.2s;
    }
    .threat-card:hover { transform: translateY(-2px); }
    .threat-card.critical { background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); }
    .threat-card.high { background: linear-gradient(135deg, #ffc107 0%, #fd7e14 100%); }
    .threat-card.medium { background: linear-gradient(135deg, #17a2b8 0%, #0dcaf0 100%); }
    .threat-card.low { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); }
    
    .ttp-badge {
        background: rgba(220, 53, 69, 0.2);
        border: 1px solid #dc3545;
        color: #dc3545;
        font-size: 0.75rem;
        font-weight: 600;
        padding: 2px 8px;
        border-radius: 4px;
        margin: 2px;
        display: inline-block;
    }
    
    .attack-timeline {
        position: relative;
        padding-left: 30px;
    }
    .attack-timeline:before {
        content: '';
        position: absolute;
        left: 15px;
        top: 0;
        bottom: 0;
        width: 2px;
        background: #e9ecef;
    }
    .timeline-item {
        position: relative;
        margin-bottom: 15px;
    }
    .timeline-item:before {
        content: '';
        position: absolute;
        left: -22px;
        top: 5px;
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #3498db;
    }
    .timeline-item.critical:before { background: #dc3545; }
    .timeline-item.high:before { background: #ffc107; }
</style>

<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="fas fa-exclamation-triangle me-2"></i>Threat Detection Dashboard</h2>
    <div class="btn-group">
        <button class="btn btn-primary" onclick="refreshThreats()">
            <i class="fas fa-sync me-2"></i>Refresh
        </button>
        <button class="btn btn-success" onclick="exportThreatReport()">
            <i class="fas fa-download me-2"></i>Export
        </button>
        <button class="btn btn-danger" onclick="runThreatHunt()">
            <i class="fas fa-search me-2"></i>Threat Hunt
        </button>
    </div>
</div>

<!-- Threat Summary Cards -->
<div class="row mb-4">
    <div class="col-md-3">
        <div class="threat-card critical">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h6 class="mb-1">Active Threats</h6>
                    <h3 id="activeThreats">0</h3>
                </div>
                <i class="fas fa-fire fa-2x"></i>
            </div>
            <small>Threats detected in last 24h</small>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="threat-card high">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h6 class="mb-1">Critical Events</h6>
                    <h3 id="criticalEvents">0</h3>
                </div>
                <i class="fas fa-exclamation-circle fa-2x"></i>
            </div>
            <small>CRITICAL severity events</small>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="threat-card medium">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h6 class="mb-1">Unique TTPs</h6>
                    <h3 id="uniqueTTPs">0</h3>
                </div>
                <i class="fas fa-crosshairs fa-2x"></i>
            </div>
            <small>MITRE ATT&CK techniques</small>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="threat-card">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h6 class="mb-1">Top Source IP</h6>
                    <h5 id="topSourceIP">-</h5>
                </div>
                <i class="fas fa-network-wired fa-2x"></i>
            </div>
            <small>Most active threat source</small>
        </div>
    </div>
</div>

<div class="row">
    <!-- Left Column: Detected Threats -->
    <div class="col-lg-8">
        <!-- Real-time Threat Feed -->
        <div class="table-container mb-4">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h5><i class="fas fa-rss me-2"></i>Real-time Threat Feed</h5>
                <div class="form-check form-switch">
                    <input class="form-check-input" type="checkbox" id="autoRefresh" checked>
                    <label class="form-check-label" for="autoRefresh">Auto-refresh (30s)</label>
                </div>
            </div>
            <div id="threatFeed" class="attack-timeline" style="max-height: 400px; overflow-y: auto;">
                <div class="text-center py-4">
                    <div class="spinner-border" role="status">
                        <span class="visually-hidden">Loading threats...</span>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Threat Analysis -->
        <div class="table-container mb-4">
            <h5><i class="fas fa-chart-pie me-2"></i>Threat Analysis</h5>
            <div class="row">
                <div class="col-md-6">
                    <canvas id="severityChart" height="200"></canvas>
                </div>
                <div class="col-md-6">
                    <canvas id="ttpChart" height="200"></canvas>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Right Column: Threat Intelligence & Actions -->
    <div class="col-lg-4">
        <!-- Threat Intelligence Panel -->
        <div class="table-container mb-4">
            <h5><i class="fas fa-brain me-2"></i>Threat Intelligence</h5>
            <div id="threatIntelligence">
                <div class="alert alert-info">
                    <i class="fas fa-info-circle me-2"></i>
                    Loading threat intelligence data...
                </div>
            </div>
        </div>
        
        <!-- Quick Actions -->
        <div class="table-container mb-4">
            <h5><i class="fas fa-bolt me-2"></i>Quick Actions</h5>
            <div class="d-grid gap-2">
                <button class="btn btn-outline-primary" onclick="runCustomSearch()">
                    <i class="fas fa-search me-2"></i>Custom Threat Search
                </button>
                <button class="btn btn-outline-success" onclick="generateThreatReport()">
                    <i class="fas fa-file-export me-2"></i>Generate Report
                </button>
                <button class="btn btn-outline-warning" onclick="isolateThreatSource()">
                    <i class="fas fa-shield-alt me-2"></i>Isolate Threat
                </button>
                <button class="btn btn-outline-danger" onclick="clearAllThreats()">
                    <i class="fas fa-trash me-2"></i>Clear All Threats
                </button>
            </div>
        </div>
        
        <!-- Threat Statistics -->
        <div class="table-container">
            <h5><i class="fas fa-chart-bar me-2"></i>Threat Statistics</h5>
            <div id="threatStats">
                <div class="spinner-border spinner-border-sm" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Detected TTPs Table -->
<div class="table-container mb-4">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h5><i class="fas fa-list-alt me-2"></i>Detected MITRE ATT&CK TTPs</h5>
        <div class="btn-group">
            <button class="btn btn-sm btn-outline-secondary" onclick="filterTTPs('all')">All</button>
            <button class="btn btn-sm btn-outline-danger" onclick="filterTTPs('critical')">Critical</button>
            <button class="btn btn-sm btn-outline-warning" onclick="filterTTPs('high')">High</button>
            <button class="btn btn-sm btn-outline-info" onclick="filterTTPs('medium')">Medium</button>
        </div>
    </div>
    <div class="table-responsive">
        <table class="table table-hover" id="ttpTable">
            <thead>
                <tr>
                    <th>TTP ID</th>
                    <th>Technique</th>
                    <th>Count</th>
                    <th>Severity</th>
                    <th>First Seen</th>
                    <th>Last Seen</th>
                    <th>Source IPs</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="ttpTableBody">
                <tr><td colspan="8" class="text-center">Loading TTP data...</td></tr>
            </tbody>
        </table>
    </div>
</div>

<!-- Threat Timeline -->
<div class="table-container">
    <h5><i class="fas fa-timeline me-2"></i>Threat Timeline (Last 7 Days)</h5>
    <div style="height: 300px;">
        <canvas id="threatTimelineChart"></canvas>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@3.7.0/dist/chart.min.js"></script>
<script>
let refreshInterval;
let threatData = {};
let charts = {};

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    loadThreatData();
    setupAutoRefresh();
    setupCharts();
});

// Load all threat data
function loadThreatData() {
    Promise.all([
        fetch('/api/threats/summary').then(r => r.json()),
        fetch('/api/threats/recent').then(r => r.json()),
        fetch('/api/threats/ttp-detections').then(r => r.json()),
        fetch('/api/threats/timeline').then(r => r.json()),
        fetch('/api/threats/intelligence').then(r => r.json())
    ]).then(([summary, recent, ttps, timeline, intelligence]) => {
        // Handle response format - some endpoints return objects, some return arrays
        threatData = { 
            summary: summary,
            recent: Array.isArray(recent) ? recent : (recent.threats || []),
            ttps: Array.isArray(ttps) ? ttps : (ttps.ttps || []),
            timeline: Array.isArray(timeline) ? timeline : (timeline.timeline || []),
            intelligence: Array.isArray(intelligence) ? intelligence : (intelligence.intelligence || [])
        };
        updateUI();
    }).catch(error => {
        console.error('Error loading threat data:', error);
        showToast('Failed to load threat data', 'danger');
    });
}

// Update UI with loaded data
function updateUI() {
    try {
        // Update summary cards
        if (threatData.summary) {
            document.getElementById('activeThreats').textContent = 
                threatData.summary.active_threats || 0;
            document.getElementById('criticalEvents').textContent = 
                threatData.summary.critical_events || 0;
            document.getElementById('uniqueTTPs').textContent = 
                threatData.summary.unique_ttps || 0;
            document.getElementById('topSourceIP').textContent = 
                threatData.summary.top_source_ip || '-';
        }
        
        // Update threat feed
        updateThreatFeed(threatData.recent || []);
        
        // Update TTP table
        updateTTPTable(threatData.ttps || []);
        
        // Update threat intelligence
        updateThreatIntelligence(threatData.intelligence || []);
        
        // Update threat stats
        updateThreatStats(threatData.summary || {});
        
        // Update charts
        updateCharts();
    } catch (error) {
        console.error('Error updating UI:', error);
        showToast('Error updating threat dashboard', 'danger');
    }
}

// Update threat feed
function updateThreatFeed(threats) {
    const feed = document.getElementById('threatFeed');
    if (!feed) return;
    
    if (!threats || !Array.isArray(threats) || threats.length === 0) {
        feed.innerHTML = '<div class="alert alert-info">No recent threats detected</div>';
        return;
    }
    
    let html = '';
    threats.slice(0, 20).forEach(threat => {
        const severityClass = (threat.severity || 'INFO').toLowerCase();
        const time = threat.timestamp ? new Date(threat.timestamp).toLocaleTimeString() : 'N/A';
        
        html += `
            <div class="timeline-item ${severityClass}">
                <div class="card mb-2">
                    <div class="card-body p-2">
                        <div class="d-flex justify-content-between">
                            <small class="text-${severityClass}">
                                <i class="fas fa-${severityClass === 'critical' ? 'fire' : severityClass === 'high' ? 'exclamation-triangle' : 'info-circle'}"></i>
                                <strong>${threat.severity || 'INFO'}</strong>
                            </small>
                            <small class="text-muted">${time}</small>
                        </div>
                        <small class="d-block">${threat.message || 'No message'}</small>
                        <div class="mt-1">
                            <small><strong>Source:</strong> ${threat.source_ip || 'Unknown'} | ${threat.source_name || 'Unknown'}</small>
                        </div>
                        ${threat.ttp_match ? `<div class="mt-1"><span class="ttp-badge">${threat.ttp_match}</span></div>` : ''}
                    </div>
                </div>
            </div>
        `;
    });
    
    feed.innerHTML = html;
}

// Update TTP table
function updateTTPTable(ttps) {
    const tbody = document.getElementById('ttpTableBody');
    if (!ttps || ttps.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center">No TTP detections</td></tr>';
        return;
    }
    
    let html = '';
    ttps.forEach(ttp => {
        const severity = ttp.severity || 'MEDIUM';
        const severityClass = severity.toLowerCase();
        const severityColors = {
            'critical': 'danger',
            'high': 'warning',
            'medium': 'info',
            'low': 'success'
        };
        
        html += `
            <tr>
                <td><span class="badge bg-dark">${ttp.id || 'N/A'}</span></td>
                <td>
                    <strong>${ttp.name || 'Unknown Technique'}</strong><br>
                    <small class="text-muted">${ttp.description || ''}</small>
                </td>
                <td><span class="badge bg-primary">${ttp.count || 0}</span></td>
                <td>
                    <span class="badge bg-${severityColors[severityClass] || 'info'}">
                        ${severity}
                    </span>
                </td>
                <td><small>${ttp.first_seen || 'N/A'}</small></td>
                <td><small>${ttp.last_seen || 'N/A'}</small></td>
                <td>
                    <small>${ttp.source_ips ? ttp.source_ips.split(',').slice(0, 3).join(', ') : 'N/A'}</small>
                    ${ttp.source_ips && ttp.source_ips.split(',').length > 3 ? 
                      `<br><small class="text-muted">+${ttp.source_ips.split(',').length - 3} more</small>` : ''}
                </td>
                <td>
                    <button class="btn btn-sm btn-outline-info" onclick="investigateTTP('${ttp.id || ''}')">
                        <i class="fas fa-search"></i>
                    </button>
                    <button class="btn btn-sm btn-outline-warning" onclick="createRuleFromTTP('${ttp.id || ''}')">
                        <i class="fas fa-shield-alt"></i>
                    </button>
                </td>
            </tr>
        `;
    });
    
    tbody.innerHTML = html;
}

// Filter TTPs by severity
function filterTTPs(severity) {
    const rows = document.querySelectorAll('#ttpTableBody tr');
    rows.forEach(row => {
        if (severity === 'all') {
            row.style.display = '';
        } else {
            const severityText = row.querySelector('td:nth-child(4)').textContent.toLowerCase();
            row.style.display = severityText.includes(severity) ? '' : 'none';
        }
    });
}

// Setup charts
function setupCharts() {
    // Severity Distribution Chart
    charts.severity = new Chart(
        document.getElementById('severityChart').getContext('2d'),
        {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [
                        '#dc3545',
                        '#ffc107',
                        '#17a2b8',
                        '#28a745',
                        '#6c757d'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        }
    );
    
    // TTP Chart
    charts.ttp = new Chart(
        document.getElementById('ttpChart').getContext('2d'),
        {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'TTP Detections',
                    data: [],
                    backgroundColor: '#3498db'
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: { beginAtZero: true }
                }
            }
        }
    );
    
    // Threat Timeline Chart
    charts.timeline = new Chart(
        document.getElementById('threatTimelineChart').getContext('2d'),
        {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Threats',
                    data: [],
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: { beginAtZero: true }
                }
            }
        }
    );
}

// Update charts with data
function updateCharts() {
    try {
        if (!threatData.summary) return;
        
        // Update severity chart
        if (charts.severity && threatData.summary.severity_distribution) {
            const dist = threatData.summary.severity_distribution;
            charts.severity.data.datasets[0].data = [
                dist.critical || 0,
                dist.high || 0,
                dist.medium || 0,
                dist.low || 0,
                dist.info || 0
            ];
            charts.severity.update();
        }
        
        // Update TTP chart (top 10)
        if (charts.ttp && threatData.ttps && Array.isArray(threatData.ttps)) {
            const topTTPs = threatData.ttps.slice(0, 10);
            charts.ttp.data.labels = topTTPs.map(t => t.name?.substring(0, 20) || 'Unknown');
            charts.ttp.data.datasets[0].data = topTTPs.map(t => t.count || 0);
            charts.ttp.update();
        }
        
        // Update timeline chart
        if (charts.timeline && threatData.timeline && Array.isArray(threatData.timeline)) {
            charts.timeline.data.labels = threatData.timeline.map(t => t.time || t.date);
            charts.timeline.data.datasets[0].data = threatData.timeline.map(t => t.count || 0);
            charts.timeline.update();
        }
    } catch (error) {
        console.error('Error updating charts:', error);
    }
}

// Update threat intelligence
function updateThreatIntelligence(intelligence) {
    const container = document.getElementById('threatIntelligence');
    if (!intelligence || !intelligence.length) {
        container.innerHTML = '<div class="alert alert-info">No threat intelligence available</div>';
        return;
    }
    
    let html = '<div class="list-group">';
    intelligence.slice(0, 5).forEach(item => {
        html += `
            <div class="list-group-item">
                <div class="d-flex w-100 justify-content-between">
                    <h6 class="mb-1">${item.title || 'Threat Alert'}</h6>
                    <small class="text-muted">${item.date || 'Recently'}</small>
                </div>
                <p class="mb-1">${item.description || 'No description'}</p>
                <small><strong>Source:</strong> ${item.source || 'Unknown'}</small>
            </div>
        `;
    });
    html += '</div>';
    container.innerHTML = html;
}

// Update threat statistics
function updateThreatStats(summary) {
    const container = document.getElementById('threatStats');
    if (!summary) return;
    
    const stats = `
        <div class="row text-center">
            <div class="col-6 mb-2">
                <div class="p-2 bg-light rounded">
                    <small class="text-muted d-block">Total Threats</small>
                    <strong>${summary.total_threats || 0}</strong>
                </div>
            </div>
            <div class="col-6 mb-2">
                <div class="p-2 bg-light rounded">
                    <small class="text-muted d-block">Attack Sources</small>
                    <strong>${summary.unique_sources || 0}</strong>
                </div>
            </div>
            <div class="col-6 mb-2">
                <div class="p-2 bg-light rounded">
                    <small class="text-muted d-block">Affected Users</small>
                    <strong>${summary.affected_users || 0}</strong>
                </div>
            </div>
            <div class="col-6 mb-2">
                <div class="p-2 bg-light rounded">
                    <small class="text-muted d-block">Avg Severity</small>
                    <strong>${summary.avg_severity || 'Low'}</strong>
                </div>
            </div>
        </div>
    `;
    container.innerHTML = stats;
}

// Setup auto-refresh
function setupAutoRefresh() {
    const autoRefresh = document.getElementById('autoRefresh');
    autoRefresh.addEventListener('change', function() {
        if (this.checked) {
            startAutoRefresh();
        } else {
            stopAutoRefresh();
        }
    });
    startAutoRefresh();
}

function startAutoRefresh() {
    if (refreshInterval) clearInterval(refreshInterval);
    refreshInterval = setInterval(loadThreatData, 30000);
}

function stopAutoRefresh() {
    if (refreshInterval) clearInterval(refreshInterval);
}

// Action functions
function refreshThreats() {
    loadThreatData();
    showToast('Threat data refreshed', 'success');
}

function exportThreatReport() {
    window.location.href = '/api/threats/export?format=pdf';
}

function runThreatHunt() {
    showToast('Starting threat hunt...', 'info');
    fetch('/api/threats/hunt', { method: 'POST' })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                showToast(`Threat hunt completed: ${data.found} threats found`, 'success');
                loadThreatData();
            } else {
                showToast('Threat hunt failed', 'danger');
            }
        })
        .catch(() => showToast('Error running threat hunt', 'danger'));
}

function runCustomSearch() {
    const query = prompt('Enter search query (IP, user, TTP, etc.):');
    if (query) {
        window.location.href = `/logs?search=${encodeURIComponent(query)}`;
    }
}

function generateThreatReport() {
    fetch('/api/threats/report', { method: 'POST' })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                showToast('Threat report generated successfully', 'success');
                window.open(`/api/threats/report/${data.report_id}`, '_blank');
            } else {
                showToast('Failed to generate report', 'danger');
            }
        });
}

function isolateThreatSource() {
    const source = prompt('Enter source IP to isolate:');
    if (source && confirm(`Isolate ${source}? This will block all traffic from this IP.`)) {
        fetch('/api/threats/isolate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ source_ip: source })
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                showToast(`Successfully isolated ${source}`, 'success');
            } else {
                showToast(`Failed to isolate ${source}: ${data.error}`, 'danger');
            }
        });
    }
}

function clearAllThreats() {
    if (confirm('Clear all threat data? This will reset threat counters but keep log data.')) {
        fetch('/api/threats/clear', { method: 'POST' })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    showToast('All threats cleared', 'success');
                    loadThreatData();
                } else {
                    showToast('Failed to clear threats', 'danger');
                }
            });
    }
}

function investigateTTP(ttpId) {
    window.location.href = `/logs?search=${encodeURIComponent(ttpId)}`;
}

function createRuleFromTTP(ttpId) {
    fetch(`/api/threats/ttp/${ttpId}/create-rule`, { method: 'POST' })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                showToast('Custom rule created from TTP', 'success');
            } else {
                showToast('Failed to create rule', 'danger');
            }
        });
}

// Utility functions
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    toast.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 1050;';
    
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" onclick="this.parentElement.parentElement.remove()"></button>
        </div>
    `;
    
    document.body.appendChild(toast);
    
    // Auto remove after 3 seconds
    setTimeout(() => {
        if (toast.parentNode) {
            toast.remove();
        }
    }, 3000);
}

// Clean up on page unload
window.addEventListener('beforeunload', function() {
    stopAutoRefresh();
    Object.values(charts).forEach(chart => chart.destroy());
});
</script>
{% endblock %}
'''

TTP_DETECTION_TEMPLATE = '''
{% extends "base.html" %}
{% block title %}TTP Detection{% endblock %}
{% block content %}
<div class="dashboard-header mb-4">
    <h2><i class="fas fa-project-diagram me-2"></i>TTP Detection - MITRE ATT&CK Framework</h2>
    <p class="text-muted">Tactics, Techniques, and Procedures detection based on MITRE ATT&CK framework</p>
</div>

<!-- TTP Statistics Cards -->
<div class="row mb-4">
    <div class="col-md-3 mb-3">
        <div class="stat-card">
            <h6 class="text-muted mb-2">Unique TTPs</h6>
            <h3>{{ ttp_stats.unique_ttps or 0 }}</h3>
            <small><i class="fas fa-crosshairs me-1"></i>Detected Techniques</small>
        </div>
    </div>
    <div class="col-md-3 mb-3">
        <div class="stat-card warning">
            <h6 class="text-muted mb-2">Total Detections</h6>
            <h3>{{ ttp_stats.total_ttp_detections or 0 }}</h3>
            <small><i class="fas fa-shield-alt me-1"></i>Last 7 Days</small>
        </div>
    </div>
    <div class="col-md-3 mb-3">
        <div class="stat-card critical">
            <h6 class="text-muted mb-2">Attacking IPs</h6>
            <h3>{{ ttp_stats.attacking_ips or 0 }}</h3>
            <small><i class="fas fa-network-wired me-1"></i>Unique Sources</small>
        </div>
    </div>
    <div class="col-md-3 mb-3">
        <div class="stat-card danger">
            <h6 class="text-muted mb-2">Targeted Assets</h6>
            <h3>{{ ttp_stats.targeted_assets or 0 }}</h3>
            <small><i class="fas fa-server me-1"></i>Under Attack</small>
        </div>
    </div>
</div>

<!-- TTP Detections Table -->
<div class="table-container mb-4">
    <h5><i class="fas fa-shield-alt me-2"></i>MITRE ATT&CK TTP Detections</h5>
    <div class="table-responsive">
        <table class="table table-hover">
            <thead>
                <tr>
                    <th>TTP/Technique</th>
                    <th>Detection Count</th>
                    <th>Critical</th>
                    <th>Source IPs</th>
                    <th>First Detected</th>
                    <th>Last Detected</th>
                    <th>Related Playbooks</th>
                </tr>
            </thead>
            <tbody>
                {% for ttp in ttp_detections[:20] %}
                <tr>
                    <td><strong>{{ ttp.ttp_match }}</strong></td>
                    <td><span class="badge bg-primary">{{ ttp.detection_count }}</span></td>
                    <td><span class="badge bg-danger">{{ ttp.critical_detections }}</span></td>
                    <td><small>{{ ttp.source_ips[:100] }}...</small></td>
                    <td><small>{{ ttp.first_detected }}</small></td>
                    <td><small>{{ ttp.last_detected }}</small></td>
                    <td>
                        {% if ttp.playbooks %}
                        <span class="badge bg-info">{{ ttp.playbooks|length }}</span>
                        {% else %}
                        <span class="text-muted">-</span>
                        {% endif %}
                    </td>
                </tr>
                {% else %}
                <tr><td colspan="7" class="text-center text-muted">No TTP detections available</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<!-- Attack Chains -->
<div class="table-container mb-4">
    <h5><i class="fas fa-link me-2"></i>Attack Chain Analysis</h5>
    <p class="text-muted small">Sequential TTP progressions indicating multi-stage attacks</p>
    <div class="table-responsive">
        <table class="table table-hover">
            <thead>
                <tr>
                    <th>Source IP</th>
                    <th>TTP Chain</th>
                    <th>TTP Count</th>
                    <th>Duration</th>
                </tr>
            </thead>
            <tbody>
                {% for chain in attack_chains[:15] %}
                <tr>
                    <td><span class="badge bg-danger">{{ chain.source_ip }}</span></td>
                    <td><code style="font-size: 0.85rem;">{{ chain.attack_chain[:200] }}...</code></td>
                    <td><span class="badge bg-warning text-dark">{{ chain.ttp_count }}</span></td>
                    <td><small>{{ chain.chain_start }} → {{ chain.chain_end }}</small></td>
                </tr>
                {% else %}
                <tr><td colspan="4" class="text-center text-muted">No attack chains detected</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<!-- TTP Correlations -->
<div class="table-container mb-4">
    <h5><i class="fas fa-sitemap me-2"></i>TTP Correlation Matrix</h5>
    <p class="text-muted small">TTPs frequently appearing together indicate coordinated attack patterns</p>
    <div class="table-responsive">
        <table class="table table-hover">
            <thead>
                <tr>
                    <th>TTP 1</th>
                    <th>TTP 2</th>
                    <th>Correlation Count</th>
                </tr>
            </thead>
            <tbody>
                {% for corr in ttp_correlations[:20] %}
                <tr>
                    <td><code>{{ corr.ttp1 }}</code></td>
                    <td><code>{{ corr.ttp2 }}</code></td>
                    <td><span class="badge bg-warning text-dark">{{ corr.correlation_count }}</span></td>
                </tr>
                {% else %}
                <tr><td colspan="3" class="text-center text-muted">No correlations detected</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<!-- Targeted Assets -->
<div class="table-container mb-4">
    <h5><i class="fas fa-bullseye me-2"></i>Most Targeted Assets</h5>
    <div class="table-responsive">
        <table class="table table-hover">
            <thead>
                <tr>
                    <th>Destination IP</th>
                    <th>Unique TTPs</th>
                    <th>Total Attacks</th>
                    <th>Attack Techniques</th>
                </tr>
            </thead>
            <tbody>
                {% for asset in targeted_assets[:15] %}
                <tr>
                    <td><span class="badge bg-info">{{ asset.dest_ip }}</span></td>
                    <td><span class="badge bg-danger">{{ asset.unique_ttps }}</span></td>
                    <td>{{ asset.total_attacks }}</td>
                    <td><small>{{ asset.attack_techniques[:100] }}...</small></td>
                </tr>
                {% else %}
                <tr><td colspan="4" class="text-center text-muted">No targeted assets identified</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<!-- Recent TTP Activity -->
<div class="table-container mb-4">
    <h5><i class="fas fa-clock me-2"></i>Recent TTP Activity</h5>
    <div class="table-responsive">
        <table class="table table-hover">
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>TTP</th>
                    <th>Source IP</th>
                    <th>Source</th>
                    <th>Severity</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody>
                {% for ttp in recent_ttps[:20] %}
                <tr>
                    <td><small>{{ ttp.timestamp }}</small></td>
                    <td><strong>{{ ttp.ttp_match }}</strong></td>
                    <td>{{ ttp.source_ip or 'N/A' }}</td>
                    <td>{{ ttp.source_name }}</td>
                    <td>
                        <span class="badge bg-{{ 'danger' if ttp.severity == 'CRITICAL' else ('warning' if ttp.severity == 'HIGH' else 'info') }}">
                            {{ ttp.severity }}
                        </span>
                    </td>
                    <td><small>{{ ttp.message[:80] }}...</small></td>
                </tr>
                {% else %}
                <tr><td colspan="6" class="text-center text-muted">No recent TTP activity</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

{% endblock %}
'''

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point."""
    if not HAS_DEPS:
        print("Please install required dependencies:")
        print("pip install flask werkzeug plotly watchdog")
        return
    
    # Create uploads directory
    os.makedirs('uploads', exist_ok=True)
    
    # Start the application
    app = LogAnalyzerApp()
    app.run(host='0.0.0.0', port=5000, debug=False)

if __name__ == '__main__':
    main()