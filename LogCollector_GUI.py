#!/usr/bin/env python3
"""
Desktop GUI Log Collector - Real-time System & Network Log Collection
Supports: Windows Event Logs, Syslog, Network packets, File monitoring
"""

import os
import sys
import json
import sqlite3
import threading
import queue
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import csv

# Try to import optional system log collectors
try:
    import win32evtlog
    import win32con
    import pywintypes
    HAS_WINDOWS_LOGS = True
except ImportError:
    HAS_WINDOWS_LOGS = False

try:
    import socket
    HAS_NETWORK = True
except ImportError:
    HAS_NETWORK = False

# ============================================================================
# WINDOWS EVENT LOG COLLECTOR
# ============================================================================

class WindowsEventLogCollector:
    """Real-time Windows Event Log collector."""
    
    def __init__(self, playbook_type: str = 'windows'):
        self.playbook_type = playbook_type
        self.running = False
        self.collected_logs = []
        
    def start(self) -> List[Dict]:
        """Collect Windows Event Logs."""
        if not HAS_WINDOWS_LOGS:
            return [{'error': 'Windows Event Log module not available (install pywin32)'}]
        
        collected = []
        try:
            # Event log sources to monitor
            sources = ['System', 'Application', 'Security']
            
            for source in sources:
                try:
                    handle = win32evtlog.OpenEventLog(None, source)
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    events = win32evtlog.ReadEventLog(handle, flags, 0)
                    
                    for event in events[:100]:  # Last 100 events per source
                        event_data = {
                            'timestamp': str(event.TimeGenerated),
                            'source': source,
                            'event_id': event.EventID,
                            'event_type': event.EventType,
                            'message': event.StringInserts[0] if event.StringInserts else 'N/A',
                            'severity': self._map_severity(event.EventType),
                            'source_name': f'Windows-{source}'
                        }
                        collected.append(event_data)
                    
                    win32evtlog.CloseEventLog(handle)
                except Exception as e:
                    collected.append({'error': f'Failed to read {source}: {e}'})
        
        except Exception as e:
            collected.append({'error': f'Windows Event Log error: {e}'})
        
        return collected
    
    @staticmethod
    def _map_severity(event_type: int) -> str:
        """Map Windows event type to severity."""
        mapping = {
            win32con.EVENTLOG_ERROR_TYPE: 'HIGH',
            win32con.EVENTLOG_WARNING_TYPE: 'MEDIUM',
            win32con.EVENTLOG_INFORMATION_TYPE: 'INFO',
        }
        return mapping.get(event_type, 'INFO')


class SyslogCollector:
    """Syslog/system log collector (Linux/Mac)."""
    
    def __init__(self, playbook_type: str = 'linux'):
        self.playbook_type = playbook_type
        self.running = False
        
    def start(self) -> List[Dict]:
        """Collect system logs from common locations."""
        collected = []
        log_files = [
            '/var/log/auth.log',
            '/var/log/syslog',
            '/var/log/messages',
            '/var/log/secure',
        ]
        
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()[-100:]  # Last 100 lines
                        for line in lines:
                            if line.strip():
                                collected.append({
                                    'timestamp': datetime.now().isoformat(),
                                    'source': log_file,
                                    'message': line.strip(),
                                    'severity': 'INFO',
                                    'source_name': f'Syslog-{log_file}'
                                })
                except Exception as e:
                    collected.append({'error': f'Failed to read {log_file}: {e}'})
        
        return collected


class NetworkPacketCollector:
    """Minimal network activity logger."""
    
    def __init__(self, playbook_type: str = 'network'):
        self.playbook_type = playbook_type
        
    def start(self) -> List[Dict]:
        """Log local network connections and DNS."""
        collected = []
        try:
            if sys.platform == 'win32':
                import subprocess
                result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, timeout=5)
                for line in result.stdout.split('\n')[4:]:  # Skip headers
                    if line.strip():
                        collected.append({
                            'timestamp': datetime.now().isoformat(),
                            'source': 'netstat',
                            'message': line.strip(),
                            'severity': 'INFO',
                            'source_name': 'Network-Connections'
                        })
            else:
                # Linux netstat
                import subprocess
                result = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True, timeout=5)
                for line in result.stdout.split('\n')[2:]:
                    if line.strip():
                        collected.append({
                            'timestamp': datetime.now().isoformat(),
                            'source': 'netstat',
                            'message': line.strip(),
                            'severity': 'INFO',
                            'source_name': 'Network-Connections'
                        })
        except Exception as e:
            collected.append({'error': f'Network collection error: {e}'})
        
        return collected


# ============================================================================
# SIMPLE DATABASE FOR LOGS
# ============================================================================

class LogDatabase:
    """SQLite database for storing collected logs."""
    
    def __init__(self, db_path: str = 'collected_logs.db'):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    source_name TEXT,
                    severity TEXT,
                    message TEXT,
                    source TEXT,
                    event_type TEXT,
                    event_id TEXT
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON logs(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON logs(severity)')
            conn.commit()
    
    def insert_logs(self, logs: List[Dict]):
        """Insert logs into database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for log in logs:
                cursor.execute('''
                    INSERT INTO logs (timestamp, source_name, severity, message, source, event_type, event_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    log.get('timestamp', ''),
                    log.get('source_name', ''),
                    log.get('severity', 'INFO'),
                    log.get('message', ''),
                    log.get('source', ''),
                    log.get('event_type', ''),
                    log.get('event_id', '')
                ))
            conn.commit()
    
    def get_logs(self, limit: int = 500) -> List[Dict]:
        """Fetch recent logs."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_stats(self) -> Dict:
        """Get log statistics."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM logs')
            total = cursor.fetchone()[0]
            
            cursor.execute('''
                SELECT severity, COUNT(*) as count
                FROM logs
                GROUP BY severity
            ''')
            severity_dist = {row[0]: row[1] for row in cursor.fetchall()}
            
            cursor.execute('''
                SELECT source_name, COUNT(*) as count
                FROM logs
                GROUP BY source_name
                ORDER BY count DESC
            ''')
            top_sources = dict(cursor.fetchall())
            
            return {
                'total_logs': total,
                'severity_distribution': severity_dist,
                'top_sources': top_sources
            }
    
    def export_csv(self, filepath: str):
        """Export logs to CSV."""
        logs = self.get_logs(5000)
        if not logs:
            return False
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=logs[0].keys())
            writer.writeheader()
            writer.writerows(logs)
        return True


# ============================================================================
# GUI APPLICATION
# ============================================================================

class LogCollectorGUI:
    """Desktop GUI for real-time log collection."""
    
    def __init__(self, root, playbook_type: str = 'all'):
        self.root = root
        self.root.title(f"Log Collector - {playbook_type.upper()} Scope")
        self.root.geometry("1200x700")
        self.playbook_type = playbook_type
        self.db = LogDatabase()
        self.log_queue = queue.Queue()
        self.is_collecting = False
        self.collector_thread = None
        
        # Initialize collectors based on playbook type
        self.collectors = self._init_collectors()
        
        self._build_ui()
        self._schedule_queue_check()
    
    def _init_collectors(self) -> List:
        """Initialize appropriate collectors based on playbook type."""
        collectors = []
        
        if self.playbook_type in ['windows', 'all']:
            collectors.append(('Windows Event Logs', WindowsEventLogCollector()))
        if self.playbook_type in ['linux', 'mac', 'all']:
            collectors.append(('System Logs', SyslogCollector()))
        
        collectors.append(('Network Connections', NetworkPacketCollector()))
        
        return collectors
    
    def _build_ui(self):
        """Build the GUI layout."""
        # Top control panel
        control_frame = ttk.Frame(self.root, padding="10")
        control_frame.pack(fill=tk.X, side=tk.TOP)
        
        ttk.Label(control_frame, text=f"Playbook: {self.playbook_type.upper()}", 
                 font=('Arial', 12, 'bold')).pack(side=tk.LEFT, padx=5)
        
        self.start_btn = ttk.Button(control_frame, text="▶ Start Collection", 
                                    command=self._start_collection)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="⏹ Stop Collection", 
                                   command=self._stop_collection, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text="📊 Statistics", 
                  command=self._show_stats).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text="💾 Export CSV", 
                  command=self._export_logs).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text="🔍 View Database", 
                  command=self._open_database_viewer).pack(side=tk.LEFT, padx=5)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_frame = ttk.Frame(self.root, padding="5")
        status_frame.pack(fill=tk.X, side=tk.TOP)
        ttk.Label(status_frame, textvariable=self.status_var, 
                 foreground="blue").pack(side=tk.LEFT)
        
        # Notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Live Log tab
        live_frame = ttk.Frame(notebook)
        notebook.add(live_frame, text="📋 Live Logs")
        
        ttk.Label(live_frame, text="Real-time log stream:").pack(anchor=tk.W, padx=5, pady=5)
        self.log_text = scrolledtext.ScrolledText(live_frame, height=20, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure text tags for severity colors
        self.log_text.tag_config('CRITICAL', foreground='red')
        self.log_text.tag_config('HIGH', foreground='orange')
        self.log_text.tag_config('MEDIUM', foreground='gold')
        self.log_text.tag_config('LOW', foreground='blue')
        self.log_text.tag_config('INFO', foreground='green')
        
        # Collector Status tab
        status_tab = ttk.Frame(notebook)
        notebook.add(status_tab, text="🔧 Collectors")
        
        self.collector_status = scrolledtext.ScrolledText(status_tab, height=20)
        self.collector_status.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Log in memory counter
        self.count_var = tk.StringVar(value="Logs collected: 0")
        ttk.Label(self.root, textvariable=self.count_var, 
                 font=('Arial', 10, 'bold')).pack(side=tk.BOTTOM, pady=5)
    
    def _start_collection(self):
        """Start real-time log collection in background thread."""
        if self.is_collecting:
            messagebox.showwarning("Already Running", "Collection is already active")
            return
        
        self.is_collecting = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set("🔴 Collecting logs...")
        
        self.collector_thread = threading.Thread(target=self._collector_loop, daemon=True)
        self.collector_thread.start()
    
    def _stop_collection(self):
        """Stop log collection."""
        self.is_collecting = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("⏸ Collection stopped")
    
    def _collector_loop(self):
        """Background thread that collects logs periodically."""
        interval = 5  # Collect every 5 seconds
        
        while self.is_collecting:
            try:
                collected_all = []
                collector_msgs = []
                
                for name, collector in self.collectors:
                    try:
                        logs = collector.start()
                        filtered_logs = [l for l in logs if 'error' not in l]
                        collected_all.extend(filtered_logs)
                        collector_msgs.append(f"✓ {name}: {len(filtered_logs)} logs")
                    except Exception as e:
                        collector_msgs.append(f"✗ {name}: {e}")
                
                if collected_all:
                    self.db.insert_logs(collected_all)
                    self.log_queue.put(('logs', collected_all))
                
                self.log_queue.put(('status', collector_msgs))
                time.sleep(interval)
            
            except Exception as e:
                self.log_queue.put(('error', str(e)))
                time.sleep(interval)
    
    def _schedule_queue_check(self):
        """Periodically check the log queue and update UI."""
        try:
            while True:
                msg_type, data = self.log_queue.get_nowait()
                
                if msg_type == 'logs':
                    self._display_logs(data)
                elif msg_type == 'status':
                    self._update_collector_status(data)
                elif msg_type == 'error':
                    self.log_text.insert(tk.END, f"[ERROR] {data}\n", 'CRITICAL')
                    self.log_text.see(tk.END)
        
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(500, self._schedule_queue_check)
    
    def _display_logs(self, logs: List[Dict]):
        """Display logs in the live text widget."""
        for log in logs:
            if 'error' in log:
                self.log_text.insert(tk.END, f"[ERROR] {log['error']}\n", 'CRITICAL')
            else:
                severity = log.get('severity', 'INFO')
                timestamp = log.get('timestamp', '')
                source = log.get('source_name', 'Unknown')
                message = log.get('message', '')[:100]
                
                line = f"[{timestamp}] [{severity}] {source} - {message}\n"
                self.log_text.insert(tk.END, line, severity)
        
        self.log_text.see(tk.END)
        
        # Update counter
        stats = self.db.get_stats()
        self.count_var.set(f"Logs collected: {stats['total_logs']}")
    
    def _update_collector_status(self, msgs: List[str]):
        """Update collector status display."""
        self.collector_status.config(state=tk.NORMAL)
        self.collector_status.delete('1.0', tk.END)
        
        for msg in msgs:
            self.collector_status.insert(tk.END, msg + "\n")
        
        self.collector_status.config(state=tk.DISABLED)
    
    def _show_stats(self):
        """Show statistics window."""
        stats = self.db.get_stats()
        
        msg = f"""
Log Collection Statistics:

Total Logs: {stats['total_logs']}

Severity Distribution:
{chr(10).join([f"  {k}: {v}" for k, v in stats['severity_distribution'].items()])}

Top Sources:
{chr(10).join([f"  {k}: {v}" for k, v in list(stats['top_sources'].items())[:10]])}
        """
        
        messagebox.showinfo("Statistics", msg)
    
    def _export_logs(self):
        """Export logs to CSV."""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        
        if filepath:
            if self.db.export_csv(filepath):
                messagebox.showinfo("Success", f"Logs exported to:\n{filepath}")
            else:
                messagebox.showerror("Error", "Failed to export logs")
    
    def _open_database_viewer(self):
        """Open database viewer window."""
        viewer = tk.Toplevel(self.root)
        viewer.title("Database Viewer")
        viewer.geometry("800x400")
        
        logs = self.db.get_logs(200)
        
        # Create treeview
        columns = ('timestamp', 'source_name', 'severity', 'message')
        tree = ttk.Treeview(viewer, columns=columns, height=15)
        tree.column('#0', width=0, stretch=tk.NO)
        tree.column('timestamp', width=150, anchor=tk.W)
        tree.column('source_name', width=150, anchor=tk.W)
        tree.column('severity', width=80, anchor=tk.CENTER)
        tree.column('message', width=400, anchor=tk.W)
        
        tree.heading('#0', text='', anchor=tk.W)
        tree.heading('timestamp', text='Timestamp', anchor=tk.W)
        tree.heading('source_name', text='Source', anchor=tk.W)
        tree.heading('severity', text='Severity', anchor=tk.CENTER)
        tree.heading('message', text='Message', anchor=tk.W)
        
        for log in logs:
            tree.insert('', 'end', values=(
                log['timestamp'],
                log['source_name'],
                log['severity'],
                log['message'][:50]
            ))
        
        scrollbar = ttk.Scrollbar(viewer, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        
        tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        scrollbar.pack(fill=tk.Y, side=tk.RIGHT)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point for GUI application."""
    playbook_type = os.getenv('ACTIVE_PLAYBOOK_TYPE', 'all').lower()
    
    root = tk.Tk()
    app = LogCollectorGUI(root, playbook_type)
    root.mainloop()


if __name__ == '__main__':
    main()
