#!/usr/bin/env python
"""
Log Analyzer - Choose between Web UI and Desktop GUI
Supports multiple playbook types from manifest
"""

import os
import sys
import json
import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import threading
import time

class LauncherGUI:
    def __init__(self, root, playbook_types='all'):
        self.root = root
        # Parse playbook types (could be 'all', 'windows', or 'windows+linux')
        if isinstance(playbook_types, str):
            self.playbook_types = [t.strip() for t in playbook_types.split('+')] if '+' in playbook_types else [playbook_types]
        else:
            self.playbook_types = playbook_types if isinstance(playbook_types, list) else ['all']
        
        # Format display
        self.display_scope = '+'.join(self.playbook_types).upper() if self.playbook_types != ['all'] else 'ALL'
        
        self.root.title("Log Analyzer Launcher")
        self.root.geometry("450x350")
        self.root.resizable(False, False)
        
        # Center window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (self.root.winfo_width() // 2)
        y = (self.root.winfo_screenheight() // 2) - (self.root.winfo_height() // 2)
        self.root.geometry(f"+{x}+{y}")
        
        self._build_ui()
    
    def _build_ui(self):
        # Header
        header = ttk.Frame(self.root)
        header.pack(fill=tk.X, padx=20, pady=20)
        
        ttk.Label(header, text="Log Analyzer", 
                 font=('Arial', 16, 'bold')).pack()
        ttk.Label(header, text=f"Scope: {self.display_scope}", 
                 font=('Arial', 10, 'italic')).pack()
        
        # Show selected playbooks
        if self.playbook_types != ['all']:
            playbook_info = f"Monitoring: {', '.join(t.title() for t in self.playbook_types)}"
            ttk.Label(header, text=playbook_info,
                     font=('Arial', 9), foreground='green').pack()
        
        # Separator
        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Options frame
        options = ttk.Frame(self.root)
        options.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        ttk.Label(options, text="Select Mode:", 
                 font=('Arial', 11, 'bold')).pack(anchor=tk.W, pady=(0, 15))
        
        # Web UI button
        web_frame = ttk.LabelFrame(options, text="🌐 Web Interface", padding=10)
        web_frame.pack(fill=tk.X, pady=10)
        ttk.Label(web_frame, text="Browser-based UI with analytics,\nplaybook management, and advanced features.",
                 justify=tk.LEFT).pack(anchor=tk.W)
        ttk.Button(web_frame, text="Launch Web UI →", 
                  command=self._launch_web).pack(fill=tk.X, pady=5)
        
        # Desktop GUI button
        desktop_frame = ttk.LabelFrame(options, text="🖥️ Desktop GUI", padding=10)
        desktop_frame.pack(fill=tk.X, pady=10)
        ttk.Label(desktop_frame, text="Native desktop app with real-time system\nlog collection (Windows Event Log, Syslog, Network).",
                 justify=tk.LEFT).pack(anchor=tk.W)
        ttk.Button(desktop_frame, text="Launch Desktop GUI →", 
                  command=self._launch_desktop).pack(fill=tk.X, pady=5)
        
        # Footer
        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        ttk.Button(self.root, text="Exit", 
                  command=self.root.quit).pack(fill=tk.X, padx=20, pady=10)
    
    def _launch_web(self):
        """Launch web interface."""
        messagebox.showinfo("Web UI", "Starting web server on http://localhost:5000...\n\nBrowser will open shortly.")
        
        def run_web():
            try:
                from Log_Analyzer import LogAnalyzerApp
                app = LogAnalyzerApp()
                # Set playbook types in environment
                os.environ['ACTIVE_PLAYBOOK_TYPES'] = ','.join(self.playbook_types)
                # Use 0.0.0.0 to allow local access, try port 5000 first, fallback to 5001
                try:
                    app.run(host='0.0.0.0', port=5000, debug=False)
                except OSError:
                    # Port 5000 in use or permission denied, try 5001
                    app.run(host='0.0.0.0', port=5001, debug=False)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to start web server:\n{e}")
        
        thread = threading.Thread(target=run_web, daemon=True)
        thread.start()
        
        # Wait a moment then open browser
        time.sleep(2)
        import webbrowser
        webbrowser.open('http://localhost:5000')
    
    def _launch_desktop(self):
        """Launch desktop GUI."""
        try:
            # Set playbook types in environment
            os.environ['ACTIVE_PLAYBOOK_TYPES'] = ','.join(self.playbook_types)
            from LogCollector_GUI import main
            self.root.destroy()
            main()
        except ImportError:
            messagebox.showerror("Error", "LogCollector_GUI.py not found.\n\nMake sure it's in the same directory.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start desktop GUI:\n{e}")


def main():
    # Support both single type (ACTIVE_PLAYBOOK_TYPE) and multiple types (ACTIVE_PLAYBOOK_TYPES)
    playbook_types_str = os.getenv('ACTIVE_PLAYBOOK_TYPES', os.getenv('ACTIVE_PLAYBOOK_TYPE', 'all')).lower()
    playbook_types = [t.strip() for t in playbook_types_str.split(',') if t.strip()]
    
    root = tk.Tk()
    launcher = LauncherGUI(root, playbook_types)
    root.mainloop()


if __name__ == '__main__':
    main()
