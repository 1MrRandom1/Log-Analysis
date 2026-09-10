#!/usr/bin/env python
"""
Log Analyzer - Portable Edition Entry Point
Automatically detects deployment mode and runs with appropriate playbook types
"""

import os
import sys
import json
import subprocess
import time
from pathlib import Path

def load_manifest():
    """Load manifest.json if this is a deployed package."""
    manifest_path = Path(__file__).parent / 'manifest.json'
    if manifest_path.exists():
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load manifest: {e}")
    return None

def main():
    # Check for manifest in deployed package
    manifest = load_manifest()
    
    # Set environment variables based on manifest or existing env
    if manifest and 'selected_types' in manifest:
        selected = ','.join(manifest['selected_types'])
        os.environ['ACTIVE_PLAYBOOK_TYPES'] = selected
        print(f"✓ Loaded from manifest: {selected}")
    else:
        # Use existing environment or default
        types = os.getenv('ACTIVE_PLAYBOOK_TYPES') or os.getenv('ACTIVE_PLAYBOOK_TYPE', 'all')
        os.environ['ACTIVE_PLAYBOOK_TYPES'] = types
    
    # Try to import and run Launcher first (for GUI mode)
    try:
        from Launcher import main as launcher_main
        print("Starting with Launcher (GUI mode)...")
        launcher_main()
        sys.exit(0)
    except (ImportError, Exception) as e:
        print(f"Launcher not available: {e}")
        print("Falling back to web mode...")
    
    # Fallback to web UI
    try:
        from Log_Analyzer import LogAnalyzerApp, HAS_DEPS
        
        if not HAS_DEPS:
            print("Installing dependencies on first run...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'])
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', 
                                 'flask', 'werkzeug', 'plotly', 'watchdog', 'reportlab'])
            time.sleep(1)
        
        app = LogAnalyzerApp()
        playbooks = os.environ.get('ACTIVE_PLAYBOOK_TYPES', 'all')
        
        print(f"\n{'='*50}")
        print("  Log Analyzer - Portable Edition")
        print(f"{'='*50}")
        print(f"Active Playbooks: {playbooks.upper()}")
        print(f"Web UI: http://localhost:5000")
        print(f"\nPress Ctrl+C to stop")
        print(f"{'='*50}\n")
        
        # Use 0.0.0.0 to allow local access, try port 5000 first, fallback to 5001
        try:
            app.run(host='0.0.0.0', port=5000, debug=False)
        except OSError:
            # Port 5000 in use or permission denied, try 5001
            print("Port 5000 in use or access denied, trying port 5001...")
            app.run(host='0.0.0.0', port=5001, debug=False)
    except Exception as e:
        print(f"Error starting Log Analyzer: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
