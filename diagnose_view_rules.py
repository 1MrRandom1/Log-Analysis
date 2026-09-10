#!/usr/bin/env python
"""
Quick diagnostic to check why View Rules shows 0 playbooks
"""

import os
import json
from pathlib import Path

print("="*60)
print("DIAGNOSING VIEW RULES ISSUE")
print("="*60)

# Check current directory
cwd = Path.cwd()
print(f"\nCurrent directory: {cwd}")

# Check if manifest exists
manifest_path = Path('manifest.json')
if manifest_path.exists():
    print("\n✓ Running from PORTABLE PACKAGE")
    with open(manifest_path, 'r') as f:
        manifest = json.load(f)
    print(f"  Selected types: {manifest.get('selected_types', 'NOT FOUND')}")
    print(f"  Playbook type: {manifest.get('playbook_type', 'NOT FOUND')}")
else:
    print("\n✓ Running from MAIN DIRECTORY")

# Check environment variables
env_multi = os.getenv('ACTIVE_PLAYBOOK_TYPES')
env_single = os.getenv('ACTIVE_PLAYBOOK_TYPE')

print(f"\nEnvironment variables:")
print(f"  ACTIVE_PLAYBOOK_TYPES: {env_multi or 'NOT SET'}")
print(f"  ACTIVE_PLAYBOOK_TYPE: {env_single or 'NOT SET'}")

# Check playbook files
print(f"\nPlaybook files in current directory:")
playbook_files = list(Path('.').glob('playbooks_*.json'))
print(f"  Found {len(playbook_files)} playbook files")
for f in sorted(playbook_files):
    print(f"    - {f.name}")

# Now try to initialize the app and check what happens
print("\n" + "="*60)
print("INITIALIZING APP TO CHECK RULE LOADING")
print("="*60)

try:
    import sys
    sys.path.insert(0, '.')
    from Log_Analyzer import LogAnalyzerApp
    
    print("\nInitializing LogAnalyzerApp...")
    app = LogAnalyzerApp()
    
    print(f"\n✓ Initialization complete!")
    print(f"  All playbook rules: {len(app.all_playbook_rules)}")
    print(f"  Playbooks by type: {len(app.playbooks_by_type)}")
    print(f"  Active playbook type: {app.active_playbook_type}")
    print(f"  Active playbook types: {app.active_playbook_types}")
    print(f"  LogManager rules: {len(app.log_manager.playbook_rules)}")
    
    # Check what view_rules would return
    print(f"\nWhat View Rules endpoint would show:")
    active_types = getattr(app, 'active_playbook_types', ['all'])
    playbook_stats = []
    
    for ptype, playbook in app.playbooks_by_type.items():
        # Only show if 'all' or if this type is in active list
        if 'all' not in active_types and ptype not in active_types:
            print(f"  - Skipping {ptype} (not in active list)")
            continue
        
        playbook_stats.append(ptype)
        print(f"  ✓ Including {ptype}")
    
    print(f"\nRESULT:")
    print(f"  Total playbooks to display: {len(playbook_stats)}")
    print(f"  Total rules to display: {len(app.log_manager.playbook_rules)}")
    
    if len(playbook_stats) == 0:
        print(f"\n❌ ERROR: No playbooks would be displayed!")
        print(f"  This explains why you're seeing 0 playbooks.")
        print(f"  Active types: {active_types}")
        print(f"  Available types: {list(app.playbooks_by_type.keys())}")
    else:
        print(f"\n✅ Should show {len(playbook_stats)} playbooks")

except Exception as e:
    print(f"\n❌ ERROR during initialization: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*60)
