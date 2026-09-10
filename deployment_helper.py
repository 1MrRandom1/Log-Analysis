"""
deployment_helper.py - Network Deployment Assistant for Log Analyzer

This script helps prepare and manage Log Analyzer deployments across your network.
Supports multi-playbook packages, environment variable configuration, and deployment tracking.

Usage:
    python deployment_helper.py --list-packages
    python deployment_helper.py --verify <package.zip>
    python deployment_helper.py --extract <package.zip> --dest C:\Program Files\LogAnalyzer
    python deployment_helper.py --update-env --types windows,linux
"""

import os
import sys
import json
import argparse
import zipfile
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

class DeploymentHelper:
    """Helper class for Log Analyzer network deployments."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.workspace = Path(__file__).parent
        
    def log(self, msg: str, level: str = "INFO"):
        """Print log message."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if self.verbose or level in ["ERROR", "WARNING"]:
            print(f"[{timestamp}] [{level}] {msg}")
    
    def list_packages(self) -> None:
        """List all available deployment packages."""
        self.log("Scanning for deployment packages...")
        packages = list(self.workspace.glob("plug_and_play_*.zip"))
        
        if not packages:
            print("No deployment packages found.")
            return
        
        print(f"\n{'Package Name':<40} {'Date Modified':<20} {'Size':<10}")
        print("=" * 70)
        
        for pkg in sorted(packages, key=lambda x: x.stat().st_mtime, reverse=True):
            size_mb = pkg.stat().st_size / (1024 * 1024)
            mtime = datetime.fromtimestamp(pkg.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            print(f"{pkg.name:<40} {mtime:<20} {size_mb:>8.2f} MB")
    
    def verify_package(self, package_path: str) -> bool:
        """Verify package integrity and content."""
        pkg_path = Path(package_path)
        
        if not pkg_path.exists():
            self.log(f"Package not found: {package_path}", "ERROR")
            return False
        
        if not zipfile.is_zipfile(pkg_path):
            self.log(f"Invalid ZIP file: {package_path}", "ERROR")
            return False
        
        print(f"\nVerifying: {pkg_path.name}")
        print("=" * 50)
        
        try:
            with zipfile.ZipFile(pkg_path, 'r') as zf:
                # Check manifest
                if 'manifest.json' not in zf.namelist():
                    self.log("Missing manifest.json", "ERROR")
                    return False
                
                manifest_data = json.loads(zf.read('manifest.json').decode('utf-8'))
                print(f"✓ Package Type: {manifest_data.get('playbook_type', 'Unknown')}")
                print(f"✓ Selected Types: {', '.join(manifest_data.get('selected_types', []))}")
                print(f"✓ Rules: {manifest_data.get('rule_count', 0)}")
                print(f"✓ Logs: {manifest_data.get('log_count', 0)}")
                print(f"✓ Generated: {manifest_data.get('generated_at', 'Unknown')}")
                
                # Check critical files
                required_files = ['manifest.json', 'Log_Analyzer.py', 'run_portable.py']
                platform_files = {
                    'windows': 'start_portable.bat',
                    'unix': 'start_portable.sh'
                }
                
                print(f"\nFiles ({len(zf.namelist())} total):")
                for req_file in required_files:
                    if req_file in zf.namelist():
                        print(f"  ✓ {req_file}")
                    else:
                        print(f"  ✗ {req_file} (MISSING)")
                        return False
                
                print(f"\nPlatform launchers:")
                if platform_files['windows'] in zf.namelist():
                    print(f"  ✓ Windows ({platform_files['windows']})")
                if platform_files['unix'] in zf.namelist():
                    print(f"  ✓ Unix/Linux ({platform_files['unix']})")
                
                # Check playbook files
                playbooks = [f for f in zf.namelist() if f.startswith('playbooks_')]
                if playbooks:
                    print(f"\nPlaybooks ({len(playbooks)}):")
                    for pb in playbooks:
                        print(f"  ✓ {pb}")
                
                print("\n✓ Package verification passed!")
                return True
                
        except Exception as e:
            self.log(f"Verification failed: {e}", "ERROR")
            return False
    
    def extract_package(self, package_path: str, dest: str) -> bool:
        """Extract package to destination."""
        pkg_path = Path(package_path)
        dest_path = Path(dest)
        
        if not pkg_path.exists():
            self.log(f"Package not found: {package_path}", "ERROR")
            return False
        
        if not zipfile.is_zipfile(pkg_path):
            self.log(f"Invalid ZIP file: {package_path}", "ERROR")
            return False
        
        print(f"\nExtracting: {pkg_path.name}")
        print(f"Destination: {dest_path}")
        
        try:
            dest_path.mkdir(parents=True, exist_ok=True)
            
            with zipfile.ZipFile(pkg_path, 'r') as zf:
                zf.extractall(dest_path)
            
            # Make shell scripts executable on Unix
            if sys.platform != 'win32':
                sh_file = dest_path / 'start_portable.sh'
                if sh_file.exists():
                    os.chmod(sh_file, 0o755)
                    self.log(f"Made executable: {sh_file}")
            
            print(f"\n✓ Extracted {len(os.listdir(dest_path))} items to {dest_path}")
            return True
            
        except Exception as e:
            self.log(f"Extraction failed: {e}", "ERROR")
            return False
    
    def get_package_info(self, package_path: str) -> Optional[Dict[str, Any]]:
        """Get package metadata."""
        try:
            with zipfile.ZipFile(package_path, 'r') as zf:
                if 'manifest.json' in zf.namelist():
                    manifest = json.loads(zf.read('manifest.json').decode('utf-8'))
                    return manifest
        except Exception as e:
            self.log(f"Could not read manifest: {e}", "ERROR")
        return None
    
    def update_env_file(self, types: str, output_file: str = ".env") -> bool:
        """Create/update .env file for deployment."""
        env_content = f"ACTIVE_PLAYBOOK_TYPES={types}\n"
        
        try:
            Path(output_file).write_text(env_content)
            print(f"✓ Created {output_file}")
            print(f"  ACTIVE_PLAYBOOK_TYPES={types}")
            return True
        except Exception as e:
            self.log(f"Failed to create .env: {e}", "ERROR")
            return False
    
    def generate_deployment_report(self, packages_dir: Optional[str] = None) -> None:
        """Generate a deployment summary report."""
        search_dir = Path(packages_dir) if packages_dir else self.workspace
        packages = list(search_dir.glob("plug_and_play_*.zip"))
        
        print("\n" + "=" * 70)
        print("LOG ANALYZER DEPLOYMENT REPORT")
        print("=" * 70)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Workspace: {self.workspace}")
        print(f"Packages Found: {len(packages)}\n")
        
        if not packages:
            print("No packages available for deployment.\n")
            return
        
        total_size = 0
        all_types = set()
        
        for pkg in sorted(packages):
            info = self.get_package_info(str(pkg))
            if info:
                total_size += pkg.stat().st_size
                for t in info.get('selected_types', []):
                    all_types.add(t)
                
                print(f"Package: {pkg.name}")
                print(f"  Types: {', '.join(info.get('selected_types', []))}")
                print(f"  Rules: {info.get('rule_count', 0)}")
                print(f"  Size: {pkg.stat().st_size / (1024*1024):.2f} MB")
                print(f"  Generated: {info.get('generated_at', 'Unknown')}\n")
        
        print("-" * 70)
        print(f"Total Packages: {len(packages)}")
        print(f"Total Size: {total_size / (1024*1024):.2f} MB")
        print(f"Playbook Types: {', '.join(sorted(all_types))}")
        print("=" * 70 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description='Log Analyzer Network Deployment Helper',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python deployment_helper.py --list
  python deployment_helper.py --verify plug_and_play_windows+linux.zip
  python deployment_helper.py --extract plug_and_play_windows.zip -d "C:\\Program Files\\LogAnalyzer"
  python deployment_helper.py --report
        '''
    )
    
    parser.add_argument('--list', action='store_true', help='List available packages')
    parser.add_argument('--verify', metavar='PACKAGE', help='Verify package integrity')
    parser.add_argument('--extract', metavar='PACKAGE', help='Extract package')
    parser.add_argument('-d', '--dest', metavar='DEST', help='Extraction destination')
    parser.add_argument('--update-env', action='store_true', help='Create .env file')
    parser.add_argument('--types', metavar='TYPES', help='Playbook types (comma-separated)')
    parser.add_argument('--report', action='store_true', help='Generate deployment report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    helper = DeploymentHelper(verbose=args.verbose)
    
    if args.list:
        helper.list_packages()
    elif args.verify:
        success = helper.verify_package(args.verify)
        sys.exit(0 if success else 1)
    elif args.extract:
        if not args.dest:
            print("Error: --dest required with --extract")
            sys.exit(1)
        success = helper.extract_package(args.extract, args.dest)
        sys.exit(0 if success else 1)
    elif args.update_env:
        if not args.types:
            print("Error: --types required with --update-env")
            sys.exit(1)
        success = helper.update_env_file(args.types)
        sys.exit(0 if success else 1)
    elif args.report:
        helper.generate_deployment_report()
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
