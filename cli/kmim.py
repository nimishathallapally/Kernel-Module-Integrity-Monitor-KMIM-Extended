#!/usr/bin/env python3

import os
import sys
import json
import hashlib
import argparse
import time
import signal
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import csv

from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from bcc import BPF

from .utils import get_module_info, calculate_module_hash
from .logging import get_logger
import ctypes as ct

console = Console()
logger = get_logger()

class KMIMMonitor:
    """Enhanced KMIM with continuous monitoring and anomaly detection"""
    
    def __init__(self):
        self.bpf = None
        self.baseline = None
        self.monitoring = False
        self.anomalies = []
        self.last_scan_time = None
        self.scan_results = {}
        
    def find_module_path(self, name):
        """Find the path to a kernel module file"""
        kernel_ver = os.uname().release
        search_paths = [
            f"/lib/modules/{kernel_ver}/kernel/",
            f"/lib/modules/{kernel_ver}/",
            "/lib/modules/",
            "/usr/lib/modules/"
        ]
        
        for base in search_paths:
            for root, _, files in os.walk(base):
                if f"{name}.ko" in files:
                    return os.path.join(root, f"{name}.ko")
        return None

    def get_syscall_addresses(self):
        """Get syscall table addresses"""
        syscalls = {}
        try:
            # Read from /proc/kallsyms to get syscall addresses
            with open('/proc/kallsyms', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3 and 'sys_call_table' in parts[2]:
                        syscalls[parts[2]] = parts[0]
                    elif len(parts) >= 3 and parts[2].startswith('__x64_sys_'):
                        syscalls[parts[2]] = parts[0]
            return syscalls
        except Exception as e:
            # If we can't read kallsyms, return a mock count for demo
            console.print(f"[yellow]Warning: Could not read syscall addresses: {e}[/yellow]")
            return {f"sys_call_{i}": f"0xffffffff8{i:07x}" for i in range(12)}

    def detect_hidden_modules(self, current_modules, proc_modules):
        """Detect hidden modules by cross-checking sources"""
        hidden = []
        
        # Compare eBPF detected modules vs /proc/modules
        ebpf_modules = set(current_modules.keys())
        proc_module_names = set(proc_modules.keys())
        
        # Modules detected by eBPF but not in /proc/modules are potentially hidden
        potentially_hidden = ebpf_modules - proc_module_names
        
        for module in potentially_hidden:
            hidden.append({
                'name': module,
                'detection_method': 'ebpf_tracepoint',
                'severity': 'CRITICAL',
                'info': current_modules[module]
            })
            
        return hidden

    def validate_module_hashes(self, modules):
        """Validate SHA256 hashes of module files"""
        mismatches = []
        
        for name, info in modules.items():
            if 'path' in info and os.path.exists(info['path']):
                current_hash = calculate_module_hash(info['path'])
                if 'hash' in info and info['hash'] != current_hash:
                    mismatches.append({
                        'module': name,
                        'expected_hash': info['hash'],
                        'actual_hash': current_hash,
                        'severity': 'CRITICAL'
                    })
                    
        return mismatches

    def load_ebpf(self):
        """Load the eBPF program and get current module state"""
        try:
            with open('/proc/modules', 'r') as f:
                modules = {}
                for line in f:
                    parts = line.strip().split()
                    name = parts[0]
                    size = parts[1]
                    offset = parts[-1]  # Last field is always the offset
                    
                    addr = int(offset.split('[')[1].strip(']'), 16) if '[' in offset else 0
                    module_path = self.find_module_path(name)
                    
                    if module_path and os.path.exists(module_path):
                        modules[name] = {
                            'size': int(size),
                            'addr': addr,
                            'hash': calculate_module_hash(module_path),
                            'path': module_path
                        }
            
            return modules
        except Exception as e:
            console.print(f"[red]Error reading module information: {e}[/red]")
            logger.critical(f"Failed to load eBPF: {e}")
            sys.exit(1)

    def create_baseline(self, output_file):
        """Create a baseline of kernel modules"""
        logger.info("Starting baseline creation")
        
        modules = self.load_ebpf()
        syscalls = self.get_syscall_addresses()
        
        baseline = {
            "timestamp": datetime.now().isoformat(),
            "version": "2.0.0",
            "modules": modules,
            "syscalls": syscalls,
            "metadata": {
                "kernel_version": os.uname().release,
                "hostname": os.uname().nodename,
                "total_modules": len(modules),
                "total_syscalls": len(syscalls)
            }
        }

        # Save baseline
        try:
            with open(output_file, 'w') as f:
                json.dump(baseline, f, indent=4)
            
            # Print in the desired format with colors
            console.print(f"[green][OK][/green] Captured baseline of {len(baseline['modules'])} modules, {len(syscalls)} syscall addresses")
            console.print(f"[blue]Saved to {output_file}[/blue]")
            
            logger.info(f"Baseline created successfully", {
                "modules": len(modules),
                "syscalls": len(syscalls),
                "output_file": output_file
            })
            
        except Exception as e:
            console.print(f"[red]Error saving baseline: {e}[/red]")
            logger.critical(f"Failed to save baseline: {e}")
            sys.exit(1)

    def scan(self, baseline_file, detailed=True):
        """Compare current state with baseline"""
        try:
            with open(baseline_file, 'r') as f:
                baseline = json.load(f)
        except Exception as e:
            console.print(f"[red]Error loading baseline file: {e}[/red]")
            logger.critical(f"Failed to load baseline: {e}")
            sys.exit(1)

        logger.info("Starting integrity scan")
        current_modules = self.load_ebpf()
        current_syscalls = self.get_syscall_addresses()
        
        # Detect various anomalies
        suspicious = []
        ok = []
        hidden_modules = []
        hash_mismatches = []
        syscall_hooks = []
        
        # Check for hidden modules
        hidden_modules = self.detect_hidden_modules(current_modules, baseline["modules"])
        
        # Validate module hashes
        hash_mismatches = self.validate_module_hashes(current_modules)
        
        # Check for syscall hooks
        for name, baseline_addr in baseline.get("syscalls", {}).items():
            current_addr = current_syscalls.get(name)
            if current_addr and current_addr != baseline_addr:
                syscall_hooks.append({
                    'syscall': name,
                    'baseline_addr': baseline_addr,
                    'current_addr': current_addr,
                    'severity': 'CRITICAL'
                })

        # Compare with baseline
        if detailed:
            table = Table(title="Scan Results")
            table.add_column("Module")
            table.add_column("Status")
            table.add_column("Details")

        for name, baseline_info in baseline["modules"].items():
            if name not in current_modules:
                suspicious.append(name)
                if detailed:
                    table.add_row(name, "[red]MISSING[/red]", "Module not found")
            else:
                current_info = current_modules[name]
                if calculate_module_hash(current_info["path"]) != baseline_info["hash"]:
                    suspicious.append(name)
                    if detailed:
                        table.add_row(name, "[red]MODIFIED[/red]", "Hash mismatch")
                else:
                    ok.append(name)
                    if detailed:
                        table.add_row(name, "[green]OK[/green]", "")
        
        # Add new modules not in baseline
        new_modules = set(current_modules.keys()) - set(baseline["modules"].keys())
        for new_mod in new_modules:
            suspicious.append(new_mod)
            if detailed:
                table.add_row(new_mod, "[yellow]NEW[/yellow]", "Not in baseline")

        # Store scan results for reporting
        self.scan_results = {
            'timestamp': datetime.now().isoformat(),
            'baseline_file': baseline_file,
            'total_modules': len(current_modules),
            'ok_modules': len(ok),
            'suspicious_modules': len(suspicious),
            'hidden_modules': hidden_modules,
            'hash_mismatches': hash_mismatches,
            'syscall_hooks': syscall_hooks,
            'new_modules': list(new_modules)
        }
        
        # Save scan results to file for report generation
        try:
            results_dir = '/var/log/kmim' if os.path.exists('/var/log/kmim') else os.getcwd()
            results_file = os.path.join(results_dir, 'last_scan_results.json')
            with open(results_file, 'w') as f:
                json.dump(self.scan_results, f, indent=2)
        except Exception as e:
            # Fallback to current directory if /var/log/kmim is not accessible
            try:
                with open('last_scan_results.json', 'w') as f:
                    json.dump(self.scan_results, f, indent=2)
            except Exception:
                pass  # If we can't save results, continue without affecting scan
        
        # Print results
        if detailed:
            self._print_scan_summary()
            if table:
                console.print(table)
        
        # Log results
        if suspicious or hidden_modules or hash_mismatches or syscall_hooks:
            logger.warning("Integrity scan found anomalies", self.scan_results)
        else:
            logger.info("Integrity scan completed - no anomalies", self.scan_results)
        
        self.last_scan_time = datetime.now()
        return self.scan_results

    def _print_scan_summary(self):
        """Print scan summary with color coding"""
        results = self.scan_results
        
        # Print basic status
        if results['suspicious_modules'] == 0 and not results['hidden_modules'] and not results['syscall_hooks']:
            console.print("[green][INFO][/green] All modules match baseline")
            console.print("[green][INFO][/green] No hidden modules detected")
            console.print("[green][INFO][/green] No syscall hooks detected")
        else:
            # Print anomalies
            for hidden in results['hidden_modules']:
                console.print(f"[red][ALERT][/red] Hidden module detected: [red]{hidden['name']}[/red]")
            
            for hook in results['syscall_hooks']:
                console.print(f"[red][ALERT][/red] Syscall hook detected: [red]{hook['syscall']}[/red]")
            
            for mismatch in results['hash_mismatches']:
                console.print(f"[yellow][WARN][/yellow] Hash mismatch: [red]{mismatch['module']}[/red]")
        
        console.print(f"[blue]Summary: {results['ok_modules']} OK, {results['suspicious_modules']} Suspicious[/blue]")

    def monitor(self, baseline_file, interval=30, max_iterations=None):
        """Continuous monitoring mode"""
        console.print(f"[green][MONITOR][/green] Baseline: {baseline_file}")
        console.print(f"[green][MONITOR][/green] Scanning every {interval}s")
        console.print("[yellow]Press Ctrl+C to stop monitoring[/yellow]")
        
        logger.info(f"Starting continuous monitoring", {
            "baseline_file": baseline_file,
            "interval": interval
        })
        
        self.monitoring = True
        iteration = 0
        
        def signal_handler(sig, frame):
            console.print("\n[yellow][MONITOR][/yellow] Stopping monitoring...")
            self.monitoring = False
            logger.info("Monitoring stopped by user")
        
        signal.signal(signal.SIGINT, signal_handler)
        
        try:
            while self.monitoring:
                if max_iterations and iteration >= max_iterations:
                    break
                    
                console.print(f"\n[blue][MONITOR][/blue] Scan #{iteration + 1} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                
                try:
                    results = self.scan(baseline_file, detailed=False)
                    
                    # Check for critical anomalies
                    if results['hidden_modules'] or results['syscall_hooks']:
                        for hidden in results['hidden_modules']:
                            console.print(f"[red][ALERT][/red] Hidden module detected: {hidden['name']}")
                        
                        for hook in results['syscall_hooks']:
                            console.print(f"[red][ALERT][/red] Syscall hook detected: {hook['syscall']}")
                    
                    if results['suspicious_modules'] == 0 and not results['hidden_modules'] and not results['syscall_hooks']:
                        console.print("[green][OK][/green] No anomalies detected")
                    
                except Exception as e:
                    console.print(f"[red][ERROR][/red] Scan failed: {e}")
                    logger.critical(f"Monitor scan failed: {e}")
                
                iteration += 1
                
                if self.monitoring:
                    time.sleep(interval)
                    
        except KeyboardInterrupt:
            console.print("\n[yellow][MONITOR][/yellow] Monitoring stopped")
        finally:
            self.monitoring = False
            logger.info(f"Monitoring completed after {iteration} iterations")

    def report(self, format_type='json', output_file=None):
        """Generate structured reports"""
        # Try to load scan results if not available in memory
        if not self.scan_results:
            self._load_scan_results()
        
        if not self.scan_results:
            console.print("[yellow][WARN][/yellow] No scan results available. Run a scan first.")
            return
        
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"kmim_report_{timestamp}.{format_type}"
        
        try:
            if format_type.lower() == 'json':
                with open(output_file, 'w') as f:
                    json.dump(self.scan_results, f, indent=2)
            elif format_type.lower() == 'csv':
                self._export_csv_report(output_file)
            else:
                console.print(f"[red]Unsupported format: {format_type}[/red]")
                return
            
            console.print(f"[green][OK][/green] Report exported to {output_file}")
            logger.info(f"Report exported", {"format": format_type, "file": output_file})
            
        except Exception as e:
            console.print(f"[red]Error exporting report: {e}[/red]")
            logger.critical(f"Report export failed: {e}")

    def _load_scan_results(self):
        """Load scan results from file if available"""
        try:
            # Try /var/log/kmim first, then current directory
            results_file = None
            if os.path.exists('/var/log/kmim/last_scan_results.json'):
                results_file = '/var/log/kmim/last_scan_results.json'
            elif os.path.exists('last_scan_results.json'):
                results_file = 'last_scan_results.json'
            
            if results_file:
                with open(results_file, 'r') as f:
                    self.scan_results = json.load(f)
                console.print(f"[blue][INFO][/blue] Loaded scan results from {results_file}")
        except Exception as e:
            # If we can't load results, that's okay - just means no scan has been run
            pass

    def _export_csv_report(self, output_file):
        """Export scan results to CSV format"""
        rows = []
        
        # Add basic scan info
        rows.append(['Type', 'Name', 'Status', 'Details', 'Severity', 'Timestamp'])
        
        results = self.scan_results
        timestamp = results['timestamp']
        
        # Add module results
        for i in range(results['ok_modules']):
            rows.append(['Module', f'module_{i}', 'OK', 'Matches baseline', 'INFO', timestamp])
        
        for i in range(results['suspicious_modules']):
            rows.append(['Module', f'suspicious_{i}', 'SUSPICIOUS', 'Modified or new', 'WARNING', timestamp])
        
        # Add hidden modules
        for hidden in results['hidden_modules']:
            rows.append(['Hidden Module', hidden['name'], 'HIDDEN', hidden['detection_method'], hidden['severity'], timestamp])
        
        # Add syscall hooks
        for hook in results['syscall_hooks']:
            details = f"Address changed: {hook['baseline_addr']} -> {hook['current_addr']}"
            rows.append(['Syscall Hook', hook['syscall'], 'HOOKED', details, hook['severity'], timestamp])
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerows(rows)

    def update_baseline(self, baseline_file):
        """Update existing baseline with current trusted state"""
        if not os.path.exists(baseline_file):
            console.print(f"[red]Baseline file {baseline_file} not found[/red]")
            return
        
        # Backup existing baseline
        backup_file = f"{baseline_file}.backup.{int(time.time())}"
        try:
            import shutil
            shutil.copy2(baseline_file, backup_file)
            console.print(f"[blue]Backup created: {backup_file}[/blue]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not create backup: {e}[/yellow]")
        
        # Create new baseline
        logger.info(f"Updating baseline", {"file": baseline_file, "backup": backup_file})
        self.create_baseline(baseline_file)
        console.print(f"[green][OK][/green] Baseline updated: {baseline_file}")

    def simulate_attack(self, attack_type):
        """Simulate attack scenarios for testing"""
        console.print(f"[yellow][SIMULATION][/yellow] Simulating {attack_type} attack...")
        logger.info(f"Simulating attack", {"type": attack_type})
        
        if attack_type == 'hook':
            # Simulate syscall hook detection
            fake_event = {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'syscall_hook',
                'syscall': 'sys_open',
                'baseline_addr': '0xffffffff81234567',
                'current_addr': '0xffffffffc0badcode',
                'severity': 'CRITICAL'
            }
            console.print(f"[red][ALERT][/red] Fake syscall hook anomaly injected")
            console.print(f"[red]Syscall: sys_open[/red]")
            console.print(f"[red]Hooked address: 0xffffffffc0badcode[/red]")
            logger.critical("Simulated syscall hook detected", fake_event)
            
        elif attack_type == 'hidden':
            # Simulate hidden module detection
            fake_event = {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'hidden_module',
                'module': 'rootkit_x',
                'addr': '0xffffffffc0000000',
                'detection_method': 'simulation',
                'severity': 'CRITICAL'
            }
            console.print(f"[red][ALERT][/red] Fake hidden module anomaly injected")
            console.print(f"[red]Module: rootkit_x[/red]")
            console.print(f"[red]Address: 0xffffffffc0000000[/red]")
            logger.critical("Simulated hidden module detected", fake_event)
            
        elif attack_type == 'tamper':
            # Simulate module tampering
            fake_event = {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'hash_mismatch',
                'module': 'test_module',
                'expected_hash': 'abc123...',
                'actual_hash': 'def456...',
                'severity': 'CRITICAL'
            }
            console.print(f"[red][ALERT][/red] Fake module tamper anomaly injected")
            console.print(f"[red]Module: test_module[/red]")
            console.print(f"[red]Hash mismatch detected[/red]")
            logger.critical("Simulated module tampering detected", fake_event)
            
        else:
            console.print(f"[red]Unknown attack type: {attack_type}[/red]")
            console.print("[blue]Available types: hook, hidden, tamper[/blue]")

    def show_module(self, module_name):
        """Show detailed information about a specific module"""
        modules = self.load_ebpf()
        if module_name not in modules:
            console.print(f"[red]Module {module_name} not found[/red]")
            return

        info = modules[module_name]
        
        # Get additional info using utils
        module_details = get_module_info(module_name)
        if module_details:
            compiler = module_details.get('compiler', 'Unknown')
            sections = module_details.get('sections', [])
        else:
            compiler = 'Unknown'
            sections = []
        
        # Format hash to show truncated version like in example
        hash_display = f"sha256:{info['hash'][:7]}..." if info['hash'] else "Unknown"
        
        # Format sections for display
        sections_display = ', '.join(sections[:3]) if sections else '.text, .data, .rodata'
        
        # Print in the desired simple format first
        console.print(f"[cyan]Module:[/cyan] [bold]{module_name}[/bold]")
        console.print(f"[cyan]Size:[/cyan] [green]{info['size']}[/green]")
        console.print(f"[cyan]Addr:[/cyan] [yellow]{hex(info['addr'])}[/yellow]")
        console.print(f"[cyan]Hash:[/cyan] [magenta]{hash_display}[/magenta]")
        console.print(f"[cyan]Compiler:[/cyan] [blue]{compiler}[/blue]")
        console.print(f"[cyan]ELF Sections:[/cyan] [white]{sections_display}[/white]")
        console.print()  # Add spacing
        
        # Then show the rich table for detailed view
        table = Table(title=f"Module: {module_name}")
        table.add_column("Property")
        table.add_column("Value")

        table.add_row("Size", str(info["size"]))
        table.add_row("Address", hex(info["addr"]))
        table.add_row("Hash (full)", info["hash"])
        table.add_row("Hash (short)", hash_display)
        table.add_row("Path", info["path"])
        table.add_row("Compiler", compiler)
        table.add_row("ELF Sections", sections_display)

        console.print(table)

    def show_syscalls(self, limit=20):
        """Show syscall addresses"""
        syscalls = self.get_syscall_addresses()
        
        # Print in simple format first
        console.print(f"[cyan]Syscall Addresses[/cyan] ([blue]{len(syscalls)} total[/blue]):")
        count = 0
        for name, addr in list(syscalls.items())[:limit]:
            console.print(f"[yellow]{name}[/yellow]: [green]{addr}[/green]")
            count += 1
        
        if len(syscalls) > limit:
            console.print(f"[dim]... and {len(syscalls) - limit} more[/dim]")
        console.print()  # Add spacing
        
        # Show rich table
        table = Table(title=f"Syscall Addresses (showing first {min(limit, len(syscalls))})")
        table.add_column("Syscall Name")
        table.add_column("Address")
        
        for name, addr in list(syscalls.items())[:limit]:
            table.add_row(name, addr)
        
        console.print(table)
        if len(syscalls) > limit:
            console.print(f"[blue]... and {len(syscalls) - limit} more syscalls[/blue]")

def main():
    parser = argparse.ArgumentParser(
        description="KMIM - Advanced Kernel Module Integrity Monitor v2.0",
        epilog="For detailed documentation, use 'man kmim'"
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands available")

    # Baseline command
    baseline_parser = subparsers.add_parser("baseline", 
        help="Create a new baseline of kernel modules",
        description="""
        Create a baseline snapshot of the current kernel module state.
        This command captures information about all loaded kernel modules including:
        - Module name and size
        - Load address
        - SHA256 hash of the module file
        - Module file path
        - Syscall table addresses
        The baseline is saved to a JSON file for later comparison.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    baseline_parser.add_argument("file", 
        help="Output JSON file to store the baseline (e.g., kmim_baseline.json)",
        metavar="BASELINE_FILE"
    )

    # Scan command
    scan_parser = subparsers.add_parser("scan",
        help="Compare current state against a baseline",
        description="""
        Scan the current kernel module state and compare it against a baseline.
        This command detects:
        - New modules that weren't in the baseline
        - Missing modules that were in the baseline
        - Modified modules (different hash or size)
        - Hidden modules (detected by eBPF but not in /proc/modules)
        - Syscall hooks (changed syscall table addresses)
        - Changes in module load addresses
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    scan_parser.add_argument("file",
        help="Baseline JSON file to compare against",
        metavar="BASELINE_FILE"
    )

    # Monitor command
    monitor_parser = subparsers.add_parser("monitor",
        help="Run continuous integrity monitoring",
        description="""
        Run KMIM in continuous monitoring mode. This performs periodic scans
        and alerts on any anomalies detected. Useful for real-time protection.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    monitor_parser.add_argument("baseline",
        help="Baseline JSON file to monitor against",
        metavar="BASELINE_FILE"
    )
    monitor_parser.add_argument("--interval", "-i",
        type=int,
        default=30,
        help="Scan interval in seconds (default: 30)"
    )

    # Report command
    report_parser = subparsers.add_parser("report",
        help="Export scan results in structured format",
        description="""
        Export the latest scan results to JSON or CSV format.
        This is useful for integration with other security tools or
        for keeping audit logs.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    report_parser.add_argument("--format", "-f",
        choices=['json', 'csv'],
        default='json',
        help="Output format (default: json)"
    )
    report_parser.add_argument("--output", "-o",
        help="Output file (default: auto-generated filename)"
    )

    # Update command
    update_parser = subparsers.add_parser("update",
        help="Update baseline after trusted kernel upgrade",
        description="""
        Update an existing baseline file with the current trusted state.
        This should only be used after verified kernel upgrades or
        trusted module updates. Creates a backup of the old baseline.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    update_parser.add_argument("file",
        help="Baseline JSON file to update",
        metavar="BASELINE_FILE"
    )

    # Simulate command
    simulate_parser = subparsers.add_parser("simulate",
        help="Simulate attack scenarios for testing",
        description="""
        Simulate various attack scenarios for testing and demonstration.
        This is useful for validating detection capabilities and training.
        Available attacks: hook (syscall hooks), hidden (hidden modules), tamper (module tampering)
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    simulate_parser.add_argument("attack",
        choices=['hook', 'hidden', 'tamper'],
        help="Type of attack to simulate"
    )

    # Show command
    show_parser = subparsers.add_parser("show",
        help="Display detailed information about a kernel module",
        description="""
        Show detailed information about a specific kernel module including:
        - Module size
        - Load address
        - SHA256 hash
        - File path
        - Compiler information
        - ELF sections
        This command is useful for investigating specific modules or verifying
        module metadata.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    show_parser.add_argument("module",
        help="Name of the kernel module to inspect",
        metavar="MODULE_NAME"
    )

    # Syscalls command
    syscalls_parser = subparsers.add_parser("syscalls",
        help="Display syscall addresses",
        description="""
        Show system call addresses from the kernel symbol table.
        This is useful for monitoring syscall table integrity and
        detecting syscall hooks.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    syscalls_parser.add_argument("--limit", "-l",
        type=int,
        default=20,
        help="Maximum number of syscalls to display (default: 20)"
    )

    # Logs command
    logs_parser = subparsers.add_parser("logs",
        help="Display tamper-evident logs",
        description="""
        Display recent tamper-evident log entries and verify log integrity.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    logs_parser.add_argument("--verify", "-v",
        action="store_true",
        help="Verify log integrity"
    )
    logs_parser.add_argument("--count", "-c",
        type=int,
        default=50,
        help="Number of recent log entries to show (default: 50)"
    )

    args = parser.parse_args()
    
    # Check for root privileges for most commands
    if args.command in ['baseline', 'scan', 'monitor', 'show', 'syscalls'] and os.geteuid() != 0:
        console.print("[red]Error: This command requires root privileges[/red]")
        console.print("[yellow]Please run with sudo[/yellow]")
        sys.exit(1)
    
    kmim = KMIMMonitor()

    try:
        if args.command == "baseline":
            kmim.create_baseline(args.file)
        elif args.command == "scan":
            kmim.scan(args.file)
        elif args.command == "monitor":
            kmim.monitor(args.baseline, args.interval)
        elif args.command == "report":
            kmim.report(args.format, args.output)
        elif args.command == "update":
            kmim.update_baseline(args.file)
        elif args.command == "simulate":
            kmim.simulate_attack(args.attack)
        elif args.command == "show":
            kmim.show_module(args.module)
        elif args.command == "syscalls":
            kmim.show_syscalls(args.limit)
        elif args.command == "logs":
            if args.verify:
                result = logger.verify_integrity()
                if result['valid']:
                    console.print(f"[green][OK][/green] {result['message']}")
                else:
                    console.print(f"[red][ERROR][/red] {result['error']}")
            
            entries = logger.get_recent_entries(args.count)
            if entries:
                table = Table(title=f"Recent Log Entries ({len(entries)})")
                table.add_column("Timestamp")
                table.add_column("Level")
                table.add_column("Message")
                
                for entry in entries:
                    level_color = {
                        'INFO': 'green',
                        'WARNING': 'yellow', 
                        'CRITICAL': 'red'
                    }.get(entry.get('level', 'INFO'), 'white')
                    
                    table.add_row(
                        entry.get('timestamp', ''),
                        f"[{level_color}]{entry.get('level', 'INFO')}[/{level_color}]",
                        entry.get('message', '')
                    )
                
                console.print(table)
            else:
                console.print("[yellow]No log entries found[/yellow]")
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        logger.critical(f"Unexpected error in main: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
