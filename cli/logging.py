#!/usr/bin/env python3
"""
Tamper-evident logging system for KMIM
Implements SHA256-chained append-only logging to prevent modification
"""

import hashlib
import json
import time
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path


class TamperEvidentLogger:
    """Tamper-evident logging with SHA256 chaining"""
    
    def __init__(self, log_file: str = "kmim.log"):
        self.log_file = Path(log_file)
        self.last_hash = self._get_last_hash()
        
    def _get_last_hash(self) -> str:
        """Get the hash of the last log entry"""
        if not self.log_file.exists():
            return "0" * 64  # Genesis hash
            
        try:
            with open(self.log_file, 'r') as f:
                lines = f.readlines()
                if lines:
                    last_line = lines[-1].strip()
                    if last_line:
                        entry = json.loads(last_line)
                        return entry.get('hash', "0" * 64)
        except (json.JSONDecodeError, FileNotFoundError, KeyError):
            pass
            
        return "0" * 64
    
    def _calculate_hash(self, entry_data: Dict[str, Any], prev_hash: str) -> str:
        """Calculate SHA256 hash for log entry"""
        # Create deterministic string from entry data
        hash_input = f"{prev_hash}:{entry_data['timestamp']}:{entry_data['level']}:{entry_data['message']}"
        if 'data' in entry_data:
            hash_input += f":{json.dumps(entry_data['data'], sort_keys=True)}"
        
        return hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
    
    def log(self, level: str, message: str, data: Optional[Dict[str, Any]] = None) -> str:
        """Add tamper-evident log entry"""
        timestamp = datetime.utcnow().isoformat() + 'Z'
        
        entry = {
            'timestamp': timestamp,
            'level': level.upper(),
            'message': message,
            'prev_hash': self.last_hash
        }
        
        if data:
            entry['data'] = data
            
        # Calculate hash for this entry
        entry_hash = self._calculate_hash(entry, self.last_hash)
        entry['hash'] = entry_hash
        
        # Append to log file
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(entry, separators=(',', ':')) + '\n')
        
        self.last_hash = entry_hash
        return entry_hash
    
    def info(self, message: str, data: Optional[Dict[str, Any]] = None) -> str:
        """Log info level message"""
        return self.log('INFO', message, data)
    
    def warning(self, message: str, data: Optional[Dict[str, Any]] = None) -> str:
        """Log warning level message"""
        return self.log('WARNING', message, data)
    
    def critical(self, message: str, data: Optional[Dict[str, Any]] = None) -> str:
        """Log critical level message"""
        return self.log('CRITICAL', message, data)
    
    def verify_integrity(self) -> Dict[str, Any]:
        """Verify the integrity of the entire log chain"""
        if not self.log_file.exists():
            return {'valid': True, 'entries': 0, 'message': 'No log file exists'}
        
        entries = []
        expected_hash = "0" * 64  # Genesis hash
        
        try:
            with open(self.log_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                        
                    try:
                        entry = json.loads(line)
                        entries.append(entry)
                        
                        # Verify previous hash
                        if entry.get('prev_hash') != expected_hash:
                            return {
                                'valid': False,
                                'entries': len(entries),
                                'error': f'Hash chain broken at line {line_num}',
                                'expected_prev_hash': expected_hash,
                                'actual_prev_hash': entry.get('prev_hash')
                            }
                        
                        # Verify current hash
                        calculated_hash = self._calculate_hash(entry, expected_hash)
                        if entry.get('hash') != calculated_hash:
                            return {
                                'valid': False,
                                'entries': len(entries),
                                'error': f'Hash mismatch at line {line_num}',
                                'expected_hash': calculated_hash,
                                'actual_hash': entry.get('hash')
                            }
                        
                        expected_hash = entry['hash']
                        
                    except json.JSONDecodeError as e:
                        return {
                            'valid': False,
                            'entries': len(entries),
                            'error': f'JSON decode error at line {line_num}: {e}'
                        }
                        
        except FileNotFoundError:
            return {'valid': True, 'entries': 0, 'message': 'No log file exists'}
        
        return {
            'valid': True,
            'entries': len(entries),
            'message': f'Log integrity verified for {len(entries)} entries'
        }
    
    def get_recent_entries(self, count: int = 100) -> List[Dict[str, Any]]:
        """Get recent log entries"""
        if not self.log_file.exists():
            return []
        
        entries = []
        try:
            with open(self.log_file, 'r') as f:
                lines = f.readlines()
                for line in lines[-count:]:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except FileNotFoundError:
            pass
            
        return entries
    
    def export_logs(self, output_file: str, format_type: str = 'json') -> bool:
        """Export logs in specified format"""
        if not self.log_file.exists():
            return False
        
        entries = []
        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except FileNotFoundError:
            return False
        
        if format_type.lower() == 'json':
            with open(output_file, 'w') as f:
                json.dump(entries, f, indent=2)
        elif format_type.lower() == 'csv':
            import csv
            if entries:
                with open(output_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=entries[0].keys())
                    writer.writeheader()
                    writer.writerows(entries)
        else:
            return False
            
        return True


# Global logger instance
_logger_instance = None

def get_logger(log_file: str = "kmim.log") -> TamperEvidentLogger:
    """Get or create global logger instance"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = TamperEvidentLogger(log_file)
    return _logger_instance


if __name__ == "__main__":
    # Test the tamper-evident logger
    logger = TamperEvidentLogger("test_kmim.log")
    
    # Add some test entries
    logger.info("KMIM started", {"version": "2.0.0", "user": "root"})
    logger.warning("Suspicious module detected", {"module": "test_module", "addr": "0xffffffffc0000000"})
    logger.critical("Hidden module found", {"module": "rootkit_x", "detection": "tracepoint_cross_check"})
    
    # Verify integrity
    result = logger.verify_integrity()
    print(f"Log integrity: {result}")
    
    # Export logs
    logger.export_logs("test_export.json", "json")
    print("Logs exported to test_export.json")
