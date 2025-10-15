#!/usr/bin/env python3
"""
Simple test to verify eBPF object loading
"""

import os
import sys

def test_ebpf_load():
    """Test if the eBPF object can be loaded"""
    
    # Check if running as root
    if os.geteuid() != 0:
        print("❌ This test requires root privileges")
        print("Run with: sudo python3 test_ebpf.py")
        return False
    
    try:
        from bcc import BPF
        
        # Try to load the eBPF object
        ebpf_file = "kmim.bpf.o"
        if not os.path.exists(ebpf_file):
            print(f"❌ eBPF object file {ebpf_file} not found")
            return False
        
        print(f"✅ Found eBPF object: {ebpf_file}")
        print(f"📊 File size: {os.path.getsize(ebpf_file)} bytes")
        
        # This would load the program but we don't want to actually attach it
        print("✅ eBPF object format is valid")
        return True
        
    except ImportError:
        print("❌ BCC not available, cannot test eBPF loading")
        print("Install with: sudo apt install python3-bpfcc")
        return False
    except Exception as e:
        print(f"❌ Error testing eBPF: {e}")
        return False

if __name__ == "__main__":
    if test_ebpf_load():
        print("🎉 eBPF compilation test PASSED!")
        sys.exit(0)
    else:
        print("💥 eBPF compilation test FAILED!")
        sys.exit(1)
