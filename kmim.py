#!/usr/bin/env python3
"""
KMIM - Kernel Module Integrity Monitor
Entry point script to avoid module import warnings.
"""

import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run the main function
from cli.kmim import main

if __name__ == "__main__":
    main()
