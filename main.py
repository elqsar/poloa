#!/usr/bin/env python3
"""
POLOA - PostgreSQL Log Analyzer - CLI Application Entry Point

This is the main entry point for the POLOA CLI.
It imports and runs the CLI from the poloa package.

Usage:
    python3 main.py <log_file> [options]

For more information, run:
    python3 main.py --help
"""

from poloa.cli import main

if __name__ == '__main__':
    main()
