#!/usr/bin/env python3
"""
PostgreSQL Log Parser - CLI Application Entry Point

This is the main entry point for the PostgreSQL log parser CLI.
It imports and runs the CLI from the postg package.

Usage:
    python3 main.py <log_file> [options]

For more information, run:
    python3 main.py --help
"""

from postg.cli import main

if __name__ == '__main__':
    main()
