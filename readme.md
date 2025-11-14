# PostgreSQL Log Parser

A powerful CLI tool for parsing and analyzing PostgreSQL log files with beautiful terminal visualizations.

## Features

✨ **Beautiful Visualizations** - Rich terminal UI with color-coded tables, panels, and formatted output
📊 **Comprehensive Statistics** - Parse rates, log level distributions, top databases, users, and IPs
❌ **Error Detection** - Identify and highlight errors and fatal messages
🐌 **Slow Query Analysis** - Find queries exceeding configurable thresholds
🔌 **Connection Issues** - Track SSL errors, connection resets, and startup packet issues
🔒 **Deadlock Detection** - Detailed deadlock event analysis with process and query information
🚨 **Security Alerts** - Identify suspicious IPs with excessive connection failures
⚠️  **Constraint Violations** - Detect database constraint violations
💾 **Checkpoint & Vacuum Tracking** - Monitor database maintenance operations

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Basic usage
```bash
python3 main.py postgresql.log.2025-11-14-11
```

### With custom options
```bash
python3 main.py postgresql.log.2025-11-14-11 -o report.json -t 10000 -s 100
```

### Export all entries
```bash
python3 main.py postgresql.log.2025-11-14-11 --export-all
```

### Show help
```bash
python3 main.py --help
```

## Options

- `-o, --output` - Output JSON file path (default: log_analysis_summary.json)
- `-t, --slow-query-threshold` - Slow query threshold in milliseconds (default: 5000)
- `-s, --security-threshold` - Connection issue threshold for security alerts (default: 50)
- `--export-all` - Export all log entries to JSON (can be large)

## Output

The tool provides:
1. **Terminal Visualization** - Beautiful, color-coded summary displayed in your terminal
2. **JSON Export** - Structured data export for further analysis or integration