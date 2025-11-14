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

### From Source (Development)
```bash
# Clone the repository and install dependencies
pip install -r requirements.txt

# Or install in development mode
pip install -e .
```

### As a Package
```bash
# Install the package
pip install .

# Install with YAML configuration support
pip install ".[config]"

# Install with development dependencies
pip install ".[dev]"
```

After installation, you can use either:
- `python3 main.py <log_file>` (backward compatible)
- `postg-parser <log_file>` (if installed as package)

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
- `-t, --slow-query-threshold` - Slow query threshold in milliseconds (default: 3000)
- `-s, --security-threshold` - Connection issue threshold for security alerts (default: 30)
- `-c, --config` - Path to YAML configuration file (optional)
- `--export-all` - Export all log entries to JSON (can be large)

## Configuration File

You can create a `config.yaml` file to set default values for all options. CLI arguments will override config file values.

Example `config.yaml`:
```yaml
thresholds:
  slow_query_ms: 3000.0
  security_connection_failures: 30

display:
  color_scheme: "default"
  show_emojis: true
  max_items_per_table: 10

export:
  default_format: "json"
  include_all_entries: false
```

The tool will automatically search for config files in:
1. `./config.yaml` (current directory)
2. `~/.postg/config.yaml` (user home directory)

Or specify a custom path with `-c/--config` option

## Output

The tool provides:
1. **Terminal Visualization** - Beautiful, color-coded summary displayed in your terminal
2. **JSON Export** - Structured data export for further analysis or integration

## Project Structure

The project has been refactored into a modular package structure for better maintainability and extensibility:

```
postg/
├── postg/                      # Main package directory
│   ├── __init__.py            # Package initialization
│   ├── models.py              # Data models (LogEntry, DeadlockInfo, Config)
│   ├── parser.py              # Core parsing logic
│   ├── analyzers.py           # Analysis methods (errors, slow queries, etc.)
│   ├── visualizer.py          # Rich terminal UI components
│   ├── exporter.py            # JSON export functionality
│   ├── config.py              # Configuration management
│   └── cli.py                 # Click CLI interface
├── main.py                     # Entry point (backward compatible)
├── config.yaml                 # Default configuration file
├── setup.py                    # Package installation configuration
├── requirements.txt            # Production dependencies
├── requirements-dev.txt        # Development dependencies
├── tests/                      # Test directory
└── README.md                   # This file
```

### Architecture Benefits

- **Modularity**: Each file has a single, clear responsibility
- **Extensibility**: Easy to add new analyzers or export formats
- **Testability**: Isolated components are easier to unit test
- **Configuration**: YAML config for customization without code changes
- **Backward Compatible**: Existing CLI usage works identically
- **Professional Structure**: Standard Python package layout