# POLOA - PostgreSQL Log Analyzer

A powerful CLI tool for parsing and analyzing PostgreSQL log files with beautiful terminal visualizations.

## Features

- ✨ **Beautiful Visualizations** - Rich terminal UI with color-coded tables, panels, and formatted output
- 📊 **Comprehensive Statistics** - Parse rates, log level distributions, top databases, users, and IPs
- ❌ **Error Detection** - Identify and highlight errors and fatal messages
- 🐌 **Slow Query Analysis** - Find queries exceeding configurable thresholds
- 🔌 **Connection Issues** - Track SSL errors, connection resets, and startup packet issues
- 🔒 **Deadlock Detection** - Detailed deadlock event analysis with process and query information
- 🚨 **Security Alerts** - Identify suspicious IPs with excessive connection failures
- ⚠️ **Constraint Violations** - Detect database constraint violations
- 💾 **Checkpoint & Vacuum Tracking** - Monitor database maintenance operations
- 📤 **Multiple Export Formats** - Export analysis results to JSON or CSV for further processing

## Installation

### Prerequisites
Install [uv](https://docs.astral.sh/uv/) if you haven't already:
```bash
# On macOS and Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# On Windows
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### From Source (Development)
```bash
# Clone the repository and install dependencies with uv
uv sync

# This creates a virtual environment and installs all dependencies
# including development tools (pytest, black, mypy, etc.)
```

### Running the Tool
After installation with uv, you can run the tool using:
```bash
# Using uv run (recommended)
uv run poloa <log_file>

# Or activate the virtual environment
source .venv/bin/activate  # On macOS/Linux
# .venv\Scripts\activate   # On Windows
poloa <log_file>

# Or use the entry script directly (backward compatible)
python3 main.py <log_file>
```

### Installing as a Package
```bash
# Install the package in production mode (without dev dependencies)
uv sync --no-dev

# Or install the package globally
uv pip install .
```

## Usage

### Basic usage
```bash
uv run poloa postgresql.log.2025-11-14-11
# Or using the legacy entry point:
# python3 main.py postgresql.log.2025-11-14-11
```

### With custom options
```bash
uv run poloa postgresql.log.2025-11-14-11 -o report.json -t 10000 -s 100
```

### Export to CSV format
```bash
# Export summary to CSV
uv run poloa postgresql.log.2025-11-14-11 --format csv

# Export to custom CSV file
uv run poloa postgresql.log.2025-11-14-11 -f csv -o my_logs.csv

# Export all entries to CSV (can be large)
uv run poloa postgresql.log.2025-11-14-11 --format csv --export-all
```

### Export all entries to JSON
```bash
uv run poloa postgresql.log.2025-11-14-11 --export-all
```

### Show help
```bash
uv run poloa --help
```

## Options

- `-o, --output` - Output file path (default: log_analysis_summary.json)
- `-f, --format` - Export format: `json` or `csv` (default: json)
- `-t, --slow-query-threshold` - Slow query threshold in milliseconds (default: 3000)
- `-s, --security-threshold` - Connection issue threshold for security alerts (default: 30)
- `-c, --config` - Path to YAML configuration file (optional)
- `--export-all` - Export all log entries (applies to both JSON and CSV formats)

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
2. `~/.poloa/config.yaml` (user home directory)

Or specify a custom path with `-c/--config` option

## Output

The tool provides:
1. **Terminal Visualization** - Beautiful, color-coded summary displayed in your terminal
2. **JSON Export** - Structured data export with statistics, errors, slow queries, and more
3. **CSV Export** - Tabular export of all log entries for spreadsheet analysis or data processing

### Export Formats

#### JSON Format
- **Summary mode** (default): Exports statistics, errors, slow queries, deadlocks, and counts
- **Full mode** (`--export-all`): Exports all parsed log entries plus statistics
- Best for: Programmatic analysis, integration with other tools, detailed investigation

#### CSV Format
- Exports all parsed log entries as a table with columns: timestamp, timezone, ip, port, user, database, pid, level, message
- Best for: Spreadsheet analysis, data visualization tools, simple filtering and sorting

## Project Structure

```
poloa/
├── poloa/                      # Main package directory
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
├── pyproject.toml              # Package configuration
├── tests/                      # Test directory
└── readme.md                   # This file
```

### Architecture Benefits

- **Modularity**: Each file has a single, clear responsibility
- **Extensibility**: Easy to add new analyzers or export formats
- **Testability**: Isolated components are easier to unit test
- **Configuration**: YAML config for customization without code changes