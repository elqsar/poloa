# Basic usage
python3 main.py postgresql.log.2025-11-14-11

# With custom options
python3 main.py postgresql.log.2025-11-14-11 -o report.json -t 10000 -s 100

# Export all entries
python3 main.py postgresql.log.2025-11-14-11 --export-all

# Show help
python3 main.py --help