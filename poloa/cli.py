"""
Command-line interface for POLOA - PostgreSQL Log Analyzer.

This module provides the Click-based CLI that orchestrates
the parser, analyzer, visualizer, and exporter components.
"""

import click

from poloa.parser import PostgreSQLLogParser
from poloa.analyzers import LogAnalyzer
from poloa.visualizer import LogVisualizer
from poloa.exporter import LogExporter
from poloa.config import ConfigManager


@click.command()
@click.argument('log_file', type=click.Path(exists=True, readable=True))
@click.option('--output', '-o', default='log_analysis_summary.json',
              help='Output file path (default: log_analysis_summary.json)')
@click.option('--format', '-f', type=click.Choice(['json', 'csv'], case_sensitive=False),
              default='json', help='Export format: json or csv (default: json)')
@click.option('--export-all', is_flag=True,
              help='Export all log entries (applies to JSON and CSV)')
@click.option('--slow-query-threshold', '-t', default=3000.0, type=float,
              help='Slow query threshold in milliseconds (default: 3000)')
@click.option('--security-threshold', '-s', default=30, type=int,
              help='Connection issue threshold for security alerts (default: 30)')
@click.option('--config', '-c', type=click.Path(exists=True, readable=True),
              help='Path to configuration file (YAML)')
def main(log_file, output, format, export_all, slow_query_threshold, security_threshold, config):
    """
    POLOA - PostgreSQL Log Analyzer CLI

    Parse and analyze PostgreSQL log files to extract statistics, errors, and slow queries.

    LOG_FILE: Path to the PostgreSQL log file to parse
    """
    # Load configuration
    config_obj = ConfigManager.load_config(config)

    # Merge CLI args with config (CLI args take precedence)
    config_obj = ConfigManager.merge_cli_args(
        config_obj,
        slow_query_threshold_ms=slow_query_threshold,
        security_threshold=security_threshold,
        include_all_entries=export_all
    )

    # Parse the log file
    parser = PostgreSQLLogParser(log_file)
    parser.parse_file()

    # Create analyzer
    analyzer = LogAnalyzer(parser)

    # Create visualizer and render summary
    visualizer = LogVisualizer(analyzer, config_obj)
    visualizer.render_summary()

    # Create exporter and export based on format
    exporter = LogExporter(analyzer)

    # Determine output file extension if not specified
    if format.lower() == 'csv' and not output.endswith('.csv'):
        # If user didn't specify extension or used default, adjust for CSV
        if output == 'log_analysis_summary.json':
            output = 'log_analysis_summary.csv'

    # Export to the selected format
    if format.lower() == 'csv':
        exporter.export_to_csv(output)
    else:
        exporter.export_to_json(output, include_all=export_all, slow_query_threshold=slow_query_threshold)

    # Render security analysis
    visualizer.render_security_analysis(config_obj.security_threshold)

    # Render constraint violations
    visualizer.render_constraint_violations()


if __name__ == '__main__':
    main()
