"""
Export layer for saving analysis results to various formats.

This module contains the LogExporter class which handles
exporting parsed data to JSON and other formats.
"""

import json
from typing import Optional

from poloa.analyzers import LogAnalyzer


class LogExporter:
    """Exporter for PostgreSQL log analysis results"""

    def __init__(self, analyzer: LogAnalyzer):
        """
        Initialize exporter with an analyzer.

        Args:
            analyzer: LogAnalyzer instance with parsed data
        """
        self.analyzer = analyzer

    def export_to_json(self, output_file: str, include_all: bool = False, slow_query_threshold: float = 5000.0):
        """
        Export parsed data to JSON file.

        If include_all=True, exports all entries; otherwise exports summary only.

        Args:
            output_file: Path to output JSON file
            include_all: If True, export all log entries
            slow_query_threshold: Threshold for slow query analysis (in ms)
        """
        if include_all:
            data = {
                'stats': {
                    'total_lines': self.analyzer.stats['total_lines'],
                    'parsed_lines': self.analyzer.stats['parsed_lines'],
                    'unparsed_lines': self.analyzer.stats['unparsed_lines'],
                    'level_counts': dict(self.analyzer.stats['level_counts']),
                    'database_counts': dict(self.analyzer.stats['database_counts']),
                    'user_counts': dict(self.analyzer.stats['user_counts']),
                    'ip_counts': dict(self.analyzer.stats['ip_counts']),
                },
                'entries': [e.to_dict() for e in self.analyzer.entries]
            }
        else:
            data = {
                'stats': {
                    'total_lines': self.analyzer.stats['total_lines'],
                    'parsed_lines': self.analyzer.stats['parsed_lines'],
                    'unparsed_lines': self.analyzer.stats['unparsed_lines'],
                    'level_counts': dict(self.analyzer.stats['level_counts']),
                    'database_counts': dict(self.analyzer.stats['database_counts']),
                    'user_counts': dict(self.analyzer.stats['user_counts']),
                    'ip_counts': dict(self.analyzer.stats['ip_counts']),
                },
                'errors': [e.to_dict() for e in self.analyzer.get_errors()],
                'slow_queries': [
                    {'duration_ms': duration, 'entry': entry.to_dict(), 'parameters': parameters}
                    for duration, entry, parameters in self.analyzer.get_slow_queries(slow_query_threshold)
                ],
                'connection_issues_count': len(self.analyzer.get_connection_issues()),
                'checkpoints_count': len(self.analyzer.get_checkpoint_info()),
                'vacuums_count': len(self.analyzer.get_vacuum_info()),
                'deadlocks': [dl.to_dict() for dl in self.analyzer.get_deadlocks()],
            }

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"Exported to {output_file}")

    def export_to_csv(self, output_file: str):
        """
        Export parsed data to CSV file (future implementation).

        Args:
            output_file: Path to output CSV file
        """
        # TODO: Implement CSV export
        raise NotImplementedError("CSV export not yet implemented")

    def export_to_html(self, output_file: str):
        """
        Export parsed data to HTML file (future implementation).

        Args:
            output_file: Path to output HTML file
        """
        # TODO: Implement HTML export
        raise NotImplementedError("HTML export not yet implemented")
