"""
Core parsing logic for PostgreSQL log files.

This module contains the PostgreSQLLogParser class responsible for
reading and parsing PostgreSQL log files into structured LogEntry objects.
"""

import re
from collections import Counter
from typing import List, Optional

from postg.models import LogEntry


class PostgreSQLLogParser:
    """Parser for PostgreSQL log files"""

    # Regex pattern for standard PostgreSQL log format
    # Format: YYYY-MM-DD HH:MM:SS TZ:IP(PORT):USER@DATABASE:[PID]:LEVEL:  MESSAGE
    LOG_PATTERN = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
        r'(?P<timezone>\w+):'
        r'(?P<ip>[\d.]+)?\(?(?P<port>\d+)?\)?:'
        r'\[?(?P<user>[^\]@]+)?\]?@'
        r'\[?(?P<database>[^\]]+)?\]?:'
        r'\[(?P<pid>\d+)\]:'
        r'(?P<level>\w+):\s+'
        r'(?P<message>.+)$'
    )

    def __init__(self, filepath: str):
        """Initialize parser with log file path"""
        self.filepath = filepath
        self.entries: List[LogEntry] = []
        self.stats = {
            'total_lines': 0,
            'parsed_lines': 0,
            'unparsed_lines': 0,
            'level_counts': Counter(),
            'database_counts': Counter(),
            'user_counts': Counter(),
            'ip_counts': Counter(),
        }

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single log line into a LogEntry object"""
        match = self.LOG_PATTERN.match(line.strip())
        if match:
            data = match.groupdict()
            return LogEntry(
                timestamp=data['timestamp'],
                timezone=data['timezone'],
                ip=data['ip'],
                port=data['port'],
                user=data['user'],
                database=data['database'],
                pid=data['pid'],
                level=data['level'],
                message=data['message'],
                raw_line=line.strip()
            )
        return None

    def parse_file(self) -> 'PostgreSQLLogParser':
        """Parse the entire log file and link DETAIL lines to their parent entries"""
        print(f"Parsing log file: {self.filepath}")

        with open(self.filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        for line_num, line in enumerate(lines):
            self.stats['total_lines'] += 1

            # Skip empty lines
            if not line.strip():
                continue

            entry = self.parse_line(line)
            if entry:
                self.entries.append(entry)
                self.stats['parsed_lines'] += 1

                # Update statistics
                self.stats['level_counts'][entry.level] += 1
                if entry.database:
                    self.stats['database_counts'][entry.database] += 1
                if entry.user:
                    self.stats['user_counts'][entry.user] += 1
                if entry.ip:
                    self.stats['ip_counts'][entry.ip] += 1
            else:
                self.stats['unparsed_lines'] += 1
                # Likely a continuation line (starts with tab or spaces)
                # Append to the last entry's message if it exists
                if self.entries and (line.startswith('\t') or line.startswith('  ')):
                    self.entries[-1].message += '\n' + line.strip()

        print(f"Parsed {self.stats['parsed_lines']} out of {self.stats['total_lines']} lines")
        return self
