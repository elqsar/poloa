"""
Analysis layer for parsed PostgreSQL log data.

This module contains the LogAnalyzer class which provides various
analysis methods for examining parsed log entries.
"""

import re
from typing import List, Tuple, Optional

from poloa.models import LogEntry, DeadlockInfo


class LogAnalyzer:
    """Analyzer for parsed PostgreSQL log entries"""

    def __init__(self, parser):
        """
        Initialize analyzer with a parsed log file.

        Args:
            parser: PostgreSQLLogParser instance with parsed entries
        """
        self.parser = parser
        self.entries = parser.entries
        self.stats = parser.stats
        self.filepath = parser.filepath

    def get_errors(self) -> List[LogEntry]:
        """Get all ERROR and FATAL level entries"""
        return [e for e in self.entries if e.level in ('ERROR', 'FATAL')]

    def get_slow_queries(self, threshold_ms: float = 3000.0) -> List[Tuple[float, LogEntry, Optional[str]]]:
        """
        Extract queries that took longer than threshold_ms milliseconds.

        Returns list of (duration, LogEntry, parameters) tuples sorted by duration descending.
        Parameters are extracted from the DETAIL line following the query if available.

        Args:
            threshold_ms: Minimum query duration in milliseconds

        Returns:
            List of tuples containing (duration, log_entry, parameters)
        """
        slow_queries = []
        duration_pattern = re.compile(r'duration:\s*([\d.]+)\s*ms')

        # Read file again to get continuation lines
        with open(self.filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        for i, entry in enumerate(self.entries):
            if 'duration:' in entry.message:
                match = duration_pattern.search(entry.message)
                if match:
                    duration = float(match.group(1))
                    if duration >= threshold_ms:
                        # Try to find the DETAIL line with parameters
                        parameters = None
                        # Find the line index in the original file
                        for line_idx, line in enumerate(lines):
                            if entry.raw_line in line:
                                # Check next line for DETAIL with parameters
                                if line_idx + 1 < len(lines):
                                    next_line = lines[line_idx + 1].strip()
                                    if 'DETAIL:  parameters:' in next_line:
                                        # Extract parameters from DETAIL line
                                        param_start = next_line.find('parameters:')
                                        if param_start != -1:
                                            parameters = next_line[param_start + 11:].strip()
                                break

                        slow_queries.append((duration, entry, parameters))

        # Sort by duration descending
        slow_queries.sort(key=lambda x: x[0], reverse=True)
        return slow_queries

    def get_connection_issues(self) -> List[LogEntry]:
        """Get entries related to connection problems"""
        connection_keywords = [
            'could not receive data from client',
            'could not accept SSL connection',
            'invalid length of startup packet',
            'Connection reset by peer',
            'unsupported frontend protocol'
        ]

        return [
            e for e in self.entries
            if any(keyword in e.message for keyword in connection_keywords)
        ]

    def get_checkpoint_info(self) -> List[LogEntry]:
        """Get checkpoint-related log entries"""
        return [
            e for e in self.entries
            if 'checkpoint' in e.message.lower()
        ]

    def get_vacuum_info(self) -> List[LogEntry]:
        """Get autovacuum-related log entries"""
        return [
            e for e in self.entries
            if 'vacuum' in e.message.lower()
        ]

    def get_deadlocks(self) -> List[DeadlockInfo]:
        """
        Extract deadlock events from the log.

        Deadlocks span multiple lines with DETAIL, HINT, CONTEXT, and STATEMENT sections.

        Returns:
            List of DeadlockInfo objects
        """
        deadlocks = []

        for i, entry in enumerate(self.entries):
            # Look for deadlock detection message
            if entry.level == 'ERROR' and 'deadlock detected' in entry.message.lower():
                # Initialize deadlock info
                process1_pid = ''
                process2_pid = ''
                process1_query = ''
                process2_query = ''
                lock_info = ''
                context = None

                # Look ahead for DETAIL, HINT, CONTEXT, and STATEMENT lines
                j = i + 1
                while j < len(self.entries) and j < i + 10:  # Look at next 10 entries max
                    next_entry = self.entries[j]

                    # Stop if we hit a different PID or timestamp (new log entry)
                    if next_entry.pid != entry.pid or next_entry.timestamp != entry.timestamp:
                        break

                    # Parse DETAIL section for process info and queries
                    if next_entry.level == 'DETAIL':
                        detail_lines = next_entry.message.split('\n')
                        for line in detail_lines:
                            # Extract process PIDs and lock info
                            if 'Process' in line and 'waits for' in line:
                                match = re.search(r'Process (\d+) waits for', line)
                                if match and not process1_pid:
                                    process1_pid = match.group(1)
                                    lock_info = line.strip()
                                elif match and not process2_pid:
                                    process2_pid = match.group(1)
                                    lock_info += '\n' + line.strip()
                            # Extract queries for each process
                            elif line.strip().startswith('Process') and ':' in line:
                                match = re.search(r'Process (\d+):\s*(.+)', line)
                                if match:
                                    pid = match.group(1)
                                    query = match.group(2).strip()
                                    if pid == process1_pid:
                                        process1_query = query
                                    elif pid == process2_pid:
                                        process2_query = query

                    # Parse CONTEXT section
                    elif next_entry.level == 'CONTEXT':
                        context = next_entry.message.strip()

                    j += 1

                # Create deadlock info object
                deadlock = DeadlockInfo(
                    timestamp=entry.timestamp,
                    database=entry.database or 'unknown',
                    process1_pid=process1_pid,
                    process2_pid=process2_pid,
                    process1_query=process1_query,
                    process2_query=process2_query,
                    lock_info=lock_info,
                    context=context
                )
                deadlocks.append(deadlock)

        return deadlocks

    def get_entries_by_ip(self, ip: str) -> List[LogEntry]:
        """Get all entries from a specific IP address"""
        return [e for e in self.entries if e.ip == ip]

    def get_entries_by_database(self, database: str) -> List[LogEntry]:
        """Get all entries for a specific database"""
        return [e for e in self.entries if e.database == database]

    def get_entries_by_level(self, level: str) -> List[LogEntry]:
        """Get all entries of a specific log level"""
        return [e for e in self.entries if e.level == level]

    def get_top_ips(self, n: int = 10) -> List[Tuple[str, int]]:
        """Get top N IP addresses by number of log entries"""
        return self.stats['ip_counts'].most_common(n)

    def get_top_databases(self, n: int = 10) -> List[Tuple[str, int]]:
        """Get top N databases by number of log entries"""
        return self.stats['database_counts'].most_common(n)

    def get_top_users(self, n: int = 10) -> List[Tuple[str, int]]:
        """Get top N users by number of log entries"""
        return self.stats['user_counts'].most_common(n)

    def get_constraint_violations(self) -> List[LogEntry]:
        """Get entries related to constraint violations"""
        return [
            e for e in self.entries
            if e.level == 'ERROR' and any(keyword in e.message.lower() for keyword in [
                'constraint', 'duplicate key', 'foreign key', 'unique constraint'
            ])
        ]
