#!/usr/bin/env python3
"""
PostgreSQL Log Parser - CLI Application
Efficiently parses PostgreSQL log files and extracts useful statistics, errors, and slow queries.
"""

import re
from datetime import datetime
from collections import defaultdict, Counter
from dataclasses import dataclass
from typing import Optional, List, Dict, Tuple
import json
import click


@dataclass
class LogEntry:
    """Represents a single PostgreSQL log entry"""
    timestamp: str
    timezone: str
    ip: Optional[str]
    port: Optional[str]
    user: Optional[str]
    database: Optional[str]
    pid: str
    level: str
    message: str
    raw_line: str

    def to_dict(self) -> dict:
        """Convert log entry to dictionary"""
        return {
            'timestamp': self.timestamp,
            'timezone': self.timezone,
            'ip': self.ip,
            'port': self.port,
            'user': self.user,
            'database': self.database,
            'pid': self.pid,
            'level': self.level,
            'message': self.message
        }


@dataclass
class DeadlockInfo:
    """Represents a deadlock event with involved processes and queries"""
    timestamp: str
    database: str
    process1_pid: str
    process2_pid: str
    process1_query: str
    process2_query: str
    lock_info: str
    context: Optional[str]

    def to_dict(self) -> dict:
        """Convert deadlock info to dictionary"""
        return {
            'timestamp': self.timestamp,
            'database': self.database,
            'process1_pid': self.process1_pid,
            'process2_pid': self.process2_pid,
            'process1_query': self.process1_query,
            'process2_query': self.process2_query,
            'lock_info': self.lock_info,
            'context': self.context
        }


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

    def get_errors(self) -> List[LogEntry]:
        """Get all ERROR and FATAL level entries"""
        return [e for e in self.entries if e.level in ('ERROR', 'FATAL')]

    def get_slow_queries(self, threshold_ms: float = 5000.0) -> List[Tuple[float, LogEntry, Optional[str]]]:
        """
        Extract queries that took longer than threshold_ms milliseconds
        Returns list of (duration, LogEntry, parameters) tuples sorted by duration descending
        Parameters are extracted from the DETAIL line following the query if available
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
        Extract deadlock events from the log
        Deadlocks span multiple lines with DETAIL, HINT, CONTEXT, and STATEMENT sections
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

    def print_summary(self):
        """Print a summary of the parsed log file"""
        print("\n" + "="*80)
        print("PostgreSQL Log Analysis Summary")
        print("="*80)

        print(f"\n📊 Overall Statistics:")
        print(f"  Total lines: {self.stats['total_lines']}")
        print(f"  Parsed entries: {self.stats['parsed_lines']}")
        print(f"  Unparsed lines: {self.stats['unparsed_lines']}")

        print(f"\n📈 Log Levels:")
        for level, count in self.stats['level_counts'].most_common():
            print(f"  {level:15s}: {count:6d}")

        print(f"\n🗄️  Top Databases:")
        for db, count in self.get_top_databases(5):
            print(f"  {db:20s}: {count:6d}")

        print(f"\n👥 Top Users:")
        for user, count in self.stats['user_counts'].most_common(5):
            print(f"  {user:20s}: {count:6d}")

        print(f"\n🌐 Top IP Addresses:")
        for ip, count in self.get_top_ips(5):
            print(f"  {ip:20s}: {count:6d}")

        # Errors
        errors = self.get_errors()
        print(f"\n❌ Errors and Fatals: {len(errors)}")
        if errors:
            print(f"  Showing first 5:")
            for error in errors[:5]:
                print(f"  [{error.timestamp}] {error.level}: {error.message[:80]}...")

        # Slow queries
        slow_queries = self.get_slow_queries(5000)
        print(f"\n🐌 Slow Queries (>5s): {len(slow_queries)}")
        if slow_queries:
            print(f"  Top 10 slowest:")
            for duration, entry, parameters in slow_queries[:10]:
                print(f"  {duration:10.2f}ms - {entry.message}...")
                if parameters:
                    # Truncate parameters if too long
                    if len(parameters) > 150:
                        print(f"    Parameters: {parameters[:150]}...")
                    else:
                        print(f"    Parameters: {parameters}")

        # Connection issues
        conn_issues = self.get_connection_issues()
        print(f"\n🔌 Connection Issues: {len(conn_issues)}")
        if conn_issues:
            # Group by type
            issue_types = Counter()
            for entry in conn_issues:
                if 'SSL connection' in entry.message:
                    issue_types['SSL connection errors'] += 1
                elif 'Connection reset' in entry.message:
                    issue_types['Connection resets'] += 1
                elif 'startup packet' in entry.message:
                    issue_types['Invalid startup packets'] += 1
                else:
                    issue_types['Other connection issues'] += 1

            for issue_type, count in issue_types.most_common():
                print(f"  {issue_type:30s}: {count:6d}")

        # Checkpoints
        checkpoints = self.get_checkpoint_info()
        print(f"\n💾 Checkpoints: {len(checkpoints)}")

        # Vacuums
        vacuums = self.get_vacuum_info()
        print(f"\n🧹 Autovacuum Operations: {len(vacuums)}")

        # Deadlocks
        deadlocks = self.get_deadlocks()
        print(f"\n🔒 Deadlocks Detected: {len(deadlocks)}")
        if deadlocks:
            print(f"  Showing all deadlocks:")
            for i, dl in enumerate(deadlocks, 1):
                print(f"\n  Deadlock #{i} at {dl.timestamp} in database '{dl.database}':")
                print(f"    Process {dl.process1_pid} vs Process {dl.process2_pid}")
                print(f"    Lock Info: {dl.lock_info[:100]}...")
                if dl.process1_query:
                    print(f"    Query 1: {dl.process1_query[:80]}...")
                if dl.process2_query:
                    print(f"    Query 2: {dl.process2_query[:80]}...")

        print("\n" + "="*80)

    def export_to_json(self, output_file: str, include_all: bool = False):
        """
        Export parsed data to JSON file
        If include_all=True, exports all entries; otherwise exports summary only
        """
        if include_all:
            data = {
                'stats': {
                    'total_lines': self.stats['total_lines'],
                    'parsed_lines': self.stats['parsed_lines'],
                    'unparsed_lines': self.stats['unparsed_lines'],
                    'level_counts': dict(self.stats['level_counts']),
                    'database_counts': dict(self.stats['database_counts']),
                    'user_counts': dict(self.stats['user_counts']),
                    'ip_counts': dict(self.stats['ip_counts']),
                },
                'entries': [e.to_dict() for e in self.entries]
            }
        else:
            data = {
                'stats': {
                    'total_lines': self.stats['total_lines'],
                    'parsed_lines': self.stats['parsed_lines'],
                    'unparsed_lines': self.stats['unparsed_lines'],
                    'level_counts': dict(self.stats['level_counts']),
                    'database_counts': dict(self.stats['database_counts']),
                    'user_counts': dict(self.stats['user_counts']),
                    'ip_counts': dict(self.stats['ip_counts']),
                },
                'errors': [e.to_dict() for e in self.get_errors()],
                'slow_queries': [
                    {'duration_ms': duration, 'entry': entry.to_dict(), 'parameters': parameters}
                    for duration, entry, parameters in self.get_slow_queries(5000)
                ],
                'connection_issues_count': len(self.get_connection_issues()),
                'checkpoints_count': len(self.get_checkpoint_info()),
                'vacuums_count': len(self.get_vacuum_info()),
                'deadlocks': [dl.to_dict() for dl in self.get_deadlocks()],
            }

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"Exported to {output_file}")


@click.command()
@click.argument('log_file', type=click.Path(exists=True, readable=True))
@click.option('--output', '-o', default='log_analysis_summary.json',
              help='Output JSON file path (default: log_analysis_summary.json)')
@click.option('--export-all', is_flag=True,
              help='Export all log entries to JSON (can be large)')
@click.option('--slow-query-threshold', '-t', default=5000.0, type=float,
              help='Slow query threshold in milliseconds (default: 5000)')
@click.option('--security-threshold', '-s', default=50, type=int,
              help='Connection issue threshold for security alerts (default: 50)')
def main(log_file, output, export_all, slow_query_threshold, security_threshold):
    """
    PostgreSQL Log Parser CLI

    Parse and analyze PostgreSQL log files to extract statistics, errors, and slow queries.

    LOG_FILE: Path to the PostgreSQL log file to parse
    """
    # Parse the log file
    parser = PostgreSQLLogParser(log_file)
    parser.parse_file()

    # Print summary
    parser.print_summary()

    # Export to JSON
    parser.export_to_json(output, include_all=export_all)

    # Detailed analysis section
    print("\n" + "="*80)
    print("🔍 Detailed Analysis Examples")
    print("="*80)

    # Find potential security threats (many failed connections from same IP)
    print(f"\n🚨 Potential Security Threats (IPs with >{security_threshold} connection issues):")
    conn_issues = parser.get_connection_issues()
    ip_issues = Counter(e.ip for e in conn_issues if e.ip)
    threats_found = False
    for ip, count in ip_issues.most_common(10):
        if count > security_threshold:
            print(f"  {ip:20s}: {count:6d} failed connections")
            threats_found = True
    if not threats_found:
        print(f"  No IPs with more than {security_threshold} connection issues found")

    # Find constraint violations
    print("\n⚠️  Database Constraint Violations:")
    constraint_errors = [
        e for e in parser.get_errors()
        if 'violates' in e.message or 'constraint' in e.message
    ]
    if constraint_errors:
        for error in constraint_errors[:10]:
            print(f"  [{error.timestamp}] {error.database}: {error.message[:70]}...")
    else:
        print("  No constraint violations found")

    print("\n" + "="*80)


if __name__ == '__main__':
    main()
