#!/usr/bin/env python3
"""
PostgreSQL Log Parser - CLI Application
Efficiently parses PostgreSQL log files and extracts useful statistics, errors, and slow queries.
"""

import json
import re
from collections import Counter
from dataclasses import dataclass
from typing import Optional, List, Tuple

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


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

    def get_slow_queries(self, threshold_ms: float = 3000.0) -> List[Tuple[float, LogEntry, Optional[str]]]:
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
        """Print a beautifully formatted summary of the parsed log file using Rich"""
        console = Console()

        # Header
        console.print()
        console.print(Panel.fit(
            "[bold cyan]PostgreSQL Log Analysis Summary[/bold cyan]",
            border_style="cyan",
            box=box.DOUBLE
        ))
        console.print()

        # Overall Statistics Table
        stats_table = Table(title="📊 Overall Statistics", box=box.ROUNDED, show_header=False)
        stats_table.add_column("Metric", style="cyan", width=25)
        stats_table.add_column("Value", style="green bold", justify="right")

        stats_table.add_row("Total lines", f"{self.stats['total_lines']:,}")
        stats_table.add_row("Parsed entries", f"{self.stats['parsed_lines']:,}")
        stats_table.add_row("Unparsed lines", f"{self.stats['unparsed_lines']:,}")

        parse_rate = (self.stats['parsed_lines'] / self.stats['total_lines'] * 100) if self.stats[
                                                                                           'total_lines'] > 0 else 0
        stats_table.add_row("Parse rate", f"{parse_rate:.1f}%")

        console.print(stats_table)
        console.print()

        # Log Levels Table
        levels_table = Table(title="📈 Log Levels Distribution", box=box.ROUNDED)
        levels_table.add_column("Level", style="cyan")
        levels_table.add_column("Count", justify="right", style="yellow")
        levels_table.add_column("Percentage", justify="right", style="green")

        total_entries = sum(self.stats['level_counts'].values())
        for level, count in self.stats['level_counts'].most_common():
            percentage = (count / total_entries * 100) if total_entries > 0 else 0

            # Color code based on severity
            if level in ('ERROR', 'FATAL'):
                level_style = "[bold red]"
            elif level == 'WARNING':
                level_style = "[bold yellow]"
            else:
                level_style = "[bold white]"

            levels_table.add_row(
                f"{level_style}{level}[/]",
                f"{count:,}",
                f"{percentage:.1f}%"
            )

        console.print(levels_table)
        console.print()

        # Top Databases Table
        if self.stats['database_counts']:
            db_table = Table(title="🗄️  Top Databases", box=box.ROUNDED)
            db_table.add_column("Database", style="cyan")
            db_table.add_column("Entries", justify="right", style="yellow")

            for db, count in self.get_top_databases(5):
                db_table.add_row(db, f"{count:,}")

            console.print(db_table)
            console.print()

        # Top Users Table
        if self.stats['user_counts']:
            user_table = Table(title="👥 Top Users", box=box.ROUNDED)
            user_table.add_column("User", style="cyan")
            user_table.add_column("Entries", justify="right", style="yellow")

            for user, count in self.stats['user_counts'].most_common(5):
                user_table.add_row(user, f"{count:,}")

            console.print(user_table)
            console.print()

        # Top IP Addresses Table
        if self.stats['ip_counts']:
            ip_table = Table(title="🌐 Top IP Addresses", box=box.ROUNDED)
            ip_table.add_column("IP Address", style="cyan")
            ip_table.add_column("Entries", justify="right", style="yellow")

            for ip, count in self.get_top_ips(5):
                ip_table.add_row(ip, f"{count:,}")

            console.print(ip_table)
            console.print()

        # Errors Section
        errors = self.get_errors()
        if errors:
            error_panel = Panel(
                f"[bold red]{len(errors)}[/bold red] errors and fatal messages found",
                title="❌ Errors and Fatals",
                border_style="red",
                box=box.ROUNDED
            )
            console.print(error_panel)

            if errors:
                error_table = Table(box=box.SIMPLE, show_header=True, header_style="bold red")
                error_table.add_column("Timestamp", style="dim", width=19)
                error_table.add_column("Level", style="red bold", width=8)
                error_table.add_column("Database", style="cyan", width=15)
                error_table.add_column("Message", style="white")

                for error in errors[:5]:
                    msg = error.message[:80] + "..." if len(error.message) > 80 else error.message
                    error_table.add_row(
                        error.timestamp,
                        error.level,
                        error.database or "N/A",
                        msg
                    )

                console.print(error_table)
            console.print()

        # Slow Queries Section
        slow_queries = self.get_slow_queries(3000)
        if slow_queries:
            slow_panel = Panel(
                f"[bold yellow]{len(slow_queries)}[/bold yellow] queries slower than 5 seconds",
                title="🐌 Slow Queries (>3s)",
                border_style="yellow",
                box=box.ROUNDED
            )
            console.print(slow_panel)

            slow_table = Table(box=box.SIMPLE, show_header=True, header_style="bold yellow")
            slow_table.add_column("Duration", justify="right", style="red bold", width=12)
            slow_table.add_column("Timestamp", style="dim", width=19)
            slow_table.add_column("Database", style="cyan", width=15)
            slow_table.add_column("Query", style="white")

            for duration, entry, parameters in slow_queries[:10]:
                msg = entry.message[:60] + "..." if len(entry.message) > 60 else entry.message
                slow_table.add_row(
                    f"{duration:,.2f} ms",
                    entry.timestamp,
                    entry.database or "N/A",
                    msg
                )

            console.print(slow_table)
            console.print()

        # Connection Issues Section
        conn_issues = self.get_connection_issues()
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

            conn_panel = Panel(
                f"[bold orange1]{len(conn_issues)}[/bold orange1] connection-related issues detected",
                title="🔌 Connection Issues",
                border_style="orange1",
                box=box.ROUNDED
            )
            console.print(conn_panel)

            conn_table = Table(box=box.SIMPLE, show_header=True, header_style="bold orange1")
            conn_table.add_column("Issue Type", style="cyan")
            conn_table.add_column("Count", justify="right", style="yellow")

            for issue_type, count in issue_types.most_common():
                conn_table.add_row(issue_type, f"{count:,}")

            console.print(conn_table)
            console.print()

        # Deadlocks Section
        deadlocks = self.get_deadlocks()
        if deadlocks:
            deadlock_panel = Panel(
                f"[bold red]{len(deadlocks)}[/bold red] deadlock events detected",
                title="🔒 Deadlocks",
                border_style="red",
                box=box.ROUNDED
            )
            console.print(deadlock_panel)

            for i, dl in enumerate(deadlocks, 1):
                deadlock_info = f"[bold]Deadlock #{i}[/bold]\n"
                deadlock_info += f"[dim]Time:[/dim] {dl.timestamp}\n"
                deadlock_info += f"[dim]Database:[/dim] {dl.database}\n"
                deadlock_info += f"[dim]Processes:[/dim] {dl.process1_pid} ⚔️  {dl.process2_pid}\n"

                if dl.lock_info:
                    lock_preview = dl.lock_info[:100] + "..." if len(dl.lock_info) > 100 else dl.lock_info
                    deadlock_info += f"[dim]Lock Info:[/dim] {lock_preview}\n"

                if dl.process1_query:
                    query1_preview = dl.process1_query[:80] + "..." if len(
                        dl.process1_query) > 80 else dl.process1_query
                    deadlock_info += f"[dim]Query 1:[/dim] {query1_preview}\n"

                if dl.process2_query:
                    query2_preview = dl.process2_query[:80] + "..." if len(
                        dl.process2_query) > 80 else dl.process2_query
                    deadlock_info += f"[dim]Query 2:[/dim] {query2_preview}"

                console.print(Panel(deadlock_info, border_style="red", box=box.ROUNDED))
            console.print()

        # Summary Metrics Panel
        checkpoints = self.get_checkpoint_info()
        vacuums = self.get_vacuum_info()

        summary_table = Table(title="📋 Additional Metrics", box=box.ROUNDED, show_header=False)
        summary_table.add_column("Metric", style="cyan", width=30)
        summary_table.add_column("Count", style="green bold", justify="right")

        summary_table.add_row("💾 Checkpoints", f"{len(checkpoints):,}")
        summary_table.add_row("🧹 Autovacuum Operations", f"{len(vacuums):,}")

        console.print(summary_table)
        console.print()

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

    # Detailed analysis section with Rich formatting
    console = Console()

    console.print()
    console.print(Panel.fit(
        "[bold magenta]🔍 Detailed Analysis[/bold magenta]",
        border_style="magenta",
        box=box.DOUBLE
    ))
    console.print()

    # Find potential security threats (many failed connections from same IP)
    conn_issues = parser.get_connection_issues()
    ip_issues = Counter(e.ip for e in conn_issues if e.ip)
    threats_found = False

    threat_ips = [(ip, count) for ip, count in ip_issues.most_common(10) if count > security_threshold]

    if threat_ips:
        threats_found = True
        threat_panel = Panel(
            f"[bold red]{len(threat_ips)}[/bold red] IP addresses with suspicious activity detected",
            title=f"🚨 Potential Security Threats (>{security_threshold} connection issues)",
            border_style="red",
            box=box.ROUNDED
        )
        console.print(threat_panel)

        threat_table = Table(box=box.SIMPLE, show_header=True, header_style="bold red")
        threat_table.add_column("IP Address", style="red bold", width=20)
        threat_table.add_column("Failed Connections", justify="right", style="yellow")
        threat_table.add_column("Severity", style="red")

        for ip, count in threat_ips:
            if count > security_threshold * 5:
                severity = "🔴 CRITICAL"
            elif count > security_threshold * 2:
                severity = "🟠 HIGH"
            else:
                severity = "🟡 MEDIUM"

            threat_table.add_row(ip, f"{count:,}", severity)

        console.print(threat_table)
    else:
        safe_panel = Panel(
            f"[bold green]✓[/bold green] No IPs with more than {security_threshold} connection issues found",
            title=f"🚨 Potential Security Threats (>{security_threshold} connection issues)",
            border_style="green",
            box=box.ROUNDED
        )
        console.print(safe_panel)

    console.print()

    # Find constraint violations
    constraint_errors = [
        e for e in parser.get_errors()
        if 'violates' in e.message or 'constraint' in e.message
    ]

    if constraint_errors:
        constraint_panel = Panel(
            f"[bold yellow]{len(constraint_errors)}[/bold yellow] constraint violations detected",
            title="⚠️  Database Constraint Violations",
            border_style="yellow",
            box=box.ROUNDED
        )
        console.print(constraint_panel)

        constraint_table = Table(box=box.SIMPLE, show_header=True, header_style="bold yellow")
        constraint_table.add_column("Timestamp", style="dim", width=19)
        constraint_table.add_column("Database", style="cyan", width=15)
        constraint_table.add_column("Violation", style="white")

        for error in constraint_errors[:10]:
            msg = error.message[:70] + "..." if len(error.message) > 70 else error.message
            constraint_table.add_row(
                error.timestamp,
                error.database or "N/A",
                msg
            )

        console.print(constraint_table)
    else:
        no_violations_panel = Panel(
            "[bold green]✓[/bold green] No constraint violations found",
            title="⚠️  Database Constraint Violations",
            border_style="green",
            box=box.ROUNDED
        )
        console.print(no_violations_panel)

    console.print()


if __name__ == '__main__':
    main()
