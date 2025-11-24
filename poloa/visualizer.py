"""
Visualization layer using Rich library for terminal UI.

This module contains the LogVisualizer class which creates beautiful
terminal displays of parsed log data.
"""

from collections import Counter
from typing import List, Tuple

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from poloa.analyzers import LogAnalyzer


class LogVisualizer:
    """Visualizer for PostgreSQL log analysis results"""

    def __init__(self, analyzer: LogAnalyzer, config=None):
        """
        Initialize visualizer with an analyzer.

        Args:
            analyzer: LogAnalyzer instance with parsed data
            config: Optional Config instance for display settings
        """
        self.analyzer = analyzer
        self.config = config
        self.console = Console()

    def render_summary(self):
        """Print a beautifully formatted summary of the parsed log file using Rich"""
        console = self.console

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

        stats = self.analyzer.stats
        stats_table.add_row("Total lines", f"{stats['total_lines']:,}")
        stats_table.add_row("Parsed entries", f"{stats['parsed_lines']:,}")
        stats_table.add_row("Unparsed lines", f"{stats['unparsed_lines']:,}")

        parse_rate = (stats['parsed_lines'] / stats['total_lines'] * 100) if stats['total_lines'] > 0 else 0
        stats_table.add_row("Parse rate", f"{parse_rate:.1f}%")

        console.print(stats_table)
        console.print()

        # Log Levels Table
        levels_table = Table(title="📈 Log Levels Distribution", box=box.ROUNDED)
        levels_table.add_column("Level", style="cyan")
        levels_table.add_column("Count", justify="right", style="yellow")
        levels_table.add_column("Percentage", justify="right", style="green")

        total_entries = sum(stats['level_counts'].values())
        for level, count in stats['level_counts'].most_common():
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
        if stats['database_counts']:
            db_table = Table(title="🗄️  Top Databases", box=box.ROUNDED)
            db_table.add_column("Database", style="cyan")
            db_table.add_column("Entries", justify="right", style="yellow")

            for db, count in self.analyzer.get_top_databases(5):
                db_table.add_row(db, f"{count:,}")

            console.print(db_table)
            console.print()

        # Top Users Table
        if stats['user_counts']:
            user_table = Table(title="👥 Top Users", box=box.ROUNDED)
            user_table.add_column("User", style="cyan")
            user_table.add_column("Entries", justify="right", style="yellow")

            for user, count in self.analyzer.get_top_users(5):
                user_table.add_row(user, f"{count:,}")

            console.print(user_table)
            console.print()

        # Top IP Addresses Table
        if stats['ip_counts']:
            ip_table = Table(title="🌐 Top IP Addresses", box=box.ROUNDED)
            ip_table.add_column("IP Address", style="cyan")
            ip_table.add_column("Entries", justify="right", style="yellow")

            for ip, count in self.analyzer.get_top_ips(5):
                ip_table.add_row(ip, f"{count:,}")

            console.print(ip_table)
            console.print()

        # Errors Section
        errors = self.analyzer.get_errors()
        if errors:
            error_panel = Panel(
                f"[bold red]{len(errors)}[/bold red] errors and fatal messages found",
                title="❌ Errors and Fatals",
                border_style="red",
                box=box.ROUNDED
            )
            console.print(error_panel)

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
        threshold_ms = self.config.slow_query_threshold_ms if self.config else 3000.0
        slow_queries = self.analyzer.get_slow_queries(threshold_ms)
        if slow_queries:
            slow_panel = Panel(
                f"[bold yellow]{len(slow_queries)}[/bold yellow] queries slower than {threshold_ms/1000}s",
                title=f"🐌 Slow Queries (>{threshold_ms/1000}s)",
                border_style="yellow",
                box=box.ROUNDED
            )
            console.print(slow_panel)

            slow_table = Table(box=box.SIMPLE, show_header=True, header_style="bold yellow")
            slow_table.add_column("Duration", justify="right", style="red bold", width=12)
            slow_table.add_column("Timestamp", style="dim", width=19)
            slow_table.add_column("Database", style="cyan", width=15)
            slow_table.add_column("Query", style="white", overflow="fold")

            for duration, entry, parameters, expanded_query in slow_queries[:10]:
                query_text = expanded_query or entry.message
                if parameters and expanded_query:
                    query_text = f"{expanded_query}\n[dim]-- parameters: {parameters}[/dim]"

                slow_table.add_row(
                    f"{duration:,.2f} ms",
                    entry.timestamp,
                    entry.database or "N/A",
                    query_text
                )

            console.print(slow_table)
            console.print()

        # Connection Issues Section
        conn_issues = self.analyzer.get_connection_issues()
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
        deadlocks = self.analyzer.get_deadlocks()
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
        checkpoints = self.analyzer.get_checkpoint_info()
        vacuums = self.analyzer.get_vacuum_info()

        summary_table = Table(title="📋 Additional Metrics", box=box.ROUNDED, show_header=False)
        summary_table.add_column("Metric", style="cyan", width=30)
        summary_table.add_column("Count", style="green bold", justify="right")

        summary_table.add_row("💾 Checkpoints", f"{len(checkpoints):,}")
        summary_table.add_row("🧹 Autovacuum Operations", f"{len(vacuums):,}")

        console.print(summary_table)
        console.print()

    def render_security_analysis(self, security_threshold: int = 30):
        """Render security threat analysis section"""
        console = self.console

        console.print()
        console.print(Panel.fit(
            "[bold magenta]🔍 Detailed Analysis[/bold magenta]",
            border_style="magenta",
            box=box.DOUBLE
        ))
        console.print()

        # Find potential security threats (many failed connections from same IP)
        conn_issues = self.analyzer.get_connection_issues()
        ip_issues = Counter(e.ip for e in conn_issues if e.ip)

        threat_ips = [(ip, count) for ip, count in ip_issues.most_common(10) if count > security_threshold]

        if threat_ips:
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

    def render_constraint_violations(self):
        """Render constraint violations section"""
        console = self.console

        # Find constraint violations
        constraint_errors = self.analyzer.get_constraint_violations()

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
