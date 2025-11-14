"""
Data models for PostgreSQL log parser.

This module contains all data classes used throughout the application.
"""

from dataclasses import dataclass, field
from typing import Optional


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


@dataclass
class Config:
    """Configuration settings for the log parser"""

    # Thresholds
    slow_query_threshold_ms: float = 3000.0
    security_threshold: int = 30

    # Display settings
    color_scheme: str = "default"
    show_emojis: bool = True
    max_items_per_table: int = 10

    # Export settings
    default_export_format: str = "json"
    include_all_entries: bool = False

    # Pattern settings
    log_format: str = "default"
    custom_pattern: Optional[str] = None

    @classmethod
    def from_dict(cls, config_dict: dict) -> 'Config':
        """Create Config from dictionary"""
        # Flatten nested structure if present
        if 'thresholds' in config_dict:
            config_dict['slow_query_threshold_ms'] = config_dict['thresholds'].get('slow_query_ms', 3000.0)
            config_dict['security_threshold'] = config_dict['thresholds'].get('security_connection_failures', 30)

        if 'display' in config_dict:
            config_dict['color_scheme'] = config_dict['display'].get('color_scheme', 'default')
            config_dict['show_emojis'] = config_dict['display'].get('show_emojis', True)
            config_dict['max_items_per_table'] = config_dict['display'].get('max_items_per_table', 10)

        if 'export' in config_dict:
            config_dict['default_export_format'] = config_dict['export'].get('default_format', 'json')
            config_dict['include_all_entries'] = config_dict['export'].get('include_all_entries', False)

        if 'patterns' in config_dict:
            config_dict['log_format'] = config_dict['patterns'].get('log_format', 'default')
            config_dict['custom_pattern'] = config_dict['patterns'].get('custom_pattern')

        # Filter to only valid Config fields
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_dict = {k: v for k, v in config_dict.items() if k in valid_fields}

        return cls(**filtered_dict)

    def to_dict(self) -> dict:
        """Convert Config to dictionary"""
        return {
            'thresholds': {
                'slow_query_ms': self.slow_query_threshold_ms,
                'security_connection_failures': self.security_threshold,
            },
            'display': {
                'color_scheme': self.color_scheme,
                'show_emojis': self.show_emojis,
                'max_items_per_table': self.max_items_per_table,
            },
            'export': {
                'default_format': self.default_export_format,
                'include_all_entries': self.include_all_entries,
            },
            'patterns': {
                'log_format': self.log_format,
                'custom_pattern': self.custom_pattern,
            }
        }
