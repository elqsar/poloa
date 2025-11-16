"""
Configuration management for POLOA - PostgreSQL Log Analyzer.

This module handles loading and managing configuration from
YAML files and command-line overrides.
"""

import os
from pathlib import Path
from typing import Optional

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

from poloa.models import Config


class ConfigManager:
    """Manager for loading and merging configuration"""

    DEFAULT_CONFIG_PATHS = [
        'config.yaml',
        'config.yml',
        '~/.poloa/config.yaml',
        '~/.poloa/config.yml',
    ]

    @classmethod
    def load_config(cls, config_path: Optional[str] = None) -> Config:
        """
        Load configuration from file or use defaults.

        Args:
            config_path: Optional path to config file. If None, searches default paths.

        Returns:
            Config instance
        """
        config_dict = {}

        # If specific path provided, load it
        if config_path:
            config_dict = cls._load_yaml_file(config_path)
        else:
            # Search for config in default paths
            for path in cls.DEFAULT_CONFIG_PATHS:
                expanded_path = Path(path).expanduser()
                if expanded_path.exists():
                    config_dict = cls._load_yaml_file(str(expanded_path))
                    break

        # Create Config from dict (will use defaults for missing values)
        return Config.from_dict(config_dict) if config_dict else Config()

    @classmethod
    def _load_yaml_file(cls, filepath: str) -> dict:
        """
        Load YAML configuration file.

        Args:
            filepath: Path to YAML file

        Returns:
            Dictionary of configuration values
        """
        if not YAML_AVAILABLE:
            print("Warning: PyYAML not installed. Install with: pip install pyyaml")
            return {}

        try:
            with open(filepath, 'r') as f:
                data = yaml.safe_load(f)
                return data if data else {}
        except Exception as e:
            print(f"Warning: Could not load config file {filepath}: {e}")
            return {}

    @classmethod
    def merge_cli_args(cls, config: Config, **cli_args) -> Config:
        """
        Merge CLI arguments into config, with CLI args taking precedence.

        Args:
            config: Base Config instance
            **cli_args: CLI arguments to merge

        Returns:
            Updated Config instance
        """
        # Filter out None values and update config
        for key, value in cli_args.items():
            if value is not None and hasattr(config, key):
                setattr(config, key, value)

        return config

    @classmethod
    def save_config(cls, config: Config, filepath: str):
        """
        Save configuration to YAML file.

        Args:
            config: Config instance to save
            filepath: Path to output file
        """
        if not YAML_AVAILABLE:
            print("Error: PyYAML not installed. Install with: pip install pyyaml")
            return

        # Ensure directory exists
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, 'w') as f:
            yaml.dump(config.to_dict(), f, default_flow_style=False, sort_keys=False)

        print(f"Configuration saved to {filepath}")
