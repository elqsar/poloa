"""
Setup script for PostgreSQL Log Parser package.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file for long description
readme_path = Path(__file__).parent / "readme.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

setup(
    name="postg-log-parser",
    version="1.0.0",
    author="PostgreSQL Log Parser Team",
    author_email="",
    description="A CLI tool for parsing and analyzing PostgreSQL log files",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/postg-log-parser",
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Database",
        "Topic :: System :: Logging",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.0",
        "rich>=13.0.0",
    ],
    extras_require={
        "config": ["pyyaml>=6.0"],
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "postg-parser=postg.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.yaml", "*.yml"],
    },
    zip_safe=False,
)
