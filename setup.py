"""
Basilisk EDR Setup Configuration
Package metadata and dependency management for PyPI distribution.

Author: Álvaro Fernández Ramos
Version: 7.1.0
Date: 2025-01-15
"""
import sys
from setuptools import setup, find_packages

extra_requirements = []
if sys.platform.startswith('win'):
    extra_requirements.append('pywin32')

setup(
    name="Basilisk",
    version="7.1.0",
    description="Basilisk EDR - Advanced Endpoint Detection and Response System",
    author="Álvaro Fernández Ramos",
    author_email="alvarofdezr@outlook.es",
    url="https://github.com/yourusername/basilisk",
    packages=find_packages(),
    python_requires='>=3.10',
    install_requires=[
        "fastapi",
        "uvicorn[standard]",
        "sqlalchemy",
        "pydantic",
        "requests",
        "PyYAML",
        "python-multipart",
        "itsdangerous",
        "psutil",
        "watchdog",
        "yara-python",
        "argon2-cffi",
        "python-dotenv",
        "cryptography",
        "fpdf2",
        "matplotlib",
        "pyinstaller"
    ] + extra_requirements,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)