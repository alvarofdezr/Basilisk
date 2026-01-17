import sys
from setuptools import setup, find_packages

'''
Notes: This is the setup file for the Basilisk EDR project.
It defines the package metadata and dependencies required for installation.
Author: Álvaro Fernández Ramos
Date: 2025-01-15
'''
# Define extra requirements based on the operating system
extra_requirements = []
if sys.platform.startswith('win'):
    extra_requirements.append('pywin32')
    
setup(
    name = "Basilisk",
    version = "6.7.1",
    description= "Basilisk EDR - Advanced Endpoint Detection and Response System",
    author = "Álvaro Fernández Ramos",
    packages=find_packages(),
    python_requires='>=3.10',
    install_requires=[
        # Core
        "fastapi",
        "uvicorn[standard]",
        "sqlalchemy",
        "pydantic",
        "requests",
        "PyYAML",
        "python-multipart",
        
        # System & Security
        "psutil",
        "watchdog",      
        "yara-python",
        "argon2-cffi",
        "python-dotenv",
        "cryptography",

        # Utils
        "fpdf2",
        "matplotlib",
        "pyinstaller"
    ] + extra_requirements,
)