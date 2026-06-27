"""
setup.py

Optional packaging so VaultKeeper can be installed as a CLI tool:
    pip install -e .
    vaultkeeper list
"""

from setuptools import find_packages, setup

setup(
    name="vaultkeeper",
    version="1.0.0",
    description="A local, encrypted CLI password manager.",
    packages=find_packages(exclude=["tests", "tests.*"]),
    install_requires=[
        "cryptography>=42.0.0",
        "pyperclip>=1.8.2",
        "tabulate>=0.9.0",
        "pyotp>=2.9.0",
    ],
    extras_require={
        "dev": ["pytest>=8.0.0"],
    },
    entry_points={
        "console_scripts": [
            "vaultkeeper=vaultkeeper.main:main",
        ],
    },
    python_requires=">=3.9",
)
