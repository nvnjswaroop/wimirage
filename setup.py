"""Minimal setup.py shim.

This file exists for environments that still expect `pip install .` to find a
`setup.py` at the repo root. All real metadata lives in `pyproject.toml`;
this shim just hands off to setuptools' PEP 621 backend. Section 8 #3.
"""

from setuptools import setup

setup()
