#!/usr/bin/env python3
"""
Entry point for PyInstaller builds.
This wrapper allows the package to be imported properly.
"""

from socks_proxy_win.__main__ import main

if __name__ == "__main__":
    main()
