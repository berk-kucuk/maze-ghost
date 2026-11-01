#!/usr/bin/env python3
"""Maze Ghost — the welcome window of a Ghost session."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    from mazeghost.gui.welcome import run
    sys.exit(run())
