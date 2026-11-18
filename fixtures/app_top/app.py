"""Fixture: REACHABLE via top-level module code (Phase 2).
No main(), no function at all — yaml.load runs on import.
Old code dropped top-level calls (current was None) -> missed.
"""
import yaml

with open("config.yaml") as f:
    DATA = yaml.load(f, Loader=yaml.Loader)
