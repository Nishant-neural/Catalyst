"""Fixture: REACHABLE via star import (Phase 2).
helpers.parse_config (yaml.load) and legacy.parse_config (safe_load)
both exist. app.py does `from helpers import *`, so parse_config
is helpers'. Old code saw 2 candidates -> ambiguous -> uncertain.
New code prefers the star-imported module.
"""
from helpers import *

def main():
    return parse_config("config.yaml")

if __name__ == "__main__":
    main()
