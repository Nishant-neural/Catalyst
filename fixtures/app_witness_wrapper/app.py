"""Fixture: witness trace keeps the wrapper middle (Phase 5).
main -> helpers.parse_config -> yaml.load. Old harness filtered the
trace to entry_mod.* only, so helpers.parse_config was dropped.
"""
from helpers import parse_config

def main():
    return parse_config("config.yaml")

if __name__ == "__main__":
    main()
