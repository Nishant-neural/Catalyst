"""Fixture: REACHABLE via assignment alias (Phase 2).
load = yaml.load, then main() calls load(f). Old code had no alias
tracking, so the call was dropped -> not_reachable (wrong, a miss).
"""
import yaml

load = yaml.load

def main():
    with open("config.yaml") as f:
        return load(f, Loader=yaml.Loader)

if __name__ == "__main__":
    main()
