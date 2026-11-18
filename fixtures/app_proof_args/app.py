"""Fixture: witness keeps the static verdict when the entry needs args
(Phase 5). main(args) raises TypeError when called with no args, so the
witness never hits yaml.load — but the static verdict stays reachable.
A failed witness never downgrades.
"""
import yaml

def main(args):
    with open("config.yaml") as f:
        return yaml.load(f, Loader=yaml.Loader)

if __name__ == "__main__":
    import sys
    main(sys.argv)
