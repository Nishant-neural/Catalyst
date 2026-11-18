"""Fixture: NOT-REACHABLE via constant propagation (Phase 4).
for name in ["safe_load", "dump"]: getattr can only be safe names.
"""
import yaml

def load_config(path):
    for name in ["safe_load", "dump"]:
        func = getattr(yaml, name)
    with open(path) as f:
        return func(f)

def main():
    return load_config("config.yaml")

if __name__ == "__main__":
    main()
