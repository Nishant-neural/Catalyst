"""Fixture: NOT-REACHABLE via string concat (Phase 4).
name = "safe_" + "load" -> "safe_load".
"""
import yaml

def load_config(path):
    name = "safe_" + "load"
    func = getattr(yaml, name)
    with open(path) as f:
        return func(f)

def main():
    return load_config("config.yaml")

if __name__ == "__main__":
    main()
