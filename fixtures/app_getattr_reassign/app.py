"""Fixture: NOT-REACHABLE via last-assignment-wins (Phase 4).
name = "load" then name = "safe_load" before the call. The later
unconditional assignment wins; the old code used ast.walk order,
so this was resolved randomly.
"""
import yaml

def load_config(path):
    name = "load"
    name = "safe_load"
    func = getattr(yaml, name)
    with open(path) as f:
        return func(f)

def main():
    return load_config("config.yaml")

if __name__ == "__main__":
    main()
