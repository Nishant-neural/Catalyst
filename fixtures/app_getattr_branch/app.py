"""Fixture: REACHABLE via branch union (Phase 4).
if/else assigns "load" or "safe_load". Either branch can run, so the
possible values are both, and "load" is vulnerable. Fail-closed.
"""
import yaml

def load_config(path, use_unsafe):
    if use_unsafe:
        name = "load"
    else:
        name = "safe_load"
    func = getattr(yaml, name)
    with open(path) as f:
        return func(f)

def main():
    return load_config("config.yaml", True)

if __name__ == "__main__":
    main()
