"""Fixture: REACHABLE via constant propagation (Phase 4).
name = "load" -> getattr(yaml, name) is yaml.load. No LLM needed.
"""
import yaml

def load_config(path):
    name = "load"
    func = getattr(yaml, name)
    with open(path) as f:
        return func(f, Loader=yaml.Loader)

def main():
    return load_config("config.yaml")

if __name__ == "__main__":
    main()
