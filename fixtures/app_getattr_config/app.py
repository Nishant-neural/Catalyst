"""Fixture: UNCERTAIN (Phase 4). name comes from config, not a literal.
Constant propagation returns None, and the LLM must answer "unknown".
"""
import yaml

config = {"func": "load"}

def load_config(path):
    name = config["func"]
    func = getattr(yaml, name)
    with open(path) as f:
        return func(f)

def main():
    return load_config("config.yaml")

if __name__ == "__main__":
    main()
