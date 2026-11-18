"""Fixture: REACHABLE via importlib alias (Phase 4 / callgraph).
mod = importlib.import_module("yaml"); mod.load(f) is yaml.load.
Old code dropped the mod.load call as attr-unresolved -> missed.
"""
import importlib

def load_config(path):
    mod = importlib.import_module("yaml")
    with open(path) as f:
        return mod.load(f, Loader=mod.Loader)

def main():
    return load_config("config.yaml")

if __name__ == "__main__":
    main()
