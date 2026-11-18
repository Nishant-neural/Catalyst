"""Fixture: REACHABLE via self.method (Phase 2).
Two classes both define helper(). Loader.helper() calls yaml.load,
SafeLoader.helper() calls safe_load. main() uses Loader.
Old code resolved 'helper' by simple name -> 2 candidates -> ambiguous
-> uncertain. New code resolves self.helper to the enclosing class.
"""
import yaml

class Loader:
    def helper(self):
        with open("config.yaml") as f:
            return yaml.load(f, Loader=yaml.Loader)
    def load_config(self):
        return self.helper()

class SafeLoader:
    def helper(self):
        with open("config.yaml") as f:
            return yaml.safe_load(f)
    def load_config(self):
        return self.helper()

def main():
    return Loader().load_config()

if __name__ == "__main__":
    main()
