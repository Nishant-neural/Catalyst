"""A dynamic site inside __getattr__ of a reachable module: nothing
calls __getattr__ by name, so BFS alone never reaches it — but
attribute access invokes it at runtime, so the getattr(yaml, key)
site inside it is a real hole. Must be UNCERTAIN, never not_reachable.
(Regression for the MkDocs config_options.py:549 site, 19 Nov 2026.)"""
import yaml

class Config:
    def __getattr__(self, key):
        return getattr(yaml, key)

def main():
    cfg = Config()
    print(cfg.something)

if __name__ == "__main__":
    main()
