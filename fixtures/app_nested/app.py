"""Fixture: REACHABLE via nested function (Phase 2).
main() defines inner(), then calls inner() AFTER the def.
Old code set current=None after the nested def, so the inner()
call was dropped -> not_reachable (wrong).
"""
import yaml

def main():
    def inner():
        with open("config.yaml") as f:
            return yaml.load(f, Loader=yaml.Loader)
    return inner()

if __name__ == "__main__":
    main()
