"""Fixture: REACHABLE. main() -> load_config() -> yaml.load() (vulnerable).

Note: PyYAML 6 requires Loader= explicitly, otherwise load() raises
TypeError before entering the function and sys.settrace never sees it.
That is exactly why the execution witness is fragile — see PHASES.md.
"""
import yaml


def load_config(path):
    with open(path) as f:
        return yaml.load(f, Loader=yaml.Loader)


def main():
    print(load_config("config.yaml"))


if __name__ == "__main__":
    main()
