"""Fixture: NOT-REACHABLE. Only yaml.safe_load() is used, never yaml.load()."""
import yaml


def load_config(path):
    with open(path) as f:
        return yaml.safe_load(f)


def main():
    print(load_config("config.yaml"))


if __name__ == "__main__":
    main()
