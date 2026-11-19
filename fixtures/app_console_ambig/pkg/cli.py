"""Console-script entry. The only real entry is mytool = "pkg.cli:run"."""
import yaml


def run():
    with open("config.yaml") as f:
        return yaml.load(f, Loader=yaml.Loader)
