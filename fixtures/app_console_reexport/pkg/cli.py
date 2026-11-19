import yaml


def main():
    yaml.load(open("config.yaml"), Loader=yaml.Loader)
