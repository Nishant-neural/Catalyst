import yaml
def parse_config(path):
    with open(path) as f:
        return yaml.load(f, Loader=yaml.Loader)
