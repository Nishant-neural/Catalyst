import yaml
def parse_config(path):
    with open(path) as f:
        return yaml.safe_load(f)
