import yaml

def load_config(path):
    with open(path) as f:
        return yaml.load(f, Loader=yaml.Loader)

def other_public(path):
    with open(path) as f:
        return yaml.load(f, Loader=yaml.Loader)

def _internal(path):
    with open(path) as f:
        return yaml.load(f, Loader=yaml.Loader)
