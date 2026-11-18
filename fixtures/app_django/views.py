import yaml

def upload(request):
    with open("config.yaml") as f:
        return yaml.load(f, Loader=yaml.Loader)

def unused(request):
    with open("config.yaml") as f:
        return yaml.load(f, Loader=yaml.Loader)
