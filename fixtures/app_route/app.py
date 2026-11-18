"""Fixture: REACHABLE via framework dispatch (ChatGPT addition).
No direct call in code from a dispatcher to upload(). The route
decorator is the entry: framework_dispatcher -> upload() -> yaml.load()
"""
import yaml
from flask import Flask
app = Flask(__name__)

@app.route("/upload")
def upload():
    with open("config.yaml") as f:
        return yaml.load(f, Loader=yaml.Loader)

def main():
    app.run()
