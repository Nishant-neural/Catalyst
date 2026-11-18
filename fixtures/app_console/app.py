"""Fixture: REACHABLE only via console_scripts (Phase 3).
No main(), no route. The only real entry is `mytool = "app:run"`.
dead() also calls yaml.load but is never invoked.
Old code fell back to all public functions, so dead() was an entry
and the path went through dead() — right verdict, wrong evidence.
"""
import yaml

def run():
    with open("config.yaml") as f:
        return yaml.load(f, Loader=yaml.Loader)

def dead():
    with open("config.yaml") as f:
        return yaml.load(f, Loader=yaml.Loader)
