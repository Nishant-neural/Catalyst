"""Fixture: REACHABLE via @click.command (Phase 3 regression).
dead() also calls yaml.load but is never invoked.
"""
import yaml
import click

@click.command()
def cli():
    with open("config.yaml") as f:
        return yaml.load(f, Loader=yaml.Loader)

def dead():
    with open("config.yaml") as f:
        return yaml.load(f, Loader=yaml.Loader)
