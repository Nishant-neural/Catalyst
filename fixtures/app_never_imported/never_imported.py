"""Never imported by app.py: its top-level code never runs, so the
yaml.load() call here must NOT make the advisory reachable."""
import yaml

yaml.load("x: 1")
