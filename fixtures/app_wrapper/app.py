"""Fixture: REACHABLE via dependency wrapper (ChatGPT addition).
main -> wrapper.parse() in helpers.py -> yaml.load()
"""
from helpers import parse_config

def main():
    print(parse_config("config.yaml"))

if __name__ == "__main__":
    main()
