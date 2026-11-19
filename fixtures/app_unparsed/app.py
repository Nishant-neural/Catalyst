"""Imports yaml but never calls yaml.load. With broken.py unparsable,
the completeness gate (not the analyser) must flip yaml.load from
not_reachable to uncertain."""
import yaml

def main():
    print(yaml.__version__)

if __name__ == "__main__":
    main()
