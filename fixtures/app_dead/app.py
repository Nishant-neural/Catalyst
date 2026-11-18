"""Fixture: NOT-REACHABLE (dead code). dead() calls yaml.load(), but
nothing ever calls dead(). A naive tool starting BFS from every function
would wrongly say reachable. Real entry points only: main() is the entry.
"""
import yaml


def dead():
    with open("x.yaml") as f:
        return yaml.load(f)


def main():
    print("hello")


if __name__ == "__main__":
    main()
