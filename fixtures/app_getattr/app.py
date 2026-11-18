"""Fixture: UNCERTAIN, then LLM-resolvable.
getattr(yaml, name) where name is a literal "safe_load" -> not-reachable.
Change name to "load" to make it reachable. Change it to config["func"]
to make it genuinely uncertain.
"""
import yaml


def load_config(path):
    name = "safe_load"
    func = getattr(yaml, name)
    with open(path) as f:
        return func(f)


def main():
    print(load_config("config.yaml"))


if __name__ == "__main__":
    main()
