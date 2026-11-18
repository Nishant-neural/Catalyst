"""Fixture: STAYS UNCERTAIN (Phase 4 aggregation fix, 19 Nov 2026).
Two dynamic sites: the first resolves to a safe literal, the second
reads the name from config and cannot be resolved. The old Phase 4
took the first resolvable site and marked the result not_reachable —
on the real PyYAML sdist that one site was getattr(..., "encoding")
and it wrongly cleared all 7 candidates including yaml.load.
Correct: not_reachable needs EVERY site resolved safe.
"""
import yaml

config = {"func": "load"}

def load_config(path):
    name = "safe_load"
    func = getattr(yaml, name)
    with open(path) as f:
        first = func(f)
    other = config["func"]
    func2 = getattr(yaml, other)
    with open(path) as f:
        return func2(f)

def main():
    return load_config("config.yaml")

if __name__ == "__main__":
    main()
