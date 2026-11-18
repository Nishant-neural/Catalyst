"""Regression fixture, 19 Nov 2026 — real MkDocs found this bug.

A project function named `.load` exists (here a test fake, in MkDocs
`FakeEntryPoint.load` in the test suite). A call to `yaml.load(f)`
must resolve to the external library function `yaml.load`, NOT to
that project function by simple-name matching. Before the fix the
call graph had main -> FakeEntryPoint.load and yaml.load was never
reachable, so a real reachable case reported uncertain.
"""
import yaml


class FakeEntryPoint:
    def load(self):
        return {}


def main():
    with open("config.yaml") as f:
        return yaml.load(f)


if __name__ == "__main__":
    main()
