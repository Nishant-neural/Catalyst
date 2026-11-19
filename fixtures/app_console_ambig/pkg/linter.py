"""A second, unrelated def run — the console script must resolve to
pkg.cli.run, not fail as ambiguous (evaluation fix, 19 Nov 2026)."""


def run():
    return None
