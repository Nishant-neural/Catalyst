"""Fixture: NOT-REACHABLE via receiver identity (Phase 12, 19 Nov 2026).
getattr(json, "load") is json.load, not yaml.load. The old resolver
matched only the simple name "load" and reported this REACHABLE with
high confidence (ChatGPT Phase 9 review, Issue 3, reproduced).
"""
import json


def main():
    name = "load"
    func = getattr(json, name)
    return func("{}")


if __name__ == "__main__":
    main()
