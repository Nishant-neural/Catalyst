"""Fixture: NOT-REACHABLE (Phase 12, 19 Nov 2026). pkg/cli.py is never
imported, guarded or configured, so its top-level yaml.load() never
runs. The old entry-point rule made every file named cli.py a program
root and reported this REACHABLE via pkg.cli.<module> (ChatGPT Phase 9
review, section 4B, reproduced).
"""


def main():
    print("clean")


if __name__ == "__main__":
    main()
