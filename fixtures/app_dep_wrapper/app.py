"""Fixture: UNCERTAIN via dependency entry (Phase 12, 19 Nov 2026).
The app calls thirdparty.safe_api(); thirdparty is not in the project
and its source is not parsed, so thirdparty.vulnerable may be called
internally by the wrapper. The old code said NOT_REACHABLE + OpenVEX
(ChatGPT Phase 9 review, Issue 2, reproduced). Unit-test-only: the
advisory is for thirdparty, not the sample PyYAML one verify.py uses.
"""
import thirdparty


def main():
    return thirdparty.safe_api("example")


if __name__ == "__main__":
    main()
