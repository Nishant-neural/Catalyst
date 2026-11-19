"""Constructs a library class whose __init__ is the vulnerable function
(the requests / urllib3 Retry case, 19 Nov 2026)."""
from urllib3.util.retry import Retry


def make_session():
    return Retry(3, read=False)


def main():
    make_session()


if __name__ == "__main__":
    main()
