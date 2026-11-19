"""Relative-import + constructor chain (the requests / Retry case,
19 Nov 2026): main.py relatively imports Adapter; Adapter.__init__
constructs a urllib3 Retry, whose __init__ is the vulnerable function."""
from urllib3.util.retry import Retry


class Adapter:
    def __init__(self):
        self.retry = Retry(3)
