"""A test file using @mock.patch: the decorated function is not a
route and not an entry point. (MkDocs had 123 phantom entries from
this exact pattern, 19 Nov 2026.)"""
from unittest import mock
import yaml

@mock.patch("yaml.load")
def test_something(mock_load):
    pass
