"""Library-mode fixture: a public class whose method shares a name with
a medium-confidence text candidate (the Flask Request.max_content_length
case, 19 Nov 2026)."""
from .wrappers import Request

__all__ = ["Request"]
