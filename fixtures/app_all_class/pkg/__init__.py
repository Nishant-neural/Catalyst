"""__all__ lists a class, not a function (the requests Session case,
19 Nov 2026): constructing the class is public API use, so its
__init__ must be an entry, while a non-exported helper must not be."""
from .widgets import Widget

__all__ = ["Widget"]
