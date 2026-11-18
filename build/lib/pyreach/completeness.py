"""Completeness ledger — core, not a write-up item (ChatGPT fix).

Parsing every file does NOT mean every call was found. Record, per run:
- project source: files discovered vs parsed
- dependency source: modules discovered vs parsed
- imports: unresolved imports
- entry points: identified vs unsupported registrations
- dynamic calls: unresolved
- call graph: unresolved / ambiguous edges
- vulnerable targets: identified, with confidence

NOT_REACHABLE is allowed only when the ledger shows 100% coverage
of the analyser's *explicitly supported scope* — not a claim that
every possible Python runtime behaviour was modelled.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Ledger:
    project_files_discovered: int = 0
    project_files_parsed: int = 0
    dependency_modules_discovered: int = 0
    dependency_modules_parsed: int = 0
    unresolved_imports: list[str] = field(default_factory=list)
    entry_points_identified: int = 0
    entry_points_unsupported: list[str] = field(default_factory=list)
    dynamic_unresolved: int = 0
    ambiguous_edges: int = 0
    vulnerable_targets_high: int = 0
    vulnerable_targets_low: int = 0

    def is_complete_for_not_reachable(self) -> bool:
        return (
            self.project_files_discovered == self.project_files_parsed
            and self.dynamic_unresolved == 0
            and self.ambiguous_edges == 0
            and self.vulnerable_targets_low == 0
            and not self.unresolved_imports
        )

    def to_dict(self) -> dict:
        return {
            "project_source": f"{self.project_files_parsed}/{self.project_files_discovered} parsed",
            "dependency_source": f"{self.dependency_modules_parsed}/{self.dependency_modules_discovered} parsed",
            "unresolved_imports": self.unresolved_imports,
            "entry_points_identified": self.entry_points_identified,
            "entry_points_unsupported": self.entry_points_unsupported,
            "dynamic_unresolved": self.dynamic_unresolved,
            "ambiguous_edges": self.ambiguous_edges,
            "vulnerable_targets_high": self.vulnerable_targets_high,
            "vulnerable_targets_low": self.vulnerable_targets_low,
            "complete_for_not_reachable": self.is_complete_for_not_reachable(),
        }
