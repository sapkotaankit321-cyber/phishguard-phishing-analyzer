"""Data models for findings and analysis results."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List


@dataclass
class Finding:
    """A single suspicious indicator."""
    rule_id: str
    title: str
    severity: str  # low | medium | high
    score: int
    detail: str
    mitre: str = ""


@dataclass
class AnalysisResult:
    """Aggregate result for one analyzed artifact (email or URL)."""
    source: str
    kind: str
    findings: List[Finding] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        """Risk score capped at 100."""
        return min(100, sum(f.score for f in self.findings))

    @property
    def verdict(self) -> str:
        """Human-readable verdict derived from the score."""
        if self.score >= 60:
            return "PHISHING"
        if self.score >= 30:
            return "SUSPICIOUS"
        return "LIKELY SAFE"
