"""Command-line interface for PhishGuard."""
from __future__ import annotations
import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import List, Optional

from .email_analyzer import analyze_email_file
from .models import AnalysisResult
from .report import to_html, to_markdown
from .url_analyzer import analyze_url


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    p = argparse.ArgumentParser(prog="phishguard", description="Offline phishing email & URL analyzer")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("email", help="analyze .eml files or a directory of them")
    e.add_argument("paths", nargs="+")
    u = sub.add_parser("url", help="analyze one or more URLs")
    u.add_argument("urls", nargs="*")
    u.add_argument("-f", "--file", help="file with one URL per line")
    for s in (e, u):
        s.add_argument("--format", choices=["text", "json", "md", "html"], default="text")
        s.add_argument("-o", "--output", help="write report to file")
    return p


def _collect_emails(paths: List[str]) -> List[AnalysisResult]:
    out = []
    for p in map(Path, paths):
        files = sorted(p.glob("*.eml")) if p.is_dir() else [p]
        out += [analyze_email_file(f) for f in files]
    return out


def _render(results: List[AnalysisResult], fmt: str) -> str:
    if fmt == "json":
        return json.dumps([{**asdict(r), "score": r.score, "verdict": r.verdict} for r in results], indent=2)
    if fmt == "md":
        return to_markdown(results)
    if fmt == "html":
        return to_html(results)
    lines = []
    for r in results:
        lines.append(f"[{r.verdict:^11}] {r.score:>3}/100  {r.source}")
        lines += [f"    - {f.rule_id} ({f.severity}) {f.title}: {f.detail}" for f in r.findings]
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point. Returns 2 if any artifact is PHISHING, 1 if SUSPICIOUS, else 0."""
    args = build_parser().parse_args(argv)
    if args.cmd == "email":
        results = _collect_emails(args.paths)
    else:
        urls = list(args.urls)
        if args.file:
            urls += [l.strip() for l in Path(args.file).read_text().splitlines() if l.strip() and not l.startswith("#")]
        results = [AnalysisResult(source=u, kind="url", findings=analyze_url(u), urls=[u]) for u in urls]
    text = _render(results, args.format)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(text)
    verdicts = {r.verdict for r in results}
    return 2 if "PHISHING" in verdicts else 1 if "SUSPICIOUS" in verdicts else 0


if __name__ == "__main__":
    sys.exit(main())
