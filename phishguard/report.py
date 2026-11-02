"""Markdown and HTML report generation."""
from __future__ import annotations
import html
from datetime import datetime, timezone
from typing import List

from .models import AnalysisResult


def to_markdown(results: List[AnalysisResult]) -> str:
    """Render results as a Markdown report."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = ["# PhishGuard Analysis Report", "", f"_Generated {ts}_", "",
           "| Artifact | Type | Score | Verdict |", "|---|---|---|---|"]
    for r in results:
        out.append(f"| `{r.source}` | {r.kind} | {r.score} | **{r.verdict}** |")
    for r in results:
        out += ["", f"## {r.source}", f"**Verdict:** {r.verdict} (score {r.score}/100)", ""]
        if not r.findings:
            out.append("No indicators found.")
            continue
        out += ["| Rule | Severity | Finding | Detail | MITRE ATT&CK |", "|---|---|---|---|---|"]
        for f in r.findings:
            out.append(f"| {f.rule_id} | {f.severity} | {f.title} | {f.detail.replace('|', '/')} | {f.mitre} |")
    return "\n".join(out) + "\n"


def to_html(results: List[AnalysisResult]) -> str:
    """Render results as a self-contained HTML report."""
    color = {"PHISHING": "#c0392b", "SUSPICIOUS": "#e67e22", "LIKELY SAFE": "#27ae60"}
    rows = []
    for r in results:
        items = "".join(
            f"<tr><td>{f.rule_id}</td><td class='{f.severity}'>{f.severity}</td><td>{html.escape(f.title)}</td>"
            f"<td>{html.escape(f.detail)}</td><td>{html.escape(f.mitre)}</td></tr>" for f in r.findings
        ) or "<tr><td colspan=5>No indicators found.</td></tr>"
        rows.append(
            f"<section><h2>{html.escape(r.source)}</h2><p><span class='badge' style='background:{color[r.verdict]}'>"
            f"{r.verdict}</span> score {r.score}/100</p><table><tr><th>Rule</th><th>Severity</th><th>Finding</th>"
            f"<th>Detail</th><th>MITRE</th></tr>{items}</table></section>")
    return ("<!doctype html><html><head><meta charset='utf-8'><title>PhishGuard Report</title><style>"
            "body{font-family:system-ui;margin:2em;background:#f7f9fb}table{border-collapse:collapse;width:100%}"
            "td,th{border:1px solid #ddd;padding:6px;font-size:14px}th{background:#2c3e50;color:#fff}"
            ".badge{color:#fff;padding:3px 10px;border-radius:4px;font-weight:bold}.high{color:#c0392b}"
            ".medium{color:#e67e22}.low{color:#7f8c8d}section{background:#fff;padding:1em;margin:1em 0;border-radius:8px}"
            "</style></head><body><h1>PhishGuard Analysis Report</h1>" + "".join(rows) + "</body></html>")
