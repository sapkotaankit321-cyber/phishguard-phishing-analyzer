"""Analyze raw RFC 5322 email files (.eml) for phishing indicators."""
from __future__ import annotations
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from typing import List

from .models import AnalysisResult, Finding
from .url_analyzer import analyze_url, registered_domain

URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.I)
HREF_RE = re.compile(r"<a[^>]+href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.I | re.S)
URGENCY = ["urgent", "immediately", "suspended", "within 24 hours", "verify your account", "unusual activity", "final notice", "act now", "password expires"]
RISKY_EXT = (".exe", ".scr", ".js", ".vbs", ".hta", ".iso", ".docm", ".xlsm", ".html", ".lnk")


def _body_text(msg: EmailMessage) -> tuple[str, str]:
    """Return (plain, html) bodies concatenated across parts."""
    plain, html = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except (LookupError, KeyError):
            continue
        if ctype == "text/plain":
            plain.append(content)
        elif ctype == "text/html":
            html.append(content)
    return "\n".join(plain), "\n".join(html)


def analyze_email_bytes(raw: bytes, source: str = "<email>") -> AnalysisResult:
    """Analyze raw email bytes and return an :class:`AnalysisResult`."""
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    res = AnalysisResult(source=source, kind="email")
    add = lambda *a: res.findings.append(Finding(*a))  # noqa: E731

    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    from_dom = from_addr.rsplit("@", 1)[-1].lower() if "@" in from_addr else ""
    _, reply_addr = parseaddr(str(msg.get("Reply-To", "")))
    _, rp_addr = parseaddr(str(msg.get("Return-Path", "")))

    if reply_addr and "@" in reply_addr and registered_domain(reply_addr.split("@")[1]) != registered_domain(from_dom):
        add("EML001", "Reply-To domain differs from From", "high", 20, f"{reply_addr} vs {from_addr}", "T1566 Phishing")
    if rp_addr and "@" in rp_addr and registered_domain(rp_addr.split("@")[1]) != registered_domain(from_dom):
        add("EML002", "Return-Path domain mismatch", "medium", 10, rp_addr, "T1566 Phishing")
    if from_name and re.search(r"[\w.-]+\.(com|net|org)", from_name, re.I):
        shown = re.search(r"[\w.-]+\.(com|net|org)", from_name, re.I).group(0).lower()
        if registered_domain(shown) != registered_domain(from_dom):
            add("EML003", "Display name spoofs another domain", "high", 20, f"'{from_name}' <{from_addr}>", "T1656 Impersonation")

    auth = str(msg.get("Authentication-Results", "")).lower()
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", auth)
        if m and m.group(1) in ("fail", "softfail", "none", "permerror"):
            add("EML004", f"{mech.upper()} {m.group(1)}", "high" if mech == "dmarc" else "medium",
                15 if mech == "dmarc" else 10, auth.strip()[:120], "T1566 Phishing")

    plain, html = _body_text(msg)
    subject = str(msg.get("Subject", ""))
    text = f"{subject}\n{plain}\n{re.sub('<[^>]+>', ' ', html)}".lower()
    hits = [w for w in URGENCY if w in text]
    if hits:
        add("EML005", "Urgency / pressure language", "medium", min(15, 5 * len(hits)), ", ".join(hits), "T1566 Phishing")

    for href, anchor in HREF_RE.findall(html):
        shown = re.search(r"https?://([^\s/<]+)", anchor)
        real = re.search(r"https?://([^\s/\"']+)", href)
        if shown and real and registered_domain(shown.group(1)) != registered_domain(real.group(1)):
            add("EML006", "Link text does not match destination", "high", 25, f"shows {shown.group(1)} -> {real.group(1)}", "T1566.002 Spearphishing Link")

    for part in msg.iter_attachments():
        name = (part.get_filename() or "").lower()
        if name.endswith(RISKY_EXT) or re.search(r"\.(pdf|doc|txt)\.\w+$", name):
            add("EML007", "Risky attachment type", "high", 25, name, "T1566.001 Spearphishing Attachment")

    urls = sorted(set(URL_RE.findall(plain + "\n" + html)))
    res.urls = urls
    seen: set[str] = set()
    for u in urls:
        for f in analyze_url(u):
            if f.rule_id not in seen:  # avoid double counting identical rules
                seen.add(f.rule_id)
                f.detail = f"{f.detail} [{u[:60]}]"
                res.findings.append(f)
    return res


def analyze_email_file(path: str | Path) -> AnalysisResult:
    """Analyze an .eml file on disk."""
    p = Path(path)
    return analyze_email_bytes(p.read_bytes(), source=str(p))
