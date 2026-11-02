"""Heuristic URL analysis (no network access required)."""
from __future__ import annotations
import ipaddress
import math
import re
from collections import Counter
from typing import List
from urllib.parse import urlparse

from .models import Finding

SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "work"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"}
BRANDS = ["paypal", "microsoft", "office365", "apple", "amazon", "netflix", "google", "bankofamerica", "chase", "wellsfargo", "dhl", "fedex"]
LURE_WORDS = ["login", "verify", "secure", "account", "update", "signin", "confirm", "password", "wallet", "invoice"]
MITRE_LINK = "T1566.002 Spearphishing Link"


def shannon_entropy(text: str) -> float:
    """Return the Shannon entropy (bits/char) of ``text``."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def registered_domain(host: str) -> str:
    """Approximate the registrable domain (last two labels)."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    parts = host.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def analyze_url(url: str) -> List[Finding]:
    """Analyze a URL and return a list of heuristic findings."""
    findings: List[Finding] = []
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = (parsed.hostname or "").lower()
    full = url.lower()

    def add(rid: str, title: str, sev: str, score: int, detail: str) -> None:
        findings.append(Finding(rid, title, sev, score, detail, MITRE_LINK))

    try:
        ipaddress.ip_address(host)
        add("URL001", "IP address used as host", "high", 25, host)
    except ValueError:
        pass
    if "@" in parsed.netloc:
        add("URL002", "Userinfo '@' trick in URL", "high", 25, parsed.netloc)
    if host.startswith("xn--") or ".xn--" in host:
        add("URL003", "Punycode / IDN homograph domain", "high", 25, host)
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        add("URL004", "High-abuse TLD", "medium", 10, f".{tld}")
    if registered_domain(host) in SHORTENERS:
        add("URL005", "URL shortener hides destination", "medium", 10, host)
    if parsed.scheme == "http":
        add("URL006", "Unencrypted HTTP link", "low", 5, url)
    if host.count(".") >= 4:
        add("URL007", "Excessive subdomains", "medium", 10, host)
    if len(url) > 100:
        add("URL008", "Unusually long URL", "low", 5, f"{len(url)} chars")
    reg = registered_domain(host)
    for brand in BRANDS:
        if brand in full and brand not in reg.split(".")[0]:
            add("URL009", "Brand name outside registered domain", "high", 20, f"'{brand}' on {reg}")
            break
    lures = [w for w in LURE_WORDS if w in full]
    if lures:
        add("URL010", "Credential-lure keywords", "medium", min(15, 5 * len(lures)), ", ".join(lures))
    label = reg.split(".")[0]
    if len(label) >= 10 and shannon_entropy(label) > 3.5:
        add("URL011", "High-entropy (DGA-like) domain", "medium", 10, f"{label} H={shannon_entropy(label):.2f}")
    if re.search(r"\.(exe|scr|js|vbs|hta|iso|zip)(\?|$)", parsed.path.lower()):
        add("URL012", "Direct link to executable/archive", "high", 20, parsed.path)
    return findings
