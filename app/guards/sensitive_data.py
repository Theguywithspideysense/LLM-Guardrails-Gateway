"""Shared internal spans keep input/output detection and redaction consistent.

Patterns are heuristics; public findings contain only types and counts.
"""
import ipaddress
import re
from collections import Counter
from dataclasses import dataclass

@dataclass(frozen=True)
class Finding:
    kind: str
    group: str
    start: int
    end: int

PII_PATTERNS = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "PHONE": re.compile(r"(?<![\w+])(?:\+91[ -]?)?[6-9](?:[ -]?\d){9}(?!\w)"),
    "IP_ADDRESS": re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"),
    "CREDIT_CARD": re.compile(r"(?<!\w)\d(?:[ -]?\d){12,18}(?!\w)"),
}
SECRET_PATTERNS = {
    "OPENAI_API_KEY": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "GITHUB_TOKEN": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    "AWS_ACCESS_KEY": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    "BEARER_TOKEN": re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}", re.IGNORECASE),
    "PRIVATE_KEY": re.compile(
        r"-----BEGIN (?P<key_type>(?:(?:RSA|EC|OPENSSH|ENCRYPTED) )?PRIVATE KEY)-----"
        r"[\s\S]*?(?:-----END (?P=key_type)-----|\Z)"
    ),
    "DATABASE_URL": re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?)://"
        r"[^\s:/]+:[^\s@]+@[^\s\"'<>]+", re.IGNORECASE
    ),
    "PASSWORD": re.compile(
        r"\b(?:password|passwd|api[_-]?key|client[_-]?secret)\s*[:=]\s*"
        r"(?:\"[^\"\r\n]+\"|'[^'\r\n]+'|[^\s,;]+)", re.IGNORECASE
    ),
}

def valid_card(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    if len(set(digits)) < 2:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0

def find_sensitive_data(text: str, groups: set[str] | None = None) -> list[Finding]:
    groups = {"pii", "secrets"} if groups is None else groups
    findings = []
    for group, patterns in (("secrets", SECRET_PATTERNS), ("pii", PII_PATTERNS)):
        if group not in groups:
            continue
        for kind, pattern in patterns.items():
            for match in pattern.finditer(text):
                if kind == "IP_ADDRESS":
                    try:
                        ipaddress.ip_address(match.group())
                    except ValueError:
                        continue
                if kind == "CREDIT_CARD" and not valid_card(match.group()):
                    continue
                findings.append(Finding(kind, group, match.start(), match.end()))
    return findings

def summarize(findings: list[Finding]) -> list[dict]:
    return [{"type": kind, "count": count} for kind, count in sorted(
        Counter(finding.kind for finding in findings).items()
    )]
