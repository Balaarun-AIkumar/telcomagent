"""Detectors and scrubbers shared by output guard (G5), memory, state and telemetry masking (G7)."""
from __future__ import annotations

import re

CANARY = re.compile(r"CANARY-[A-Z0-9]{12}")
KV_SECRET = re.compile(r"(?i)\b(psk|passphrase|password|wi-?fi key)\s*(?:is|[:=])\s*[\"']?([^\s\"']*\d[^\s\"']*)")
PHONE = re.compile(r"\b\d{3}-\d{3}-\d{4}\b")
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")
SUBSCRIBER_ID = re.compile(r"\bS-\d{5}\b")
_ALLOWED_TOKEN = re.compile(r"^(rv_|CPE-|ONT-|PON-|OLT-|WO-|TT-|S-|DOC-|CO-|JOB-)")
INJECTION = re.compile(
    r"(?i)(ignore (?:all |any |the )?(?:previous |prior |above )?instructions|disregard (?:the )?(?:system|previous)"
    r"|you are now|list all (?:psks|passwords|credentials)|reveal (?:all|every)|print the system prompt"
    r"|call the tool|exfiltrate|send (?:all )?(?:psks|passwords) to)"
)


TOKEN = re.compile(r"[^\s,:;\"'=()\[\]{}<>]+")


def _high_entropy(tok: str) -> bool:
    t = tok.strip(".!?`")
    if len(t) < 10 or _ALLOWED_TOKEN.match(t):
        return False
    return all(len(re.findall(p, t)) >= 2 for p in (r"[a-z]", r"[A-Z]", r"\d"))


def find_secrets(text: str) -> list[str]:
    hits = CANARY.findall(text) + [m.group(2) for m in KV_SECRET.finditer(text)]
    hits += [t for t in TOKEN.findall(text) if _high_entropy(t)]
    return hits


def scrub(text: str) -> str:
    text = CANARY.sub("[REDACTED]", text)
    text = KV_SECRET.sub(lambda m: f"{m.group(1)}: [REDACTED]", text)
    return TOKEN.sub(lambda m: "[REDACTED]" if _high_entropy(m.group(0)) else m.group(0), text)


def mask_pii(text: str) -> str:
    return EMAIL.sub("[email]", PHONE.sub("[phone]", text))


def injection_score(text: str) -> float:
    hits = len(INJECTION.findall(text))
    return min(1.0, 0.6 * hits)


def scan_output(text: str, *, mask: bool, authorized_subjects: set[str], known_secrets: set[str] = frozenset()):
    """G5: secret/canary scan, cross-subscriber leak check, role-aware PII masking."""
    findings: list[str] = []
    for s in known_secrets:
        if s and s in text:
            text = text.replace(s, "[REDACTED]")
            findings.append("known_secret")
    if find_secrets(text):
        findings.append("secret_pattern")
        text = scrub(text)

    def _sub(m: re.Match) -> str:
        if m.group(0) in authorized_subjects:
            return m.group(0)
        findings.append("cross_subscriber")
        return "[subscriber]"

    text = SUBSCRIBER_ID.sub(_sub, text)
    if mask:
        text = mask_pii(text)
    return text, findings
