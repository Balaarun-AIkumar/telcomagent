"""Check Git upload candidates without printing secret values. No external dependencies."""
from __future__ import annotations

import base64
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {
    "private key": rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "Google API key": rb"AIza[0-9A-Za-z_-]{30,}",
    "Langfuse secret": rb"sk-lf-[0-9a-fA-F-]{20,}",
    "GitHub token": rb"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})",
    "AWS access key": rb"(?:AKIA|ASIA)[A-Z0-9]{16}",
    "OpenAI-style secret": rb"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,}",
}


def candidates() -> list[Path]:
    result = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "."],
                            cwd=ROOT, capture_output=True, check=True)
    return sorted({ROOT / p.decode("utf-8") for p in result.stdout.split(b"\0") if p})


def known_secrets() -> dict[str, bytes]:
    """Read local values only for exact-match detection; never report the value."""
    values = {}
    env = ROOT / ".env"
    if env.exists():
        for line in env.read_text(encoding="utf-8-sig").splitlines():
            name, sep, value = line.strip().partition("=")
            value = value.strip().strip("\"'")
            if sep and not name.startswith("#") and re.search(r"KEY|SECRET|PASSWORD|AUTH", name) and len(value) >= 12:
                values[name] = value.encode()
        public = values.get("LANGFUSE_PUBLIC_KEY")
        secret = values.get("LANGFUSE_SECRET_KEY")
        if public and secret:
            values["derived Langfuse Basic auth"] = base64.b64encode(public + b":" + secret)
    return values


def scan(paths: list[Path]) -> list[str]:
    found = []
    known = known_secrets()
    for path in paths:
        if not path.is_file():
            continue
        data = path.read_bytes()
        name = path.relative_to(ROOT).as_posix()
        if path.name == ".env" or path.suffix in {".pem", ".key", ".db", ".p12", ".pfx"}:
            found.append(f"{name}: sensitive file is an upload candidate")
        for kind, pattern in PATTERNS.items():
            if re.search(pattern, data):
                found.append(f"{name}: possible {kind}")
        for kind, value in known.items():
            if value in data:
                found.append(f"{name}: contains configured {kind}")
    return found


if __name__ == "__main__":
    paths = candidates()
    findings = scan(paths)
    for finding in findings:
        print(finding)
    print(f"Checked {len(paths)} upload candidates; findings: {len(findings)}.")
    raise SystemExit(bool(findings))
