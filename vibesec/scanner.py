from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import re
from typing import Iterable

from .rules import RULES

MAX_FILE_BYTES = 1_000_000
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "coverage"}
TEXT_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".vue", ".json", ".yml", ".yaml", ".env", ".php", ".rb", ".java"}
WEIGHTS = {"critical": 30, "high": 15, "medium": 7, "low": 2}
AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b")
ASSIGNED_SECRET_RE = re.compile(
    r"(?P<prefix>(?:api[_-]?key|secret|token|aws[_-]?secret(?:[_-]?access)?[_-]?key|secret[_-]?access[_-]?key)\s*[:=]\s*['\"]?)"
    r"(?P<secret>[A-Za-z0-9_\-/+=]{20,})",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    evidence: str
    recommendation: str


def redact_evidence(line: str, rule_id: str) -> str:
    evidence = line.strip()[:180]
    if rule_id == "AWS001":
        return AWS_ACCESS_KEY_RE.sub(
            lambda match: f"{match.group()[:4]}****{match.group()[-4:]}",
            evidence,
        )
    if rule_id in {"AWS002", "SEC002"}:
        return ASSIGNED_SECRET_RE.sub(
            lambda match: f"{match.group('prefix')}{match.group('secret')[:4]}****{match.group('secret')[-4:]}",
            evidence,
        )
    return evidence


def iter_source_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS and path.name != ".env":
            continue
        try:
            if path.stat().st_size <= MAX_FILE_BYTES:
                yield path
        except OSError:
            continue


def scan_directory(root: str | Path) -> dict:
    base = Path(root).resolve()
    if not base.is_dir():
        raise ValueError("Scan target must be an existing directory")

    findings: list[Finding] = []
    scanned = 0
    for path in iter_source_files(base):
        scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line_number, line in enumerate(text.splitlines(), 1):
            for rule in RULES:
                if rule.extensions and path.suffix.lower() not in rule.extensions:
                    continue
                if rule.pattern.search(line):
                    evidence = redact_evidence(line, rule.rule_id)
                    findings.append(Finding(rule.rule_id, rule.title, rule.severity, str(path.relative_to(base)), line_number, evidence, rule.recommendation))

    penalty = sum(WEIGHTS[item.severity] for item in findings)
    score = max(0, 100 - penalty)
    counts = {level: sum(1 for item in findings if item.severity == level) for level in WEIGHTS}
    return {
        "scanner": "VibeSec",
        "version": "0.1.0",
        "score": score,
        "files_scanned": scanned,
        "summary": counts,
        "findings": [asdict(item) for item in findings],
        "disclaimer": "Static findings require human validation and do not prove exploitability.",
    }
