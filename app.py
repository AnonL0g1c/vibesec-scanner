from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import html
import re
import tempfile
import zipfile

import gradio as gr

MAX_ARCHIVE_BYTES = 10_000_000
MAX_FILE_BYTES = 1_000_000
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "coverage"}
TEXT_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".vue", ".json", ".yml", ".yaml", ".env", ".php", ".rb", ".java"}
WEIGHTS = {"critical": 30, "high": 15, "medium": 7, "low": 2}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    pattern: re.Pattern[str]
    recommendation: str


def rx(value: str) -> re.Pattern[str]:
    return re.compile(value, re.IGNORECASE)


RULES = (
    Rule("SEC001", "Private key committed", "critical", rx(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Revoke and rotate the key; load it from a secret manager."),
    Rule("SEC002", "Likely API token committed", "high", rx(r"(?:api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]"), "Revoke the token and inject it through environment variables."),
    Rule("INJ001", "Shell command execution", "high", rx(r"\b(?:exec|execSync|system|popen|subprocess\.(?:run|call|Popen))\s*\("), "Avoid shell execution and allowlist every argument."),
    Rule("INJ002", "Potential SQL string interpolation", "high", rx(r"(?:SELECT|INSERT|UPDATE|DELETE).{0,120}(?:\$\{|\+\s*\w+|%s|\.format\()"), "Use parameterized queries."),
    Rule("XSS001", "Unsafe HTML rendering", "high", rx(r"(?:dangerouslySetInnerHTML|\.innerHTML\s*=|\|\s*safe\b)"), "Render text safely or sanitize untrusted HTML with an allowlist."),
    Rule("CFG001", "Permissive CORS", "medium", rx(r"(?:allow_origins\s*=\s*\[?['\"]\*|Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*)"), "Allow only exact trusted origins."),
    Rule("AUTH001", "Weak hard-coded JWT secret", "high", rx(r"(?:jwt[_-]?secret|secret[_-]?key)\s*[:=]\s*['\"](?:secret|password|changeme|dev|test)['\"]"), "Generate a strong secret outside source control and rotate tokens."),
    Rule("CFG002", "Debug mode enabled", "medium", rx(r"\bdebug\s*[:=]\s*(?:true|1)\b"), "Disable debug mode in production."),
)


def safe_extract(archive: zipfile.ZipFile, destination: Path) -> None:
    total = 0
    for member in archive.infolist():
        total += member.file_size
        target = (destination / member.filename).resolve()
        if destination.resolve() not in target.parents and target != destination.resolve():
            raise ValueError("Unsafe path detected inside ZIP")
        if member.file_size > MAX_FILE_BYTES or total > 30_000_000:
            raise ValueError("Expanded archive exceeds safety limits")
    archive.extractall(destination)


def scan_zip(uploaded_file: str | None) -> tuple[str, list[list[str]]]:
    if not uploaded_file:
        raise gr.Error("Choose a ZIP project first.")
    archive_path = Path(uploaded_file)
    if archive_path.suffix.lower() != ".zip" or archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise gr.Error("Upload a valid ZIP no larger than 10 MB.")

    findings: list[list[str]] = []
    scanned = 0
    with tempfile.TemporaryDirectory(prefix="vibesec-") as tmp:
        root = Path(tmp)
        try:
            with zipfile.ZipFile(archive_path) as archive:
                safe_extract(archive, root)
        except (zipfile.BadZipFile, ValueError) as exc:
            raise gr.Error(str(exc)) from exc

        for path in root.rglob("*"):
            if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.suffix.lower() not in TEXT_EXTENSIONS and path.name != ".env":
                continue
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            scanned += 1
            text = path.read_text(encoding="utf-8", errors="replace")
            for line_number, line in enumerate(text.splitlines(), 1):
                for rule in RULES:
                    if rule.pattern.search(line):
                        findings.append([rule.severity.upper(), rule.title, f"{path.relative_to(root)}:{line_number}", rule.rule_id, line.strip()[:160], rule.recommendation])

    penalty = sum(WEIGHTS[row[0].lower()] for row in findings)
    score = max(0, 100 - penalty)
    counts = {level: sum(row[0].lower() == level for row in findings) for level in WEIGHTS}
    color = "#42e8a1" if score >= 80 else "#ffd166" if score >= 50 else "#ff7272"
    summary = f"""
    <div class="score-card">
      <div><span class="eyebrow">SECURITY SCORE</span><strong style="color:{color}">{score}<small>/100</small></strong></div>
      <div class="metrics"><b>{scanned}<span>files</span></b><b>{counts['critical']}<span>critical</span></b><b>{counts['high']}<span>high</span></b><b>{counts['medium']}<span>medium</span></b></div>
    </div>"""
    if not findings:
        summary += "<p>No matching issues found. This is not a guarantee of security.</p>"
    return summary, [[html.escape(cell) for cell in row] for row in findings]


CSS = """
body{background:radial-gradient(circle at 20% 0,#13243a 0,#090d14 42%)!important}.gradio-container{max-width:1050px!important}.hero{padding:38px 0 14px}.hero h1{font-size:clamp(40px,7vw,72px);line-height:.95;letter-spacing:-.055em;margin:12px 0}.hero h1 span{color:#42e8a1}.hero p{color:#a9b7c8;font-size:18px;max-width:720px}.score-card{display:flex;justify-content:space-between;align-items:center;padding:22px;border:1px solid #334155;border-radius:15px;background:#0c131f}.score-card strong{display:block;font-size:56px}.score-card small{font-size:18px}.eyebrow{color:#94a3b8}.metrics{display:flex;gap:26px}.metrics b{font-size:25px}.metrics span{display:block;color:#94a3b8;font-size:12px;font-weight:400}@media(max-width:650px){.score-card,.metrics{align-items:flex-start;flex-direction:column}.metrics{gap:8px}}
"""

with gr.Blocks(title="VibeSec Scanner", css=CSS, theme=gr.themes.Base(primary_hue="emerald", neutral_hue="slate")) as demo:
    gr.HTML("""<div class="hero"><small>SECURITY FOR AI-GENERATED CODE</small><h1>Ship fast.<br><span>Scan first.</span></h1><p>Upload an authorized source-code ZIP. VibeSec checks it for exposed secrets, injection risks, unsafe rendering and dangerous configuration.</p></div>""")
    upload = gr.File(label="Authorized source ZIP Â· maximum 10 MB", file_types=[".zip"], type="filepath")
    run = gr.Button("Run security scan", variant="primary")
    report = gr.HTML()
    table = gr.Dataframe(headers=["Severity", "Finding", "Location", "Rule", "Evidence", "Recommendation"], datatype=["str"] * 6, interactive=False, wrap=True)
    gr.Markdown("Only scan code you own or are authorized to assess. Files are deleted after processing. Static findings require human validation.")
    run.click(scan_zip, inputs=upload, outputs=[report, table])

if __name__ == "__main__":
    demo.launch()
