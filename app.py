from __future__ import annotations

from pathlib import Path
import html
import stat
import tempfile
import zipfile

import gradio as gr

from vibesec.scanner import MAX_FILE_BYTES, scan_directory

MAX_ARCHIVE_BYTES = 10_000_000
def safe_extract(archive: zipfile.ZipFile, destination: Path) -> None:
    total = 0
    for member in archive.infolist():
        total += member.file_size
        target = (destination / member.filename).resolve()
        if destination.resolve() not in target.parents and target != destination.resolve():
            raise ValueError("Unsafe path detected inside ZIP")
        if member.file_size > MAX_FILE_BYTES or total > 30_000_000:
            raise ValueError("Expanded archive exceeds safety limits")
        mode = member.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise ValueError("Symbolic links are not allowed inside ZIP files")
    archive.extractall(destination)


def scan_zip(uploaded_file: str | None) -> tuple[str, list[list[str]]]:
    if not uploaded_file:
        raise gr.Error("Choose a ZIP project first.")
    archive_path = Path(uploaded_file)
    if archive_path.suffix.lower() != ".zip" or archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise gr.Error("Upload a valid ZIP no larger than 10 MB.")

    with tempfile.TemporaryDirectory(prefix="vibesec-") as tmp:
        root = Path(tmp)
        try:
            with zipfile.ZipFile(archive_path) as archive:
                safe_extract(archive, root)
        except (zipfile.BadZipFile, ValueError) as exc:
            raise gr.Error(str(exc)) from exc

        result = scan_directory(root)

    findings = [
        [
            item["severity"].upper(),
            item["title"],
            f'{item["file"]}:{item["line"]}',
            item["rule_id"],
            item["evidence"],
            item["recommendation"],
        ]
        for item in result["findings"]
    ]
    score = result["score"]
    counts = result["summary"]
    scanned = result["files_scanned"]
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
    upload = gr.File(label="Authorized source ZIP · maximum 10 MB", file_types=[".zip"], type="filepath")
    run = gr.Button("Run security scan", variant="primary")
    report = gr.HTML()
    table = gr.Dataframe(headers=["Severity", "Finding", "Location", "Rule", "Evidence", "Recommendation"], datatype=["str"] * 6, interactive=False, wrap=True)
    gr.Markdown("Only scan code you own or are authorized to assess. Files are deleted after processing. Static findings require human validation.")
    run.click(scan_zip, inputs=upload, outputs=[report, table])

if __name__ == "__main__":
    demo.launch()
