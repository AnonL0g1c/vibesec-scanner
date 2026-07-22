from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import zipfile

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse

from .scanner import scan_directory

app = FastAPI(title="VibeSec Scanner", version="0.1.0")
MAX_UPLOAD_BYTES = 10_000_000

LANDING_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>VibeSec Scanner</title>
  <style>
    :root { color-scheme: dark; --bg:#090d14; --card:#111827; --line:#273244; --green:#42e8a1; --text:#edf3fa; --muted:#94a3b8; }
    * { box-sizing:border-box } body { margin:0; background:radial-gradient(circle at 20% 0,#13243a 0,var(--bg) 42%); color:var(--text); font:16px system-ui,sans-serif }
    main { max-width:920px; margin:auto; padding:64px 20px } h1 { font-size:clamp(38px,7vw,68px); margin:0; letter-spacing:-.05em } h1 span { color:var(--green) }
    .lead { color:var(--muted); font-size:19px; max-width:650px; line-height:1.55 }
    .card { margin-top:34px; padding:28px; border:1px solid var(--line); border-radius:18px; background:rgba(17,24,39,.88); box-shadow:0 22px 80px #0008 }
    .drop { display:block; padding:36px; text-align:center; border:1px dashed #4b607c; border-radius:14px; cursor:pointer } input { display:none }
    button { margin-top:18px; width:100%; padding:15px; border:0; border-radius:10px; background:var(--green); color:#052116; font-weight:800; cursor:pointer }
    button:disabled { opacity:.45; cursor:wait } #status { color:var(--muted); margin-top:14px }
    #result { display:none; margin-top:30px } .score { font-size:52px; font-weight:900 } .grid { display:grid; grid-template-columns:repeat(4,1fr); gap:10px }
    .metric,.finding { padding:15px; border:1px solid var(--line); border-radius:10px; background:#0c131f } .metric b { display:block; font-size:22px }
    .finding { margin-top:12px } .finding h3 { margin:0 0 6px } .finding p { margin:6px 0; color:var(--muted) } code { color:#f0b4b4; overflow-wrap:anywhere }
    .critical,.high { color:#ff7272 } .medium { color:#ffd166 } .low { color:#71b7ff }
    footer { margin-top:28px; color:var(--muted); font-size:13px } @media(max-width:600px){.grid{grid-template-columns:1fr 1fr}}
  </style>
</head>
<body><main>
  <p>SECURITY FOR AI-GENERATED CODE</p>
  <h1>Ship fast.<br><span>Scan first.</span></h1>
  <p class="lead">Upload an authorized source-code ZIP. VibeSec checks it locally for exposed secrets, injection risks, unsafe rendering and dangerous configuration.</p>
  <section class="card">
    <label class="drop" for="file"><strong id="filename">Choose a .zip project</strong><br><small>Maximum 10 MB &middot; source code only</small></label>
    <input id="file" type="file" accept=".zip">
    <button id="scan" disabled>Run security scan</button><div id="status"></div>
    <div id="result"><div class="score" id="score"></div><div class="grid" id="summary"></div><div id="findings"></div></div>
  </section>
  <footer>Only scan code you own or are authorized to assess. Static findings require human validation. Uploaded files are deleted after processing.</footer>
</main><script>
const file=document.querySelector('#file'), button=document.querySelector('#scan'), status=document.querySelector('#status'), result=document.querySelector('#result');
file.onchange=()=>{document.querySelector('#filename').textContent=file.files[0]?.name||'Choose a .zip project';button.disabled=!file.files.length};
button.onclick=async()=>{button.disabled=true;result.style.display='none';status.textContent='Scanning\u2026';const body=new FormData();body.append('file',file.files[0]);
try{const response=await fetch('/scan',{method:'POST',body});const data=await response.json();if(!response.ok)throw new Error(data.detail||'Scan failed');
document.querySelector('#score').textContent=data.score+'/100';document.querySelector('#summary').innerHTML=Object.entries(data.summary).map(([k,v])=>`<div class="metric ${k}"><b>${v}</b>${k}</div>`).join('');
document.querySelector('#findings').innerHTML=data.findings.length?data.findings.map(f=>`<article class="finding"><h3 class="${f.severity}">${f.severity.toUpperCase()} &middot; ${f.title}</h3><p>${f.file}:${f.line} &middot; ${f.rule_id}</p><code>${escapeHtml(f.evidence)}</code><p>${f.recommendation}</p></article>`).join(''):'<p>No matching issues found. This is not a guarantee of security.</p>';
result.style.display='block';status.textContent=`${data.files_scanned} files scanned`;}
catch(error){status.textContent=error.message}finally{button.disabled=false}};
function escapeHtml(value){const e=document.createElement('div');e.textContent=value;return e.innerHTML}
</script></body></html>"""


def safe_extract(archive: zipfile.ZipFile, destination: Path) -> None:
    for member in archive.infolist():
        target = (destination / member.filename).resolve()
        if destination.resolve() not in target.parents and target != destination.resolve():
            raise ValueError("Unsafe archive path")
        if member.file_size > MAX_UPLOAD_BYTES:
            raise ValueError("Archive member is too large")
    archive.extractall(destination)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "vibesec", "version": "0.1.0"}


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    return LANDING_PAGE


@app.post("/scan")
def scan(file: UploadFile = File(...)) -> dict:
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(400, "Upload a .zip source archive")
    with tempfile.TemporaryDirectory(prefix="vibesec-") as tmp:
        archive_path = Path(tmp) / "source.zip"
        with archive_path.open("wb") as output:
            shutil.copyfileobj(file.file, output, length=1024 * 1024)
        if archive_path.stat().st_size > MAX_UPLOAD_BYTES:
            raise HTTPException(413, "Archive exceeds 10 MB")
        source = Path(tmp) / "source"
        source.mkdir()
        try:
            with zipfile.ZipFile(archive_path) as archive:
                safe_extract(archive, source)
        except (zipfile.BadZipFile, ValueError) as exc:
            raise HTTPException(400, str(exc)) from exc
        return scan_directory(source)
