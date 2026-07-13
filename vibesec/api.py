from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import zipfile

from fastapi import FastAPI, File, HTTPException, UploadFile

from .scanner import scan_directory

app = FastAPI(title="VibeSec Scanner", version="0.1.0")
MAX_UPLOAD_BYTES = 10_000_000


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
