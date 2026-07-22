from pathlib import Path

from vibesec.scanner import scan_directory


def test_detects_multiple_web_risks(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const api_key = 'abcdefghijklmnopqrstuvwxyz123456';\n"
        "element.innerHTML = userInput;\n"
        "const jwt_secret = 'changeme';\n",
        encoding="utf-8",
    )
    report = scan_directory(tmp_path)
    ids = {finding["rule_id"] for finding in report["findings"]}
    assert {"SEC002", "XSS001", "AUTH001"} <= ids
    assert report["score"] < 100
    assert report["files_scanned"] == 1


def test_ignores_dependency_directories(tmp_path: Path) -> None:
    dependency = tmp_path / "node_modules" / "package"
    dependency.mkdir(parents=True)
    (dependency / "bad.js").write_text("element.innerHTML = input", encoding="utf-8")
    report = scan_directory(tmp_path)
    assert report["files_scanned"] == 0
    assert report["findings"] == []


def test_detects_aws_credentials(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        encoding="utf-8",
    )
    report = scan_directory(tmp_path)
    ids = {finding["rule_id"] for finding in report["findings"]}
    assert {"AWS001", "AWS002"} <= ids
    evidence = "\n".join(finding["evidence"] for finding in report["findings"])
    assert "AKIAIOSFODNN7EXAMPLE" not in evidence
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in evidence
    assert "AKIA****MPLE" in evidence
    assert "wJal****EKEY" in evidence


def test_does_not_flag_aws_placeholders(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "AWS_ACCESS_KEY_ID=your_access_key_here\n"
        "AWS_SECRET_ACCESS_KEY=your_secret_key_here\n",
        encoding="utf-8",
    )
    report = scan_directory(tmp_path)
    assert not {"AWS001", "AWS002"} & {
        finding["rule_id"] for finding in report["findings"]
    }
