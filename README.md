# VibeSec Scanner

Security scanner for web applications created with AI coding tools.

VibeSec performs deterministic, local source-code checks and produces an actionable report. It does **not** attack websites or send source code to an AI provider.

## Current checks

- Exposed API keys and private keys
- Exposed AWS access key IDs and secret access keys
- Dangerous command execution
- Potential SQL injection
- Unsafe HTML rendering / DOM XSS
- Permissive CORS
- Weak JWT secrets
- Debug mode enabled

## Quick start

```bash
python -m vibesec.cli scan ./my-project --format json
```

Run the API:

```bash
pip install -e .
uvicorn vibesec.api:app --host 0.0.0.0 --port 7860
```

Open `http://localhost:7860` to use the web interface.

Then send an authorized source archive:

```bash
curl -F "file=@project.zip" http://localhost:7860/scan
```

## Example

Scanning a small Flask app with a hard-coded token, SQL built from user input, a shell call and debug mode:

```bash
python -m vibesec.cli scan ./demo
```

```json
{
  "scanner": "VibeSec",
  "score": 48,
  "files_scanned": 1,
  "summary": { "critical": 0, "high": 3, "medium": 1, "low": 0 },
  "findings": [
    {
      "rule_id": "SEC002",
      "title": "Likely API token committed",
      "severity": "high",
      "file": "app.py",
      "line": 4,
      "evidence": "OPENAI_API_KEY = \"sk-p****3456\"",
      "recommendation": "Revoke the token and inject it through environment variables or a secret manager."
    },
    {
      "rule_id": "INJ002",
      "title": "Potential SQL string interpolation",
      "severity": "high",
      "file": "app.py",
      "line": 7,
      "recommendation": "Use parameterized queries; never concatenate user-controlled values into SQL."
    }
  ]
}
```

Secrets are masked in the report (`sk-p****3456`), so reports can be shared safely.

## Running the tests

```bash
pip install -e . pytest
python -m pytest -q
```

## Safety

Only scan code you own or are explicitly authorized to assess. Findings are leads for validation, not proof that a vulnerability is exploitable.

## License

Apache-2.0
