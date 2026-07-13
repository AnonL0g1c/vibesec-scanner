# VibeSec Scanner

Security scanner for web applications created with AI coding tools.

VibeSec performs deterministic, local source-code checks and produces an actionable report. It does **not** attack websites or send source code to an AI provider.

## Current checks

- Exposed API keys and private keys
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

Then send an authorized source archive:

```bash
curl -F "file=@project.zip" http://localhost:7860/scan
```

## Safety

Only scan code you own or are explicitly authorized to assess. Findings are leads for validation, not proof that a vulnerability is exploitable.

## License

Apache-2.0
