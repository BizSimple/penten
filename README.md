# penten
Local CI Pentesting

## CLI

`penten_cli.py` is a localhost-only scanner for local CI pentesting workflows.

### Features
- Enforces `localhost`/`127.0.0.1` targets only
- Crawls internal paths with Playwright (never follows external links)
- Logs all request/response network activity
- Profiles crawl runtime and coverage
- Exercises forms (including registration-like fields) and injection payloads
- Detects 5xx responses, possible private endpoint exposure, and suspicious reflection
- Runs `trufflehog` against collected artifacts
- Writes a final JSON report with findings and recommendations

### Usage
```bash
python penten_cli.py \
  --url http://localhost:3000 \
  --model llama3.1 \
  --max-pages 50 \
  --ollama-url http://127.0.0.1:11434 \
  --output-dir ./scan-results
```

### Requirements
- Python 3.11+
- `playwright` installed and browser runtime available
- `trufflehog` available in PATH (optional but recommended)
- Local Ollama API on `http://127.0.0.1:11434`
