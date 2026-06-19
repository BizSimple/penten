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
  --provider ollama \
  --model llama3.1 \
  --max-pages 50 \
  --max-payloads-per-path 3 \
  --ollama-url http://127.0.0.1:11434 \
  --output-dir ./scan-results
```

### Requirements
- Python 3.11+
- `playwright` installed and browser runtime available
- `trufflehog` available in PATH (optional but recommended)
- AI payload provider:
  - **Ollama** (`--provider ollama`): local API on `http://127.0.0.1:11434`
    - Optional env vars: `OLLAMA_URL` (preferred) or `OLLAMA_API_URL`
  - **DeepSeek** (`--provider deepseek`): model via `/chat/completions`
    - API key via `--api-key` or `DEEPSEEK_API_KEY`
    - Optional base URL override via `--provider-url` or `DEEPSEEK_API_URL`
  - **GLM / z.ai** (`--provider glm`): model via `/chat/completions`
    - API key via `--api-key` or `GLM_API_KEY` (or `ZAI_API_KEY`)
    - Optional base URL override via `--provider-url` or `GLM_API_URL`
  - **Gemini** (`--provider gemini`): model via `:generateContent`
    - API key via `--api-key` or `GEMINI_API_KEY`
    - Optional base URL override via `--provider-url` or `GEMINI_API_URL`
