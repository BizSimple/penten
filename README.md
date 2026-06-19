# penten
Local CI Pentesting

## CLI

`penten_cli.py` is a localhost-only scanner for local CI pentesting workflows.

### Features
- Enforces `localhost`/`127.0.0.1` targets only
- Crawls internal paths with Playwright (never follows external links)
- Logs request/response network activity to `network.json`
- Profiles crawl runtime and coverage in the final report
- Exercises forms (including registration-like fields) and injection payloads
- Detects 5xx responses, possible private endpoint exposure, and suspicious reflection
- Runs `trufflehog` against collected artifacts
- Writes HTML page snapshots plus a final JSON report with findings and recommendations

## Getting Started: scan your localhost app

1. Start your local app (example: `http://localhost:3000`).
2. Install runtime dependencies:
   ```bash
   pip install playwright
   python -m playwright install chromium
   ```
3. (Optional but recommended) install `trufflehog` and make sure it is in your `PATH`.
4. Choose a provider and model.
   - Local Ollama example model: `llama3.1`
   - Hosted providers (DeepSeek / GLM / Gemini) require a token
5. For hosted providers, store your token once:
   ```bash
   python penten_cli.py configure --provider deepseek
   ```
6. Run a scan:
   ```bash
   python penten_cli.py scan \
     --url http://localhost:3000 \
     --provider ollama \
     --model llama3.1 \
     --max-pages 50 \
     --max-forms 20 \
     --max-payloads-per-path 3 \
     --output-dir ./scan-results
   ```
7. Review artifacts:
   - `scan-results/report.json` (summary/profile/findings)
   - `scan-results/network.json` (captured request/response events)
   - `scan-results/pages/` (HTML snapshots of visited pages)

## Commands

### `scan`
Run a localhost-only scan.

Required:
- `--url` target URL (must resolve to `localhost` or `127.0.0.1`)
- `--model` model name for the selected provider

Common options:
- `--provider` AI provider (`ollama`, `deepseek`, `glm`, `gemini`) (default: `ollama`)
- `--max-pages` maximum pages to crawl (default: `50`)
- `--max-forms` maximum forms to exercise (default: `20`)
- `--max-payloads-per-path` max injection payloads tested per discovered path
- `--timeout` per-page timeout in seconds (default: `12`)
- `--provider-url` provider API base URL override
- `--vault-file` provider token vault path (default: `~/.penten/vault.json`)
- `--ignore-https-errors` ignore local HTTPS certificate errors
- `--output-dir` output directory (default: `penten-report-<timestamp>`)
- `--show-browser` run with visible browser window

### `configure`
Store provider credentials in the vault.

- `--provider` one of `ollama`, `deepseek`, `glm`, `gemini`
- `--vault-file` provider token vault path (default: `~/.penten/vault.json`)

### `navigate`
Let the AI model autonomously drive the browser to explore and probe the local site.

In this mode the script runs an agentic loop: Playwright navigates the current page and
captures its HTML structure, browser console messages, and network activity.  That context
is sent to the AI model, which responds with a JSON action object (see below).  The script
executes the action and feeds the result back to the model, repeating until the model
signals it is done or `--max-steps` is reached.

Available AI actions:

| Action | Effect |
|---|---|
| `{"action":"navigate","url":"<url>"}` | Navigate to a URL (local only) |
| `{"action":"click","selector":"<css>"}` | Click an element by CSS selector |
| `{"action":"click_text","text":"<text>"}` | Click a visible element by text |
| `{"action":"fill","selector":"<css>","value":"<val>"}` | Fill a form field |
| `{"action":"report_finding","category":"<slug>","severity":"high\|medium\|low","detail":"<desc>"}` | Record a security finding |
| `{"action":"done","summary":"<text>"}` | Signal exploration is complete |

Example:
```bash
python penten_cli.py navigate \
  --url http://localhost:3000 \
  --provider ollama \
  --model llama3.1 \
  --max-steps 20 \
  --output-dir ./navigate-results
```

Required:
- `--url` target URL (must resolve to `localhost` or `127.0.0.1`)
- `--model` model name for the selected provider

Options:
- `--provider` AI provider (`ollama`, `deepseek`, `glm`, `gemini`) (default: `ollama`)
- `--max-steps` maximum AI navigation steps (default: `20`)
- `--timeout` per-page timeout in seconds (default: `12`)
- `--provider-url` provider API base URL override
- `--vault-file` provider token vault path (default: `~/.penten/vault.json`)
- `--ignore-https-errors` ignore local HTTPS certificate errors
- `--output-dir` output directory (default: `penten-navigate-<timestamp>`)
- `--show-browser` run with visible browser window

## Provider details

- **Ollama** (`--provider ollama`): default URL `http://127.0.0.1:11434`
  - Optional env vars: `OLLAMA_URL` (preferred) or `OLLAMA_API_URL`
  - Optional override per run: `--provider-url`
- **DeepSeek** (`--provider deepseek`): model via `/chat/completions`
  - API key via `python penten_cli.py configure --provider deepseek`
  - Env var override: `DEEPSEEK_API_KEY`
  - Vault file default: `~/.penten/vault.json` (override with `--vault-file`)
  - Optional base URL override via `--provider-url` or `DEEPSEEK_API_URL`
- **GLM / z.ai** (`--provider glm`): model via `/chat/completions`
  - API key via `python penten_cli.py configure --provider glm`
  - Env var override: `GLM_API_KEY` (or `ZAI_API_KEY`)
  - Vault file default: `~/.penten/vault.json` (override with `--vault-file`)
  - Optional base URL override via `--provider-url` or `GLM_API_URL`
- **Gemini** (`--provider gemini`): model via `:generateContent`
  - API key via `python penten_cli.py configure --provider gemini`
  - Env var override: `GEMINI_API_KEY`
  - Vault file default: `~/.penten/vault.json` (override with `--vault-file`)
  - Optional base URL override via `--provider-url` or `GEMINI_API_URL`

## Requirements
- Python 3.11+
- `playwright` installed and Chromium runtime available
- `trufflehog` available in PATH (optional but recommended)
