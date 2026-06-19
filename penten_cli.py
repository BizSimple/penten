#!/usr/bin/env python3
import argparse
import asyncio
import getpass
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

try:
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError
    from playwright.async_api import async_playwright
except ImportError:  # pragma: no cover - exercised only without playwright installed
    PlaywrightTimeoutError = TimeoutError
    async_playwright = None


LOCAL_HOSTS = {"localhost", "127.0.0.1"}
SENSITIVE_PATH_PATTERN = re.compile(r"/(admin|internal|private|debug)", flags=re.I)
MAX_PAYLOADS_PER_PATH = 3
AI_PATH_CONTEXT_LIMIT = 30
AI_TIMEOUT_SECONDS = 30
SUPPORTED_PROVIDERS = ("ollama", "deepseek", "glm", "gemini")
SUPPORTED_COMMANDS = ("scan", "configure", "navigate")
AI_NAVIGATE_MAX_STEPS = 20
AI_NAVIGATE_CONSOLE_LIMIT = 20
AI_NAVIGATE_NETWORK_LIMIT = 20
AI_NAVIGATE_SUMMARY_LINKS = 30
AI_NAVIGATE_SYSTEM_PROMPT = (
    "You are an autonomous web security tester driving a browser. "
    "At each step you receive the current page state (URL, structural summary, "
    "console logs, recent network activity) and must respond with exactly one "
    "JSON action object — no markdown fences, no extra text. "
    "Available actions:\n"
    '  {"action":"navigate","url":"<url>"}\n'
    '  {"action":"click","selector":"<css-selector>"}\n'
    '  {"action":"click_text","text":"<visible-button-or-link-text>"}\n'
    '  {"action":"fill","selector":"<css-selector>","value":"<value>"}\n'
    '  {"action":"report_finding","category":"<slug>","severity":"high|medium|low","detail":"<description>"}\n'
    '  {"action":"done","summary":"<exploration-summary>"}\n'
    "Focus on: discovering hidden/sensitive paths, unprotected admin panels, "
    "authentication bypass, reflected/stored injection vulnerabilities, and "
    "exposed private data. Stay within the local target host only."
)
DEFAULT_PROVIDER_URLS = {
    "ollama": "http://127.0.0.1:11434",
    "deepseek": "https://api.deepseek.com",
    "glm": "https://open.bigmodel.cn/api/paas/v4",
    "gemini": "https://generativelanguage.googleapis.com",
}
DEFAULT_VAULT_FILE = str(Path.home() / ".penten" / "vault.json")
EXIT_SUCCESS = 0
EXIT_INVALID_INPUT = 2
EXIT_INTERRUPTED = 130
DEFAULT_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "${7*7}",
    "\" onmouseover=\"alert(1)",
]


@dataclass
class Finding:
    category: str
    severity: str
    url: str
    detail: str


@dataclass
class NetworkOperation:
    event: str
    method: str
    url: str
    status: int | None
    resource_type: str
    timestamp: float


class LinkAndFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = dict(attrs)
        if tag == "a":
            href = attr_map.get("href")
            if href:
                self.links.append(href)
        if tag == "form":
            self._current_form = {
                "action": attr_map.get("action", ""),
                "method": (attr_map.get("method") or "get").lower(),
                "fields": [],
            }
            self.forms.append(self._current_form)
        if tag in {"input", "textarea", "select"} and self._current_form is not None:
            field_name = attr_map.get("name")
            field_type = (attr_map.get("type") or "text").lower()
            if field_name:
                self._current_form["fields"].append({"name": field_name, "type": field_type})


def validate_local_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("URL must use http or https.")
    if not parsed.hostname or parsed.hostname.lower() not in LOCAL_HOSTS:
        raise ValueError("URL host must be localhost or 127.0.0.1.")
    if parsed.fragment:
        parsed = parsed._replace(fragment="")
    normalized = urllib.parse.urlunparse(parsed)
    return normalized


def is_internal_url(base_host: str, candidate_url: str) -> bool:
    parsed = urllib.parse.urlparse(candidate_url)
    if not parsed.hostname:
        return True
    host = parsed.hostname.lower()
    base = base_host.lower()
    if host == base:
        return True
    return host in LOCAL_HOSTS and base in LOCAL_HOSTS


def path_from_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return parsed.path or "/"


def build_registration_value(field_name: str, field_type: str, index: int, injected: bool, payload: str) -> str:
    lower_name = field_name.lower()
    name_tokens = {token for token in re.split(r"[^a-z0-9]+", lower_name) if token}
    if injected and field_type not in {"email", "password", "hidden"}:
        return payload
    if "mail" in lower_name or field_type == "email":
        return f"penten{index}@example.com"
    if "pass" in lower_name or field_type == "password":
        return "StrongPass123!"
    if {"user", "username", "name", "fullname"} & name_tokens:
        return f"penten_user_{index}"
    if field_type in {"checkbox", "radio"}:
        return "on"
    return f"value_{index}"


def _extract_json_payloads(content: str) -> list[str]:
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        return []
    if isinstance(parsed, list):
        return [str(item) for item in parsed if isinstance(item, str)]
    if isinstance(parsed, dict):
        for key in ("payloads", "data", "items"):
            value = parsed.get(key)
            if isinstance(value, list):
                return [str(item) for item in value if isinstance(item, str)]
    return []


def _request_payload_generation(
    url: str,
    body: dict[str, Any],
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=AI_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


def generate_ai_payloads(
    provider: str,
    model: str,
    discovered_paths: list[str],
    provider_url: str,
    api_key: str,
) -> list[str]:
    provider_name = provider.lower().strip()
    payload_prompt = (
        "Return 5 web security injection payloads as a JSON array of strings. "
        "Prioritize SQLi, XSS, SSTI and path traversal. Paths observed: "
        f"{', '.join(discovered_paths[:AI_PATH_CONTEXT_LIMIT])}"
    )
    try:
        if provider_name == "ollama":
            response = _request_payload_generation(
                provider_url.rstrip("/") + "/api/generate",
                {"model": model, "prompt": payload_prompt, "stream": False, "format": "json"},
            )
            return _extract_json_payloads(str(response.get("response", "")))
        if provider_name in {"deepseek", "glm"}:
            if not api_key:
                print(f"Warning: missing API key for {provider_name}. Using default payloads.")
                return []
            response = _request_payload_generation(
                provider_url.rstrip("/") + "/chat/completions",
                {
                    "model": model,
                    "messages": [
                        {
                            "role": "system",
                            "content": "Return only a JSON array of 5 web security injection payload strings.",
                        },
                        {"role": "user", "content": payload_prompt},
                    ],
                    "temperature": 0.2,
                },
                headers={"Authorization": "Bearer " + api_key},
            )
            choices = response.get("choices")
            if isinstance(choices, list) and choices:
                message = choices[0].get("message", {})
                return _extract_json_payloads(str(message.get("content", "")))
            return []
        if provider_name == "gemini":
            if not api_key:
                print("Warning: missing API key for gemini. Using default payloads.")
                return []
            response = _request_payload_generation(
                (
                    provider_url.rstrip("/")
                    + f"/v1beta/models/{urllib.parse.quote(model, safe='')}:generateContent"
                    + f"?key={urllib.parse.quote(api_key)}"
                ),
                {
                    "contents": [{"parts": [{"text": payload_prompt}]}],
                    "generationConfig": {"responseMimeType": "application/json"},
                },
            )
            candidates = response.get("candidates")
            if isinstance(candidates, list) and candidates:
                content = candidates[0].get("content", {})
                parts = content.get("parts", [])
                if isinstance(parts, list) and parts:
                    return _extract_json_payloads(str(parts[0].get("text", "")))
            return []
        print(f"Warning: unsupported provider '{provider_name}'. Using default payloads.")
        return []
    except (urllib.error.URLError, TimeoutError) as error:
        print(f"Warning: failed to query {provider_name} for payloads ({error}). Using default payloads.")
        return []
    except (json.JSONDecodeError, TypeError, ValueError, KeyError):
        return []


def summarize_page_for_ai(
    url: str,
    html: str,
    console_logs: list[str],
    network_ops: list[NetworkOperation],
) -> str:
    """Return a concise structural summary of a page suitable for AI context."""
    parser = LinkAndFormParser()
    parser.feed(html)

    title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    title = re.sub(r"<[^>]+>", "", title_match.group(1)).strip() if title_match else "(no title)"

    heading_tags = re.findall(r"<h[1-3][^>]*>(.*?)</h[1-3]>", html, re.I | re.S)
    headings = [re.sub(r"<[^>]+>", "", h).strip() for h in heading_tags[:8] if h.strip()]

    lines: list[str] = [f"URL: {url}", f"Title: {title}"]
    if headings:
        lines.append("Headings: " + " | ".join(headings))
    if parser.links:
        shown = parser.links[:AI_NAVIGATE_SUMMARY_LINKS]
        lines.append(
            f"Links ({len(parser.links)} total, showing {len(shown)}): "
            + ", ".join(shown)
        )
    for i, form in enumerate(parser.forms, start=1):
        field_names = [f["name"] for f in form.get("fields", [])]
        lines.append(
            f"Form {i}: {form['method'].upper()} {form['action'] or '(current)'}"
            f" fields=[{', '.join(field_names)}]"
        )
    if console_logs:
        recent = console_logs[-AI_NAVIGATE_CONSOLE_LIMIT:]
        lines.append("Console: " + "; ".join(recent))
    if network_ops:
        recent_net = network_ops[-AI_NAVIGATE_NETWORK_LIMIT:]
        net_lines = [
            f"{op.method} {op.url} -> {op.status or '?'}" for op in recent_net
        ]
        lines.append("Network: " + "; ".join(net_lines))
    return "\n".join(lines)


def _parse_navigation_action(text: str) -> dict[str, Any] | None:
    """Extract the first JSON action object from AI response text."""
    text = text.strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and "action" in obj:
            return obj
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{[^{}]*\"action\"[^{}]*\}", text, re.S)
    if match:
        try:
            obj = json.loads(match.group())
            if isinstance(obj, dict) and "action" in obj:
                return obj
        except json.JSONDecodeError:
            pass
    return None


def request_ai_navigation_action(
    provider: str,
    model: str,
    provider_url: str,
    api_key: str,
    messages: list[dict[str, Any]],
) -> str | None:
    """Send a multi-turn conversation to the AI provider and return the response text."""
    provider_name = provider.lower().strip()
    try:
        if provider_name == "ollama":
            response = _request_payload_generation(
                provider_url.rstrip("/") + "/api/chat",
                {"model": model, "messages": messages, "stream": False},
            )
            msg = response.get("message")
            if isinstance(msg, dict):
                return str(msg.get("content", ""))
            return str(response.get("response", ""))

        if provider_name in {"deepseek", "glm"}:
            if not api_key:
                print(f"Warning: missing API key for {provider_name}. Cannot navigate.")
                return None
            response = _request_payload_generation(
                provider_url.rstrip("/") + "/chat/completions",
                {"model": model, "messages": messages, "temperature": 0.3},
                headers={"Authorization": "Bearer " + api_key},
            )
            choices = response.get("choices")
            if isinstance(choices, list) and choices:
                return str(choices[0].get("message", {}).get("content", ""))
            return None

        if provider_name == "gemini":
            if not api_key:
                print("Warning: missing API key for gemini. Cannot navigate.")
                return None
            system_content = next(
                (m["content"] for m in messages if m.get("role") == "system"), ""
            )
            gemini_contents = [
                {
                    "role": "user" if m["role"] == "user" else "model",
                    "parts": [{"text": m["content"]}],
                }
                for m in messages
                if m.get("role") != "system"
            ]
            body: dict[str, Any] = {"contents": gemini_contents}
            if system_content:
                body["systemInstruction"] = {"parts": [{"text": system_content}]}
            response = _request_payload_generation(
                (
                    provider_url.rstrip("/")
                    + f"/v1beta/models/{urllib.parse.quote(model, safe='')}:generateContent"
                    + f"?key={urllib.parse.quote(api_key)}"
                ),
                body,
            )
            candidates = response.get("candidates")
            if isinstance(candidates, list) and candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if isinstance(parts, list) and parts:
                    return str(parts[0].get("text", ""))
            return None

        print(f"Warning: unsupported provider '{provider_name}'. Cannot navigate.")
        return None
    except (urllib.error.URLError, TimeoutError) as error:
        print(f"Warning: AI navigation request failed ({error}).")
        return None
    except (json.JSONDecodeError, TypeError, ValueError, KeyError):
        return None


def resolve_provider_url(provider: str, provider_url: str) -> str:
    if provider_url:
        return provider_url
    provider_name = provider.lower().strip()
    if provider_name == "ollama":
        return os.getenv("OLLAMA_URL", os.getenv("OLLAMA_API_URL", DEFAULT_PROVIDER_URLS["ollama"]))
    if provider_name == "deepseek":
        return os.getenv("DEEPSEEK_API_URL", DEFAULT_PROVIDER_URLS["deepseek"])
    if provider_name == "glm":
        return os.getenv("GLM_API_URL", DEFAULT_PROVIDER_URLS["glm"])
    if provider_name == "gemini":
        return os.getenv("GEMINI_API_URL", DEFAULT_PROVIDER_URLS["gemini"])
    return DEFAULT_PROVIDER_URLS["ollama"]


def load_vault(vault_file: str) -> dict[str, Any]:
    vault_path = Path(vault_file).expanduser()
    if not vault_path.exists():
        return {}
    try:
        content = json.loads(vault_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return content if isinstance(content, dict) else {}


def save_vault(vault_file: str, content: dict[str, Any]) -> None:
    vault_path = Path(vault_file).expanduser()
    vault_path.parent.mkdir(parents=True, exist_ok=True)
    vault_path.write_text(json.dumps(content, indent=2), encoding="utf-8")
    try:
        os.chmod(vault_path, 0o600)
    except OSError:
        pass


def resolve_provider_api_key(provider: str, vault_file: str) -> str:
    provider_name = provider.lower().strip()
    if provider_name == "deepseek":
        return os.getenv("DEEPSEEK_API_KEY", _vault_api_key(provider_name, vault_file))
    if provider_name == "glm":
        glm_api_key = os.getenv("GLM_API_KEY")
        if glm_api_key:
            return glm_api_key
        zai_api_key = os.getenv("ZAI_API_KEY")
        if zai_api_key:
            return zai_api_key
        return _vault_api_key(provider_name, vault_file)
    if provider_name == "gemini":
        return os.getenv("GEMINI_API_KEY", _vault_api_key(provider_name, vault_file))
    return ""


def _vault_api_key(provider: str, vault_file: str) -> str:
    vault = load_vault(vault_file)
    providers = vault.get("providers")
    if not isinstance(providers, dict):
        return ""
    provider_entry = providers.get(provider)
    if not isinstance(provider_entry, dict):
        return ""
    api_key = provider_entry.get("api_key")
    return str(api_key) if isinstance(api_key, str) else ""


def configure_provider(provider: str, vault_file: str) -> int:
    provider_name = provider.lower().strip()
    if provider_name == "ollama":
        print("Ollama configuration does not require a token.")
        return EXIT_SUCCESS
    raw_api_key = getpass.getpass(f"Enter API token for provider '{provider_name}': ")
    if not raw_api_key.strip():
        print("Error: API token cannot be empty.")
        return EXIT_INVALID_INPUT
    vault = load_vault(vault_file)
    providers = vault.get("providers")
    if not isinstance(providers, dict):
        providers = {}
        vault["providers"] = providers
    provider_entry = providers.get(provider_name)
    if not isinstance(provider_entry, dict):
        provider_entry = {}
        providers[provider_name] = provider_entry
    provider_entry["api_key"] = raw_api_key
    save_vault(vault_file, vault)
    print(f"Saved token for provider '{provider_name}' in {Path(vault_file).expanduser()}.")
    return EXIT_SUCCESS


def run_trufflehog_scan(scan_dir: Path) -> list[dict[str, Any]]:
    # Try both command syntaxes for compatibility across trufflehog versions.
    commands = [
        ["trufflehog", "filesystem", "--json", str(scan_dir)],
        ["trufflehog", "filesystem", str(scan_dir), "--json"],
    ]
    for command in commands:
        print(f"[secrets] Trying: {' '.join(command)}")
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            print("[secrets] trufflehog not found in PATH — skipping secret scan.")
            return [{"error": "trufflehog command was not found in PATH."}]
        if completed.returncode not in {0, 1}:
            print(f"[secrets] Command exited with code {completed.returncode}, trying next syntax ...")
            continue
        findings: list[dict[str, Any]] = []
        for line in completed.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                findings.append({"raw": line})
        print(f"[secrets] trufflehog reported {len(findings)} finding(s).")
        return findings
    return [{"error": "Unable to run trufflehog with supported command syntax."}]


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    deduplicated: list[Finding] = []
    for finding in findings:
        key = (finding.category, finding.url, finding.detail)
        if key not in seen:
            seen.add(key)
            deduplicated.append(finding)
    return deduplicated


def deduplicate_strings(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


async def fill_and_submit_form(
    context: Any,
    origin_url: str,
    form: dict[str, Any],
    payloads: list[str],
    findings: list[Finding],
) -> None:
    fields = form.get("fields", [])
    if not fields:
        return
    action_url = urllib.parse.urljoin(origin_url, form.get("action") or origin_url)
    if urllib.parse.urlparse(action_url).hostname not in LOCAL_HOSTS:
        return

    for injected in (False, True):
        page = await context.new_page()
        mode = "injected" if injected else "normal"
        print(f"[form]  {mode} submission -> {origin_url} ({len(fields)} field(s))")
        try:
            await page.goto(origin_url, wait_until="domcontentloaded", timeout=10_000)
            payload = payloads[0] if payloads else DEFAULT_INJECTION_PAYLOADS[0]
            for index, field in enumerate(fields):
                field_name = field["name"]
                selector = f'[name="{field_name}"]'
                locator = page.locator(selector).first
                value = build_registration_value(
                    field_name=field_name,
                    field_type=field.get("type", "text"),
                    index=index,
                    injected=injected,
                    payload=payload,
                )
                field_type = field.get("type", "text").lower()
                if field_type in {"checkbox", "radio"}:
                    await locator.check(timeout=2_000)
                else:
                    await locator.fill(value, timeout=2_000)

            submit_locators = [
                page.locator("button[type='submit']").first,
                page.locator("input[type='submit']").first,
            ]
            submitted = False
            for submit_locator in submit_locators:
                if await submit_locator.count():
                    await submit_locator.click(timeout=2_000)
                    submitted = True
                    break
            if not submitted:
                await page.keyboard.press("Enter")
            await page.wait_for_timeout(1_000)
            content = await page.content()
            if injected and any(p in content for p in payloads):
                findings.append(
                    Finding(
                        category="reflected_input",
                        severity="medium",
                        url=origin_url,
                        detail="Injected payload appears reflected in form response.",
                    )
                )
                print(f"  [!] MEDIUM reflected_input: payload reflected in form response on {origin_url}")
        except PlaywrightTimeoutError:
            findings.append(
                Finding(
                    category="form_timeout",
                    severity="low",
                    url=origin_url,
                    detail="Timeout while filling or submitting form.",
                )
            )
            print(f"  [!] LOW form_timeout: {origin_url}")
        finally:
            await page.close()


async def execute_navigation_action(
    page: Any,
    action: dict[str, Any],
    start_host: str,
    findings: list[Finding],
) -> tuple[bool, str]:
    """Execute one AI-chosen navigation action via Playwright.

    Returns ``(is_done, result_message)`` where *is_done* signals the AI has
    finished its exploration.
    """
    action_name = action.get("action", "")

    if action_name == "done":
        summary = action.get("summary", "Exploration complete.")
        return True, f"[ai-nav] done: {summary}"

    if action_name == "navigate":
        url = str(action.get("url", ""))
        if not url:
            return False, "[ai-nav] navigate: missing url"
        parsed = urllib.parse.urlparse(url)
        if parsed.hostname and parsed.hostname.lower() not in LOCAL_HOSTS:
            return False, f"[ai-nav] navigate: blocked non-local URL {url}"
        try:
            response = await page.goto(url, wait_until="domcontentloaded", timeout=10_000)
            status = response.status if response else "?"
            return False, f"[ai-nav] navigate -> {url} (HTTP {status})"
        except PlaywrightTimeoutError:
            return False, f"[ai-nav] navigate timeout: {url}"
        except Exception as exc:
            return False, f"[ai-nav] navigate error: {exc}"

    if action_name == "click":
        selector = str(action.get("selector", ""))
        if not selector:
            return False, "[ai-nav] click: missing selector"
        try:
            await page.locator(selector).first.click(timeout=5_000)
            await page.wait_for_timeout(500)
            return False, f"[ai-nav] click: {selector}"
        except Exception as exc:
            return False, f"[ai-nav] click error ({selector}): {exc}"

    if action_name == "click_text":
        text = str(action.get("text", ""))
        if not text:
            return False, "[ai-nav] click_text: missing text"
        try:
            await page.get_by_text(text, exact=False).first.click(timeout=5_000)
            await page.wait_for_timeout(500)
            return False, f"[ai-nav] click_text: {text!r}"
        except Exception as exc:
            return False, f"[ai-nav] click_text error ({text!r}): {exc}"

    if action_name == "fill":
        selector = str(action.get("selector", ""))
        value = str(action.get("value", ""))
        if not selector:
            return False, "[ai-nav] fill: missing selector"
        try:
            await page.locator(selector).first.fill(value, timeout=5_000)
            return False, f"[ai-nav] fill {selector} = {value!r}"
        except Exception as exc:
            return False, f"[ai-nav] fill error ({selector}): {exc}"

    if action_name == "report_finding":
        category = str(action.get("category", "ai_finding"))
        severity = str(action.get("severity", "low"))
        detail = str(action.get("detail", ""))
        if not category.startswith("ai_"):
            category = f"ai_{category}"
        if severity not in {"high", "medium", "low"}:
            severity = "low"
        findings.append(
            Finding(
                category=category,
                severity=severity,
                url=page.url,
                detail=detail,
            )
        )
        return False, f"[ai-nav] finding [{severity}] {category}: {detail}"

    return False, f"[ai-nav] unknown action: {action_name!r}"


async def run_ai_navigation_loop(
    page: Any,
    start_url: str,
    args: argparse.Namespace,
    findings: list[Finding],
    network_ops: list[NetworkOperation],
) -> list[str]:
    """Agentic loop: capture page state → ask AI → execute action → repeat.

    Returns the list of action-result strings representing what was done.
    """
    provider_url = resolve_provider_url(args.provider, args.provider_url)
    api_key = resolve_provider_api_key(args.provider, args.vault_file)
    start_host = urllib.parse.urlparse(start_url).hostname or ""

    console_logs: list[str] = []
    page.on("console", lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"))

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": AI_NAVIGATE_SYSTEM_PROMPT}
    ]
    action_history: list[str] = []

    print(
        f"\n[ai-nav] Starting AI-driven navigation "
        f"(provider={args.provider}, model={args.model}, max-steps={args.max_steps}) ..."
    )

    try:
        await page.goto(start_url, wait_until="domcontentloaded", timeout=args.timeout * 1000)
    except Exception as exc:
        print(f"[ai-nav] Failed to load start URL: {exc}")
        return action_history

    for step in range(args.max_steps):
        html = await page.content()
        current_url = page.url
        page_summary = summarize_page_for_ai(
            current_url, html, list(console_logs), list(network_ops)
        )

        recent_history = action_history[-5:]
        history_note = (
            ("\nRecent actions:\n" + "\n".join(f"  - {a}" for a in recent_history) + "\n")
            if recent_history
            else ""
        )
        user_content = (
            f"Step {step + 1}/{args.max_steps}{history_note}\n"
            f"Current page:\n{page_summary}"
        )
        messages.append({"role": "user", "content": user_content})

        print(f"\n[ai-nav] Step {step + 1}/{args.max_steps}  url={current_url}")

        raw_response = request_ai_navigation_action(
            provider=args.provider,
            model=args.model,
            provider_url=provider_url,
            api_key=api_key,
            messages=messages,
        )

        if raw_response is None:
            print("[ai-nav] No response from AI. Stopping.")
            break

        print(f"[ai-nav] AI → {raw_response[:200]!r}")
        messages.append({"role": "assistant", "content": raw_response})

        action = _parse_navigation_action(raw_response)
        if action is None:
            print(f"[ai-nav] Could not parse action from: {raw_response[:100]!r}")
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "ERROR: Could not parse your response as a JSON action. "
                        "Respond with a single JSON object only, no markdown."
                    ),
                }
            )
            continue

        is_done, result = await execute_navigation_action(
            page, action, start_host, findings
        )
        print(result)
        action_history.append(result)
        messages.append({"role": "user", "content": f"Action result: {result}"})

        if is_done:
            print("[ai-nav] AI signalled completion.")
            break

    return action_history


async def run_navigate(args: argparse.Namespace) -> int:
    if async_playwright is None:
        raise RuntimeError("playwright is not installed. Install it before running navigate.")

    start_url = validate_local_url(args.url)
    output_dir = Path(args.output_dir or f"penten-navigate-{int(time.time())}")
    output_dir.mkdir(parents=True, exist_ok=True)
    pages_dir = output_dir / "pages"
    pages_dir.mkdir(exist_ok=True)

    print("=" * 60)
    print(f"[penten] target          : {start_url}")
    print(f"[penten] output          : {output_dir}")
    print(f"[penten] provider/model  : {args.provider} / {args.model}")
    print(f"[penten] max-steps       : {args.max_steps}")
    print("=" * 60)

    network_ops: list[NetworkOperation] = []
    findings: list[Finding] = []

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=not args.show_browser)
        print(f"[browser] Chromium launched (headless={not args.show_browser})")
        context = await browser.new_context(ignore_https_errors=args.ignore_https_errors)
        page = await context.new_page()

        def on_request(request: Any) -> None:
            network_ops.append(
                NetworkOperation(
                    event="request",
                    method=request.method,
                    url=request.url,
                    status=None,
                    resource_type=request.resource_type,
                    timestamp=time.time(),
                )
            )

        def on_response(response: Any) -> None:
            network_ops.append(
                NetworkOperation(
                    event="response",
                    method=response.request.method,
                    url=response.url,
                    status=response.status,
                    resource_type=response.request.resource_type,
                    timestamp=time.time(),
                )
            )

        page.on("request", on_request)
        page.on("response", on_response)

        action_history = await run_ai_navigation_loop(
            page=page,
            start_url=start_url,
            args=args,
            findings=findings,
            network_ops=network_ops,
        )

        try:
            final_html = await page.content()
            (pages_dir / "final-page.html").write_text(final_html, encoding="utf-8")
        except Exception:
            pass

        await context.close()
        await browser.close()

    findings = deduplicate_findings(findings)
    network_serialized = [asdict(op) for op in network_ops]
    findings_serialized = [asdict(f) for f in findings]

    report = {
        "target": start_url,
        "provider": args.provider,
        "model": args.model,
        "mode": "ai_navigate",
        "action_history": action_history,
        "findings": findings_serialized,
        "profile": {
            "steps_taken": len(action_history),
            "network_events": len(network_serialized),
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    (output_dir / "network.json").write_text(json.dumps(network_serialized, indent=2), encoding="utf-8")
    (output_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\n" + "=" * 60)
    print("[done] AI navigation complete")
    print(f"[done] Steps taken    : {len(action_history)}")
    print(f"[done] Findings       : {len(findings_serialized)}")
    print(f"[done] Report         : {output_dir / 'report.json'}")
    print(f"[done] Network        : {output_dir / 'network.json'}")
    print(f"[done] Pages          : {pages_dir}")
    print("=" * 60)
    return 0


async def run_scan(args: argparse.Namespace) -> int:
    if async_playwright is None:
        raise RuntimeError("playwright is not installed. Install it before running scans.")

    start_url = validate_local_url(args.url)
    start_host = urllib.parse.urlparse(start_url).hostname or ""
    output_dir = Path(args.output_dir or f"penten-report-{int(time.time())}")
    output_dir.mkdir(parents=True, exist_ok=True)
    pages_dir = output_dir / "pages"
    pages_dir.mkdir(exist_ok=True)

    print("=" * 60)
    print(f"[penten] target          : {start_url}")
    print(f"[penten] output          : {output_dir}")
    print(f"[penten] provider/model  : {args.provider} / {args.model}")
    print(f"[penten] max-pages       : {args.max_pages}")
    print(f"[penten] max-forms       : {args.max_forms}")
    print(f"[penten] payloads/path   : {args.max_payloads_per_path}")
    print("=" * 60)

    network_ops: list[NetworkOperation] = []
    findings: list[Finding] = []
    visited_urls: list[str] = []
    discovered_paths: set[str] = set()
    discovered_forms: list[tuple[str, dict[str, Any]]] = []
    crawl_start = time.perf_counter()

    payloads = deduplicate_strings(DEFAULT_INJECTION_PAYLOADS)

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=not args.show_browser)
        print(f"[browser] Chromium launched (headless={not args.show_browser})")
        context = await browser.new_context(ignore_https_errors=args.ignore_https_errors)
        page = await context.new_page()

        def on_request(request: Any) -> None:
            network_ops.append(
                NetworkOperation(
                    event="request",
                    method=request.method,
                    url=request.url,
                    status=None,
                    resource_type=request.resource_type,
                    timestamp=time.time(),
                )
            )

        def on_response(response: Any) -> None:
            network_ops.append(
                NetworkOperation(
                    event="response",
                    method=response.request.method,
                    url=response.url,
                    status=response.status,
                    resource_type=response.request.resource_type,
                    timestamp=time.time(),
                )
            )
            if response.status >= 500:
                findings.append(
                    Finding(
                        category="server_error",
                        severity="high",
                        url=response.url,
                        detail=f"Received HTTP {response.status}",
                    )
                )

        page.on("request", on_request)
        page.on("response", on_response)

        queue: deque[str] = deque([start_url])
        seen: set[str] = set()
        print(f"\n[crawl] Starting crawl from {start_url} (limit: {args.max_pages} pages) ...")

        while queue and len(visited_urls) < args.max_pages:
            current = queue.popleft()
            if current in seen:
                continue
            if not is_internal_url(start_host, current):
                continue
            seen.add(current)
            try:
                response = await page.goto(current, wait_until="domcontentloaded", timeout=args.timeout * 1000)
                visited_urls.append(current)
                discovered_paths.add(path_from_url(current))
                status = response.status if response else None
                status_str = str(status) if status is not None else "?"
                print(f"[crawl] {len(visited_urls):>4}/{args.max_pages}  {status_str}  {current}")
                if status and status >= 500:
                    findings.append(
                        Finding(
                            category="server_error",
                            severity="high",
                            url=current,
                            detail=f"Navigation received HTTP {status}",
                        )
                    )
                    print(f"  [!] HIGH server_error: HTTP {status} on {current}")
                if "/api" in path_from_url(current).lower() and status in {200, 201, 202}:
                    findings.append(
                        Finding(
                            category="private_api_possible_exposure",
                            severity="medium",
                            url=current,
                            detail="API-like endpoint was accessible without obvious authentication.",
                        )
                    )
                    print(f"  [!] MEDIUM private_api_possible_exposure: {current}")
                if SENSITIVE_PATH_PATTERN.search(path_from_url(current)) and status in {
                    200,
                    201,
                    202,
                }:
                    findings.append(
                        Finding(
                            category="sensitive_path_exposed",
                            severity="medium",
                            url=current,
                            detail="Sensitive-looking path was reachable.",
                        )
                    )
                    print(f"  [!] MEDIUM sensitive_path_exposed: {current}")

                html = await page.content()
                page_file = pages_dir / f"page-{len(visited_urls):04d}.html"
                page_file.write_text(html, encoding="utf-8")

                parser = LinkAndFormParser()
                parser.feed(html)
                for discovered in parser.links:
                    candidate = urllib.parse.urljoin(current, discovered)
                    normalized = urllib.parse.urldefrag(candidate)[0]
                    if is_internal_url(start_host, normalized):
                        if normalized not in seen and normalized not in queue:
                            queue.append(normalized)
                for form in parser.forms:
                    discovered_forms.append((current, form))
                new_links = sum(
                    1
                    for d in parser.links
                    if is_internal_url(start_host, urllib.parse.urldefrag(urllib.parse.urljoin(current, d))[0])
                )
                if parser.links or parser.forms:
                    print(f"       -> {new_links} link(s), {len(parser.forms)} form(s) discovered")
            except Exception as error:
                findings.append(
                    Finding(
                        category="crawl_error",
                        severity="low",
                        url=current,
                        detail=str(error),
                    )
                )
                print(f"  [!] LOW crawl_error: {current} — {error}")

        print(
            f"\n[payloads] Requesting AI payloads from {args.provider} (model: {args.model}) "
            f"using {len(discovered_paths)} discovered path(s) as context ..."
        )
        payloads.extend(
            generate_ai_payloads(
                provider=args.provider,
                model=args.model,
                discovered_paths=sorted(discovered_paths),
                provider_url=resolve_provider_url(args.provider, args.provider_url),
                api_key=resolve_provider_api_key(args.provider, args.vault_file),
            )
        )
        payloads = deduplicate_strings(payloads)
        print(f"[payloads] {len(payloads)} payload(s) ready (default + AI-generated)")

        print(
            f"\n[inject] Testing {len(discovered_paths)} path(s) with up to {args.max_payloads_per_path} payload(s) each ..."
        )
        for path in sorted(discovered_paths):
            base = urllib.parse.urljoin(start_url, path)
            for payload in payloads[: args.max_payloads_per_path]:
                attack_url = f"{base}?penten_probe={urllib.parse.quote(payload)}"
                print(f"[inject] {path}  <-  {payload[:50]!r}")
                try:
                    response = await page.goto(attack_url, wait_until="domcontentloaded", timeout=args.timeout * 1000)
                    status = response.status if response else None
                    if status and status >= 500:
                        findings.append(
                            Finding(
                                category="injection_triggered_error",
                                severity="high",
                                url=attack_url,
                                detail=f"Injection payload triggered HTTP {status}",
                            )
                        )
                        print(f"  [!] HIGH injection_triggered_error: HTTP {status}")
                    body = await page.content()
                    if payload in body:
                        findings.append(
                            Finding(
                                category="reflected_input",
                                severity="medium",
                                url=attack_url,
                                detail="Payload reflected in response body.",
                            )
                        )
                        print(f"  [!] MEDIUM reflected_input: payload reflected on {path}")
                except Exception as error:
                    findings.append(
                        Finding(
                            category="injection_test_error",
                            severity="low",
                            url=attack_url,
                            detail=str(error),
                        )
                    )
                    print(f"  [!] LOW injection_test_error: {error}")

        form_count = min(len(discovered_forms), args.max_forms)
        print(f"\n[forms] Submitting {form_count} form(s) ...")
        for form_url, form in discovered_forms[: args.max_forms]:
            await fill_and_submit_form(context, form_url, form, payloads, findings)

        await context.close()
        await browser.close()

    crawl_seconds = time.perf_counter() - crawl_start

    print(f"\n[secrets] Running trufflehog scan on {output_dir} ...")
    trufflehog_results = run_trufflehog_scan(output_dir)
    if trufflehog_results and "error" not in trufflehog_results[0]:
        findings.append(
            Finding(
                category="secret_scan",
                severity="high",
                url=str(output_dir),
                detail=f"Trufflehog reported {len(trufflehog_results)} potential findings.",
            )
        )
    elif trufflehog_results:
        findings.append(
            Finding(
                category="secret_scan_warning",
                severity="low",
                url=str(output_dir),
                detail=trufflehog_results[0]["error"],
            )
        )

    findings = deduplicate_findings(findings)
    network_serialized = [asdict(item) for item in network_ops]
    findings_serialized = [asdict(item) for item in findings]
    report = {
        "target": start_url,
        "provider": args.provider,
        "model": args.model,
        "profile": {
            "crawl_seconds": crawl_seconds,
            "visited_urls": len(visited_urls),
            "discovered_paths": len(discovered_paths),
            "network_events": len(network_serialized),
        },
        "paths": sorted(discovered_paths),
        "visited_urls": visited_urls,
        "findings": findings_serialized,
        "recommendations": [
            "Return safe 4xx responses for private/internal endpoints and require authentication.",
            "Add strict server-side validation and output encoding to block injection/reflection flaws.",
            "Instrument structured logging and alerting for 5xx spikes and suspicious payload patterns.",
            "Add CI security checks (SAST/DAST/secrets) and remediation workflows for discovered issues.",
        ],
        "trufflehog": trufflehog_results,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    (output_dir / "network.json").write_text(json.dumps(network_serialized, indent=2), encoding="utf-8")
    (output_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\n" + "=" * 60)
    print(f"[done] Scan complete in {crawl_seconds:.1f}s")
    print(f"[done] Visited {len(visited_urls)} URL(s) across {len(discovered_paths)} path(s)")
    print(f"[done] Network events logged: {len(network_serialized)}")
    print(f"[done] Findings: {len(findings_serialized)}")
    if findings_serialized:
        by_severity: dict[str, int] = {}
        for f in findings_serialized:
            by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
        for severity in ("high", "medium", "low"):
            count = by_severity.get(severity, 0)
            if count:
                print(f"         {severity}: {count}")
    print(f"[done] Report : {output_dir / 'report.json'}")
    print(f"[done] Network: {output_dir / 'network.json'}")
    print(f"[done] Pages  : {pages_dir}")
    print("=" * 60)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Localhost-only Playwright crawler, profiler, injection tester and reporter."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run a local scan.")
    scan_parser.add_argument("--url", required=True, help="Target URL, must resolve to localhost or 127.0.0.1.")
    scan_parser.add_argument(
        "--provider",
        default="ollama",
        choices=SUPPORTED_PROVIDERS,
        help="AI provider used for payload generation.",
    )
    scan_parser.add_argument("--model", required=True, help="Model name for the selected AI provider.")
    scan_parser.add_argument("--max-pages", type=int, default=50, help="Maximum number of pages to crawl.")
    scan_parser.add_argument("--max-forms", type=int, default=20, help="Maximum number of forms to exercise.")
    scan_parser.add_argument("--timeout", type=int, default=12, help="Per-page timeout in seconds.")
    scan_parser.add_argument(
        "--provider-url",
        default="",
        help="Optional provider API base URL override.",
    )
    scan_parser.add_argument(
        "--vault-file",
        default=os.getenv("PENTEN_VAULT_FILE", DEFAULT_VAULT_FILE),
        help="Path to provider token vault file.",
    )
    scan_parser.add_argument(
        "--ignore-https-errors",
        action="store_true",
        help="Ignore HTTPS certificate errors during local scanning.",
    )
    scan_parser.add_argument(
        "--max-payloads-per-path",
        type=int,
        default=MAX_PAYLOADS_PER_PATH,
        help="Maximum number of injection payloads tested per discovered path.",
    )
    scan_parser.add_argument("--output-dir", default="", help="Directory for generated logs and reports.")
    scan_parser.add_argument("--show-browser", action="store_true", help="Show browser while scanning.")

    configure_parser = subparsers.add_parser("configure", help="Store provider credentials in vault.")
    configure_parser.add_argument(
        "--provider",
        required=True,
        choices=SUPPORTED_PROVIDERS,
        help="Provider to configure in vault.",
    )
    configure_parser.add_argument(
        "--vault-file",
        default=os.getenv("PENTEN_VAULT_FILE", DEFAULT_VAULT_FILE),
        help="Path to provider token vault file.",
    )

    navigate_parser = subparsers.add_parser(
        "navigate",
        help="Let the AI drive the browser to explore and probe the local site.",
    )
    navigate_parser.add_argument(
        "--url", required=True, help="Target URL, must resolve to localhost or 127.0.0.1."
    )
    navigate_parser.add_argument(
        "--provider",
        default="ollama",
        choices=SUPPORTED_PROVIDERS,
        help="AI provider that directs navigation.",
    )
    navigate_parser.add_argument("--model", required=True, help="Model name for the selected AI provider.")
    navigate_parser.add_argument(
        "--max-steps",
        type=int,
        default=AI_NAVIGATE_MAX_STEPS,
        help="Maximum number of AI navigation steps.",
    )
    navigate_parser.add_argument("--timeout", type=int, default=12, help="Per-page timeout in seconds.")
    navigate_parser.add_argument(
        "--provider-url",
        default="",
        help="Optional provider API base URL override.",
    )
    navigate_parser.add_argument(
        "--vault-file",
        default=os.getenv("PENTEN_VAULT_FILE", DEFAULT_VAULT_FILE),
        help="Path to provider token vault file.",
    )
    navigate_parser.add_argument(
        "--ignore-https-errors",
        action="store_true",
        help="Ignore HTTPS certificate errors during navigation.",
    )
    navigate_parser.add_argument("--output-dir", default="", help="Directory for generated logs and reports.")
    navigate_parser.add_argument("--show-browser", action="store_true", help="Show browser while navigating.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    parsed_argv = argv if argv is not None else sys.argv[1:]
    if parsed_argv and parsed_argv[0] not in {*SUPPORTED_COMMANDS, "-h", "--help"}:
        print("Warning: defaulting to 'scan' command. Use `scan` explicitly.")
        parsed_argv = ["scan", *parsed_argv]
    args = parser.parse_args(parsed_argv)
    try:
        if args.command == "configure":
            return configure_provider(args.provider, args.vault_file)
        if args.command == "navigate":
            return asyncio.run(run_navigate(args))
        return asyncio.run(run_scan(args))
    except ValueError as error:
        parser.error(str(error))
    except KeyboardInterrupt:
        print("Interrupted.")
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())
