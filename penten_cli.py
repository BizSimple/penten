#!/usr/bin/env python3
import argparse
import asyncio
import json
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


LOCAL_HOSTS = {"localhost", "127.0.0.1"}
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
    return parsed.hostname.lower() == base_host.lower()


def path_from_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return parsed.path or "/"


def build_registration_value(field_name: str, field_type: str, index: int, injected: bool, payload: str) -> str:
    lower_name = field_name.lower()
    if injected and field_type not in {"email", "password", "hidden"}:
        return payload
    if "mail" in lower_name or field_type == "email":
        return f"penten{index}@example.com"
    if "pass" in lower_name or field_type == "password":
        return "StrongPass123!"
    if "user" in lower_name or "name" in lower_name:
        return f"penten_user_{index}"
    if field_type in {"checkbox", "radio"}:
        return "on"
    return f"value_{index}"


def generate_ai_payloads(model: str, discovered_paths: list[str]) -> list[str]:
    payload_prompt = (
        "Return 5 web security injection payloads as a JSON array of strings. "
        "Prioritize SQLi, XSS, SSTI and path traversal. Paths observed: "
        f"{', '.join(discovered_paths[:30])}"
    )
    request_data = json.dumps(
        {"model": model, "prompt": payload_prompt, "stream": False, "format": "json"}
    ).encode("utf-8")
    request = urllib.request.Request(
        "http://127.0.0.1:11434/api/generate",
        data=request_data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return []
    try:
        parsed = json.loads(body)
        model_response = parsed.get("response", "")
        if model_response:
            extracted = json.loads(model_response)
            if isinstance(extracted, list):
                return [str(item) for item in extracted if isinstance(item, str)]
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    return []


def run_trufflehog_scan(scan_dir: Path) -> list[dict[str, Any]]:
    commands = [
        ["trufflehog", "filesystem", "--json", str(scan_dir)],
        ["trufflehog", "filesystem", str(scan_dir), "--json"],
    ]
    for command in commands:
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            return [{"error": "trufflehog command was not found in PATH."}]
        if completed.returncode not in {0, 1}:
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


async def fill_and_submit_form(
    context: Any,
    origin_url: str,
    form: dict[str, Any],
    payloads: list[str],
    findings: list[Finding],
) -> None:
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError

    fields = form.get("fields", [])
    if not fields:
        return
    action_url = urllib.parse.urljoin(origin_url, form.get("action") or origin_url)
    if urllib.parse.urlparse(action_url).hostname not in LOCAL_HOSTS:
        return

    for injected in (False, True):
        page = await context.new_page()
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
        except PlaywrightTimeoutError:
            findings.append(
                Finding(
                    category="form_timeout",
                    severity="low",
                    url=origin_url,
                    detail="Timeout while filling or submitting form.",
                )
            )
        finally:
            await page.close()


async def run_scan(args: argparse.Namespace) -> int:
    start_url = validate_local_url(args.url)
    start_host = urllib.parse.urlparse(start_url).hostname or ""
    output_dir = Path(args.output_dir or f"penten-report-{int(time.time())}")
    output_dir.mkdir(parents=True, exist_ok=True)
    pages_dir = output_dir / "pages"
    pages_dir.mkdir(exist_ok=True)

    network_ops: list[NetworkOperation] = []
    findings: list[Finding] = []
    visited_urls: list[str] = []
    discovered_paths: set[str] = set()
    discovered_forms: list[tuple[str, dict[str, Any]]] = []
    crawl_start = time.perf_counter()

    from playwright.async_api import async_playwright

    payloads = list(dict.fromkeys(DEFAULT_INJECTION_PAYLOADS))

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=not args.show_browser)
        context = await browser.new_context(ignore_https_errors=True)
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
                if status and status >= 500:
                    findings.append(
                        Finding(
                            category="server_error",
                            severity="high",
                            url=current,
                            detail=f"Navigation received HTTP {status}",
                        )
                    )
                if "/api" in path_from_url(current).lower() and status in {200, 201, 202}:
                    findings.append(
                        Finding(
                            category="private_api_possible_exposure",
                            severity="medium",
                            url=current,
                            detail="API-like endpoint was accessible without obvious authentication.",
                        )
                    )
                if re.search(r"/(admin|internal|private|debug)", path_from_url(current), flags=re.I) and status in {
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
            except Exception as error:
                findings.append(
                    Finding(
                        category="crawl_error",
                        severity="low",
                        url=current,
                        detail=str(error),
                    )
                )

        payloads.extend(generate_ai_payloads(args.model, sorted(discovered_paths)))
        payloads = list(dict.fromkeys(payloads))

        for path in sorted(discovered_paths):
            base = urllib.parse.urljoin(start_url, path)
            for payload in payloads[:3]:
                attack_url = f"{base}?penten_probe={urllib.parse.quote(payload)}"
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
                except Exception as error:
                    findings.append(
                        Finding(
                            category="injection_test_error",
                            severity="low",
                            url=attack_url,
                            detail=str(error),
                        )
                    )

        for form_url, form in discovered_forms[: args.max_forms]:
            await fill_and_submit_form(context, form_url, form, payloads, findings)

        await context.close()
        await browser.close()

    crawl_seconds = time.perf_counter() - crawl_start

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

    print(f"Scan complete. Report: {output_dir / 'report.json'}")
    print(json.dumps(report["profile"], indent=2))
    print(f"Findings: {len(findings_serialized)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Localhost-only Playwright crawler, profiler, injection tester and reporter."
    )
    parser.add_argument("--url", required=True, help="Target URL, must resolve to localhost or 127.0.0.1.")
    parser.add_argument("--model", required=True, help="Local Ollama model name.")
    parser.add_argument("--max-pages", type=int, default=50, help="Maximum number of pages to crawl.")
    parser.add_argument("--max-forms", type=int, default=20, help="Maximum number of forms to exercise.")
    parser.add_argument("--timeout", type=int, default=12, help="Per-page timeout in seconds.")
    parser.add_argument("--output-dir", default="", help="Directory for generated logs and reports.")
    parser.add_argument("--show-browser", action="store_true", help="Show browser while scanning.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return asyncio.run(run_scan(args))
    except ValueError as error:
        parser.error(str(error))
    except KeyboardInterrupt:
        print("Interrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
