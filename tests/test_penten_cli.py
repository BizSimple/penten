import asyncio
import urllib.error
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, MagicMock, patch

from penten_cli import (
    Finding,
    NetworkOperation,
    build_parser,
    build_registration_value,
    configure_provider,
    create_or_update_github_issues,
    execute_navigation_action,
    generate_ai_payloads,
    is_internal_url,
    load_vault,
    path_from_url,
    request_ai_navigation_action,
    resolve_github_token,
    resolve_provider_api_key,
    resolve_provider_url,
    run_ai_navigation_loop,
    save_vault,
    summarize_page_for_ai,
    validate_local_url,
    _github_api_request,
    _github_issue_title,
    _parse_navigation_action,
)


class ValidateLocalURLTests(unittest.TestCase):
    def test_accepts_localhost(self) -> None:
        self.assertEqual(validate_local_url("http://localhost:8080/home"), "http://localhost:8080/home")

    def test_accepts_loopback(self) -> None:
        self.assertEqual(validate_local_url("https://127.0.0.1/api"), "https://127.0.0.1/api")

    def test_rejects_external_host(self) -> None:
        with self.assertRaises(ValueError):
            validate_local_url("http://example.com")

    def test_rejects_invalid_scheme(self) -> None:
        with self.assertRaises(ValueError):
            validate_local_url("ftp://localhost")

    def test_removes_fragment(self) -> None:
        self.assertEqual(validate_local_url("http://localhost/app#frag"), "http://localhost/app")


class URLHelpersTests(unittest.TestCase):
    def test_is_internal_url(self) -> None:
        self.assertTrue(is_internal_url("localhost", "/relative/path"))
        self.assertTrue(is_internal_url("localhost", "http://localhost/a"))
        self.assertTrue(is_internal_url("localhost", "http://127.0.0.1/a"))
        self.assertTrue(is_internal_url("127.0.0.1", "http://localhost:3000/a"))
        self.assertTrue(is_internal_url("LOCALHOST", "http://localhost/a"))
        self.assertFalse(is_internal_url("localhost", "http://example.com/a"))

    def test_path_from_url(self) -> None:
        self.assertEqual(path_from_url("http://localhost"), "/")
        self.assertEqual(path_from_url("http://localhost/x/y?q=1"), "/x/y")


class FormValueTests(unittest.TestCase):
    def test_registration_values(self) -> None:
        self.assertEqual(build_registration_value("email", "email", 0, False, "X"), "penten0@example.com")
        self.assertEqual(build_registration_value("email", "email", 1, False, "X"), "penten1@example.com")
        self.assertEqual(build_registration_value("password", "password", 0, False, "X"), "StrongPass123!")
        self.assertEqual(build_registration_value("username", "text", 0, False, "X"), "penten_user_0")

    def test_injected_prefers_payload_for_text(self) -> None:
        self.assertEqual(build_registration_value("name", "text", 0, True, "PAYLOAD"), "PAYLOAD")

    def test_injected_does_not_override_hidden(self) -> None:
        self.assertEqual(build_registration_value("token", "hidden", 2, True, "PAYLOAD"), "value_2")

    def test_checkbox_and_fallback(self) -> None:
        self.assertEqual(build_registration_value("tos", "checkbox", 0, False, "X"), "on")
        self.assertEqual(build_registration_value("city", "text", 3, False, "X"), "value_3")


class FakeHTTPResponse:
    def __init__(self, body: str) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body.encode("utf-8")

    def __enter__(self) -> "FakeHTTPResponse":
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        return False


class ProviderPayloadTests(unittest.TestCase):
    @patch("urllib.request.urlopen")
    def test_ollama_payload_generation(self, mock_urlopen) -> None:
        mock_urlopen.return_value = FakeHTTPResponse('{"response":"[\\"x\\",\\"y\\"]"}')
        payloads = generate_ai_payloads("ollama", "llama3", ["/login"], "http://localhost:11434", "")
        self.assertEqual(payloads, ["x", "y"])

    @patch("urllib.request.urlopen")
    def test_deepseek_payload_generation(self, mock_urlopen) -> None:
        mock_urlopen.return_value = FakeHTTPResponse(
            '{"choices":[{"message":{"content":"[\\"x\\",\\"y\\"]"}}]}'
        )
        payloads = generate_ai_payloads("deepseek", "deepseek-chat", ["/login"], "https://api.deepseek.com", "k")
        self.assertEqual(payloads, ["x", "y"])

    @patch("urllib.request.urlopen")
    def test_glm_payload_generation(self, mock_urlopen) -> None:
        mock_urlopen.return_value = FakeHTTPResponse(
            '{"choices":[{"message":{"content":"[\\"x\\",\\"y\\"]"}}]}'
        )
        payloads = generate_ai_payloads("glm", "glm-4.5", ["/login"], "https://open.bigmodel.cn/api/paas/v4", "k")
        self.assertEqual(payloads, ["x", "y"])

    @patch("urllib.request.urlopen")
    def test_gemini_payload_generation(self, mock_urlopen) -> None:
        mock_urlopen.return_value = FakeHTTPResponse(
            '{"candidates":[{"content":{"parts":[{"text":"[\\"x\\",\\"y\\"]"}]}}]}'
        )
        payloads = generate_ai_payloads(
            "gemini",
            "gemini-2.5-flash",
            ["/login"],
            "https://generativelanguage.googleapis.com",
            "k",
        )
        self.assertEqual(payloads, ["x", "y"])

    def test_missing_api_key_for_hosted_provider_returns_empty(self) -> None:
        self.assertEqual(
            generate_ai_payloads("deepseek", "deepseek-chat", ["/login"], "https://api.deepseek.com", ""),
            [],
        )

    @patch("urllib.request.urlopen")
    def test_invalid_provider_response_returns_empty(self, mock_urlopen) -> None:
        mock_urlopen.return_value = FakeHTTPResponse('{"choices":[{"message":{"content":"not-json"}}]}')
        payloads = generate_ai_payloads("deepseek", "deepseek-chat", ["/login"], "https://api.deepseek.com", "k")
        self.assertEqual(payloads, [])

    def test_resolve_provider_url(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(resolve_provider_url("ollama", ""), "http://127.0.0.1:11434")
            self.assertEqual(resolve_provider_url("deepseek", ""), "https://api.deepseek.com")
            self.assertEqual(resolve_provider_url("glm", ""), "https://open.bigmodel.cn/api/paas/v4")
            self.assertEqual(resolve_provider_url("gemini", ""), "https://generativelanguage.googleapis.com")

    @patch.dict("os.environ", {"DEEPSEEK_API_KEY": "d", "GLM_API_KEY": "g", "GEMINI_API_KEY": "m"}, clear=True)
    def test_resolve_provider_api_key(self) -> None:
        self.assertEqual(resolve_provider_api_key("deepseek", "/tmp/missing"), "d")
        self.assertEqual(resolve_provider_api_key("glm", "/tmp/missing"), "g")
        self.assertEqual(resolve_provider_api_key("gemini", "/tmp/missing"), "m")
        self.assertEqual(resolve_provider_api_key("ollama", "/tmp/missing"), "")

    def test_vault_storage_and_lookup(self) -> None:
        with TemporaryDirectory() as tmpdir:
            vault_file = str(Path(tmpdir) / "vault.json")
            save_vault(vault_file, {"providers": {"deepseek": {"api_key": "vault-token"}}})
            self.assertEqual(load_vault(vault_file)["providers"]["deepseek"]["api_key"], "vault-token")
            with patch.dict("os.environ", {}, clear=True):
                self.assertEqual(resolve_provider_api_key("deepseek", vault_file), "vault-token")

    @patch("getpass.getpass", return_value="abc123")
    def test_configure_provider_saves_token(self, _mock_getpass) -> None:
        with TemporaryDirectory() as tmpdir:
            vault_file = str(Path(tmpdir) / "vault.json")
            result = configure_provider("gemini", vault_file)
            self.assertEqual(result, 0)
            vault = load_vault(vault_file)
            self.assertEqual(vault["providers"]["gemini"]["api_key"], "abc123")


class ParserTests(unittest.TestCase):
    def test_configure_subcommand_parsing(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["configure", "--provider", "deepseek"])
        self.assertEqual(args.command, "configure")
        self.assertEqual(args.provider, "deepseek")

    def test_scan_subcommand_parsing(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["scan", "--url", "http://localhost:3000", "--model", "llama3.1"])
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.provider, "ollama")

    def test_navigate_subcommand_parsing(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            ["navigate", "--url", "http://localhost:3000", "--model", "llama3.1"]
        )
        self.assertEqual(args.command, "navigate")
        self.assertEqual(args.provider, "ollama")
        self.assertEqual(args.url, "http://localhost:3000")
        self.assertEqual(args.model, "llama3.1")

    def test_navigate_max_steps_default(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            ["navigate", "--url", "http://localhost:3000", "--model", "m"]
        )
        self.assertGreater(args.max_steps, 0)

    def test_navigate_max_steps_override(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            ["navigate", "--url", "http://localhost:3000", "--model", "m", "--max-steps", "5"]
        )
        self.assertEqual(args.max_steps, 5)


class SummarizePageTests(unittest.TestCase):
    def test_extracts_title_and_links(self) -> None:
        html = "<html><head><title>My App</title></head><body><a href='/login'>Login</a></body></html>"
        summary = summarize_page_for_ai("http://localhost/", html, [], [])
        self.assertIn("My App", summary)
        self.assertIn("/login", summary)

    def test_includes_form_info(self) -> None:
        html = (
            "<html><body>"
            "<form action='/search' method='get'><input name='q' type='text'/></form>"
            "</body></html>"
        )
        summary = summarize_page_for_ai("http://localhost/", html, [], [])
        self.assertIn("/search", summary)
        self.assertIn("q", summary)

    def test_includes_console_logs(self) -> None:
        summary = summarize_page_for_ai(
            "http://localhost/", "<html></html>", ["[error] boom"], []
        )
        self.assertIn("[error] boom", summary)

    def test_includes_network_ops(self) -> None:
        net = [
            NetworkOperation("response", "GET", "http://localhost/api", 200, "xhr", 0.0)
        ]
        summary = summarize_page_for_ai("http://localhost/", "<html></html>", [], net)
        self.assertIn("/api", summary)
        self.assertIn("200", summary)

    def test_handles_empty_html(self) -> None:
        summary = summarize_page_for_ai("http://localhost/", "", [], [])
        self.assertIn("URL:", summary)


class ParseNavigationActionTests(unittest.TestCase):
    def test_parses_direct_json(self) -> None:
        action = _parse_navigation_action('{"action": "navigate", "url": "http://localhost/admin"}')
        self.assertIsNotNone(action)
        self.assertEqual(action["action"], "navigate")
        self.assertEqual(action["url"], "http://localhost/admin")

    def test_parses_json_embedded_in_text(self) -> None:
        text = 'Sure! Here is the action:\n{"action": "click", "selector": "#btn"}\nDone.'
        action = _parse_navigation_action(text)
        self.assertIsNotNone(action)
        self.assertEqual(action["action"], "click")

    def test_returns_none_for_non_json(self) -> None:
        self.assertIsNone(_parse_navigation_action("I'll navigate to the login page."))

    def test_returns_none_for_json_without_action(self) -> None:
        self.assertIsNone(_parse_navigation_action('{"url": "http://localhost"}'))

    def test_done_action(self) -> None:
        action = _parse_navigation_action('{"action": "done", "summary": "all explored"}')
        self.assertIsNotNone(action)
        self.assertEqual(action["action"], "done")


class RequestAiNavigationActionTests(unittest.TestCase):
    def _messages(self) -> list[dict]:
        return [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "page state"},
        ]

    @patch("urllib.request.urlopen")
    def test_ollama_returns_content(self, mock_urlopen) -> None:
        mock_urlopen.return_value = FakeHTTPResponse(
            '{"message": {"role": "assistant", "content": "{\\"action\\":\\"done\\",\\"summary\\":\\"ok\\"}"}}'
        )
        result = request_ai_navigation_action(
            "ollama", "llama3", "http://localhost:11434", "", self._messages()
        )
        self.assertIsNotNone(result)
        self.assertIn("done", result)

    @patch("urllib.request.urlopen")
    def test_deepseek_returns_content(self, mock_urlopen) -> None:
        mock_urlopen.return_value = FakeHTTPResponse(
            '{"choices":[{"message":{"content":"{\\"action\\":\\"navigate\\",\\"url\\":\\"http://localhost/admin\\"}"}}]}'
        )
        result = request_ai_navigation_action(
            "deepseek", "deepseek-chat", "https://api.deepseek.com", "key", self._messages()
        )
        self.assertIsNotNone(result)
        self.assertIn("navigate", result)

    @patch("urllib.request.urlopen")
    def test_gemini_returns_content(self, mock_urlopen) -> None:
        mock_urlopen.return_value = FakeHTTPResponse(
            '{"candidates":[{"content":{"parts":[{"text":"{\\"action\\":\\"done\\",\\"summary\\":\\"x\\"}"}]}}]}'
        )
        result = request_ai_navigation_action(
            "gemini",
            "gemini-2.5-flash",
            "https://generativelanguage.googleapis.com",
            "key",
            self._messages(),
        )
        self.assertIsNotNone(result)
        self.assertIn("done", result)

    def test_missing_api_key_deepseek_returns_none(self) -> None:
        result = request_ai_navigation_action(
            "deepseek", "deepseek-chat", "https://api.deepseek.com", "", self._messages()
        )
        self.assertIsNone(result)

    def test_missing_api_key_gemini_returns_none(self) -> None:
        result = request_ai_navigation_action(
            "gemini",
            "gemini-2.5-flash",
            "https://generativelanguage.googleapis.com",
            "",
            self._messages(),
        )
        self.assertIsNone(result)

    @patch("urllib.request.urlopen", side_effect=urllib.error.URLError("network error"))
    def test_network_error_returns_none(self, _mock) -> None:
        result = request_ai_navigation_action(
            "ollama", "llama3", "http://localhost:11434", "", self._messages()
        )
        self.assertIsNone(result)


class ExecuteNavigationActionTests(unittest.TestCase):
    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def _make_page(self, url="http://localhost/") -> MagicMock:
        page = MagicMock()
        page.url = url
        page.goto = AsyncMock(return_value=MagicMock(status=200))
        page.locator = MagicMock(return_value=MagicMock(first=MagicMock(
            click=AsyncMock(), fill=AsyncMock()
        )))
        page.get_by_text = MagicMock(return_value=MagicMock(first=MagicMock(click=AsyncMock())))
        page.wait_for_timeout = AsyncMock()
        return page

    def test_done_action_returns_true(self) -> None:
        page = self._make_page()
        is_done, msg = self._run(
            execute_navigation_action(page, {"action": "done", "summary": "x"}, "localhost", [])
        )
        self.assertTrue(is_done)
        self.assertIn("done", msg)

    def test_navigate_action(self) -> None:
        page = self._make_page()
        is_done, msg = self._run(
            execute_navigation_action(
                page,
                {"action": "navigate", "url": "http://localhost/admin"},
                "localhost",
                [],
            )
        )
        self.assertFalse(is_done)
        page.goto.assert_called_once()

    def test_navigate_blocks_external_url(self) -> None:
        page = self._make_page()
        is_done, msg = self._run(
            execute_navigation_action(
                page,
                {"action": "navigate", "url": "http://example.com/evil"},
                "localhost",
                [],
            )
        )
        self.assertFalse(is_done)
        self.assertIn("blocked", msg)
        page.goto.assert_not_called()

    def test_click_action(self) -> None:
        page = self._make_page()
        is_done, msg = self._run(
            execute_navigation_action(
                page, {"action": "click", "selector": "#btn"}, "localhost", []
            )
        )
        self.assertFalse(is_done)
        self.assertIn("#btn", msg)

    def test_fill_action(self) -> None:
        page = self._make_page()
        is_done, msg = self._run(
            execute_navigation_action(
                page,
                {"action": "fill", "selector": "input[name=q]", "value": "test"},
                "localhost",
                [],
            )
        )
        self.assertFalse(is_done)

    def test_report_finding_action(self) -> None:
        page = self._make_page()
        findings: list[Finding] = []
        is_done, msg = self._run(
            execute_navigation_action(
                page,
                {
                    "action": "report_finding",
                    "category": "sqli",
                    "severity": "high",
                    "detail": "SQL error in response",
                },
                "localhost",
                findings,
            )
        )
        self.assertFalse(is_done)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")
        self.assertIn("sqli", findings[0].category)

    def test_report_finding_clamps_invalid_severity(self) -> None:
        page = self._make_page()
        findings: list[Finding] = []
        self._run(
            execute_navigation_action(
                page,
                {"action": "report_finding", "category": "x", "severity": "critical", "detail": "d"},
                "localhost",
                findings,
            )
        )
        self.assertEqual(findings[0].severity, "low")

    def test_unknown_action(self) -> None:
        page = self._make_page()
        is_done, msg = self._run(
            execute_navigation_action(page, {"action": "fly"}, "localhost", [])
        )
        self.assertFalse(is_done)
        self.assertIn("unknown", msg)

    # --- list_files ---

    def test_list_files_no_source_dir(self) -> None:
        page = self._make_page()
        is_done, msg = self._run(
            execute_navigation_action(
                page, {"action": "list_files", "path": "."}, "localhost", [], source_dir=None
            )
        )
        self.assertFalse(is_done)
        self.assertIn("no source directory", msg)

    def test_list_files_lists_directory(self) -> None:
        page = self._make_page()
        with TemporaryDirectory() as tmpdir:
            Path(tmpdir, "app.py").write_text("# app")
            Path(tmpdir, "subdir").mkdir()
            is_done, msg = self._run(
                execute_navigation_action(
                    page, {"action": "list_files", "path": "."}, "localhost", [], source_dir=tmpdir
                )
            )
        self.assertFalse(is_done)
        self.assertIn("app.py", msg)
        self.assertIn("subdir", msg)

    def test_list_files_blocks_path_traversal(self) -> None:
        page = self._make_page()
        with TemporaryDirectory() as tmpdir:
            is_done, msg = self._run(
                execute_navigation_action(
                    page,
                    {"action": "list_files", "path": "../../etc"},
                    "localhost",
                    [],
                    source_dir=tmpdir,
                )
            )
        self.assertFalse(is_done)
        self.assertIn("traversal", msg)

    def test_list_files_not_a_directory(self) -> None:
        page = self._make_page()
        with TemporaryDirectory() as tmpdir:
            Path(tmpdir, "file.txt").write_text("data")
            is_done, msg = self._run(
                execute_navigation_action(
                    page,
                    {"action": "list_files", "path": "file.txt"},
                    "localhost",
                    [],
                    source_dir=tmpdir,
                )
            )
        self.assertFalse(is_done)
        self.assertIn("not a directory", msg)

    # --- read_file ---

    def test_read_file_no_source_dir(self) -> None:
        page = self._make_page()
        is_done, msg = self._run(
            execute_navigation_action(
                page, {"action": "read_file", "path": "app.py"}, "localhost", [], source_dir=None
            )
        )
        self.assertFalse(is_done)
        self.assertIn("no source directory", msg)

    def test_read_file_reads_content(self) -> None:
        page = self._make_page()
        with TemporaryDirectory() as tmpdir:
            Path(tmpdir, "app.py").write_text("print('hello')")
            is_done, msg = self._run(
                execute_navigation_action(
                    page,
                    {"action": "read_file", "path": "app.py"},
                    "localhost",
                    [],
                    source_dir=tmpdir,
                )
            )
        self.assertFalse(is_done)
        self.assertIn("print('hello')", msg)

    def test_read_file_blocks_path_traversal(self) -> None:
        page = self._make_page()
        with TemporaryDirectory() as tmpdir:
            is_done, msg = self._run(
                execute_navigation_action(
                    page,
                    {"action": "read_file", "path": "../../etc/passwd"},
                    "localhost",
                    [],
                    source_dir=tmpdir,
                )
            )
        self.assertFalse(is_done)
        self.assertIn("traversal", msg)

    def test_read_file_missing_path(self) -> None:
        page = self._make_page()
        with TemporaryDirectory() as tmpdir:
            is_done, msg = self._run(
                execute_navigation_action(
                    page, {"action": "read_file"}, "localhost", [], source_dir=tmpdir
                )
            )
        self.assertFalse(is_done)
        self.assertIn("missing path", msg)

    def test_read_file_not_a_file(self) -> None:
        page = self._make_page()
        with TemporaryDirectory() as tmpdir:
            Path(tmpdir, "subdir").mkdir()
            is_done, msg = self._run(
                execute_navigation_action(
                    page,
                    {"action": "read_file", "path": "subdir"},
                    "localhost",
                    [],
                    source_dir=tmpdir,
                )
            )
        self.assertFalse(is_done)
        self.assertIn("not a file", msg)

    def test_read_file_truncates_large_content(self) -> None:
        from penten_cli import AI_SOURCE_FILE_SIZE_LIMIT
        page = self._make_page()
        with TemporaryDirectory() as tmpdir:
            big = "x" * (AI_SOURCE_FILE_SIZE_LIMIT + 100)
            Path(tmpdir, "big.txt").write_text(big)
            is_done, msg = self._run(
                execute_navigation_action(
                    page,
                    {"action": "read_file", "path": "big.txt"},
                    "localhost",
                    [],
                    source_dir=tmpdir,
                )
            )
        self.assertFalse(is_done)
        self.assertIn("truncated", msg)


class RunAiNavigationLoopTests(unittest.TestCase):
    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def _make_args(self, max_steps=2):
        args = MagicMock()
        args.provider = "ollama"
        args.model = "llama3"
        args.provider_url = "http://localhost:11434"
        args.vault_file = "/tmp/missing-vault.json"
        args.max_steps = max_steps
        args.timeout = 5
        return args

    def _make_page(self):
        page = MagicMock()
        page.url = "http://localhost/"
        page.goto = AsyncMock(return_value=MagicMock(status=200))
        page.content = AsyncMock(return_value="<html><head><title>T</title></head><body></body></html>")
        page.on = MagicMock()
        page.locator = MagicMock(return_value=MagicMock(first=MagicMock(click=AsyncMock(), fill=AsyncMock())))
        page.wait_for_timeout = AsyncMock()
        return page

    @patch("penten_cli.request_ai_navigation_action")
    def test_loop_stops_on_done(self, mock_ai) -> None:
        mock_ai.return_value = '{"action":"done","summary":"explored"}'
        page = self._make_page()
        history = self._run(
            run_ai_navigation_loop(page, "http://localhost/", self._make_args(), [], [])
        )
        self.assertEqual(len(history), 1)
        self.assertIn("done", history[0])

    @patch("penten_cli.request_ai_navigation_action")
    def test_loop_respects_max_steps(self, mock_ai) -> None:
        mock_ai.return_value = '{"action":"navigate","url":"http://localhost/a"}'
        page = self._make_page()
        history = self._run(
            run_ai_navigation_loop(page, "http://localhost/", self._make_args(max_steps=2), [], [])
        )
        self.assertLessEqual(len(history), 2)

    @patch("penten_cli.request_ai_navigation_action", return_value=None)
    def test_loop_stops_when_ai_returns_none(self, _mock) -> None:
        page = self._make_page()
        history = self._run(
            run_ai_navigation_loop(page, "http://localhost/", self._make_args(), [], [])
        )
        self.assertEqual(history, [])

    @patch("penten_cli.request_ai_navigation_action")
    def test_loop_handles_parse_failure_then_recovers(self, mock_ai) -> None:
        # First response cannot be parsed; second response is a valid done action.
        responses = iter(["not json at all", '{"action":"done","summary":"ok"}'])
        mock_ai.side_effect = lambda *_a, **_kw: next(responses, None)
        page = self._make_page()
        history = self._run(
            run_ai_navigation_loop(page, "http://localhost/", self._make_args(max_steps=3), [], [])
        )
        self.assertTrue(any("done" in h for h in history))


class GitHubIssuesTests(unittest.TestCase):
    def _finding(self, severity="high", category="sqli", url="http://localhost/login", detail="detail") -> Finding:
        return Finding(category=category, severity=severity, url=url, detail=detail)

    # --- resolve_github_token ---

    def test_resolve_github_token_prefers_flag(self) -> None:
        with patch.dict("os.environ", {"GITHUB_TOKEN": "env-tok"}, clear=True):
            self.assertEqual(resolve_github_token("flag-tok"), "flag-tok")

    def test_resolve_github_token_falls_back_to_env(self) -> None:
        with patch.dict("os.environ", {"GITHUB_TOKEN": "env-tok"}, clear=True):
            self.assertEqual(resolve_github_token(""), "env-tok")

    def test_resolve_github_token_falls_back_to_gh_token(self) -> None:
        with patch.dict("os.environ", {"GH_TOKEN": "gh-tok"}, clear=True):
            self.assertEqual(resolve_github_token(""), "gh-tok")

    def test_resolve_github_token_returns_empty_when_none(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(resolve_github_token(""), "")

    # --- _github_issue_title ---

    def test_github_issue_title_format(self) -> None:
        finding = self._finding(severity="high", category="sqli", url="http://localhost/login")
        title = _github_issue_title(finding)
        self.assertIn("[penten]", title)
        self.assertIn("HIGH", title)
        self.assertIn("sqli", title)
        self.assertIn("http://localhost/login", title)

    # --- _github_api_request ---

    @patch("urllib.request.urlopen")
    def test_github_api_request_returns_dict(self, mock_urlopen) -> None:
        mock_urlopen.return_value = FakeHTTPResponse('{"number": 1, "title": "t"}')
        result = _github_api_request("GET", "/repos/o/r/issues/1", "tok")
        self.assertIsInstance(result, dict)
        self.assertEqual(result["number"], 1)

    @patch("urllib.request.urlopen")
    def test_github_api_request_returns_list(self, mock_urlopen) -> None:
        mock_urlopen.return_value = FakeHTTPResponse('[{"number": 1}]')
        result = _github_api_request("GET", "/repos/o/r/issues", "tok")
        self.assertIsInstance(result, list)

    @patch("urllib.request.urlopen", side_effect=urllib.error.URLError("err"))
    def test_github_api_request_returns_none_on_error(self, _mock) -> None:
        result = _github_api_request("GET", "/repos/o/r/issues", "tok")
        self.assertIsNone(result)

    # --- create_or_update_github_issues ---

    def test_create_or_update_no_token_prints_message(self) -> None:
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            create_or_update_github_issues([self._finding()], "owner/repo", "")
        self.assertIn("No GitHub token", buf.getvalue())

    def test_create_or_update_invalid_repo_prints_message(self) -> None:
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            create_or_update_github_issues([self._finding()], "badrepo", "tok")
        self.assertIn("Invalid repo", buf.getvalue())

    @patch("penten_cli._github_api_request")
    def test_create_or_update_creates_new_issue(self, mock_api) -> None:
        # Label exists, no existing issues, creation succeeds.
        mock_api.side_effect = [
            {"name": "penten"},          # _ensure_github_label GET
            [],                           # list existing issues
            {"number": 42, "title": "t"}, # create issue
        ]
        create_or_update_github_issues([self._finding()], "owner/repo", "tok")
        create_call = mock_api.call_args_list[2]
        self.assertEqual(create_call[0][0], "POST")
        self.assertIn("/issues", create_call[0][1])

    @patch("penten_cli._github_api_request")
    def test_create_or_update_updates_existing_issue(self, mock_api) -> None:
        finding = self._finding()
        title = _github_issue_title(finding)
        mock_api.side_effect = [
            {"name": "penten"},                      # _ensure_github_label GET
            [{"title": title, "number": 7}],          # existing issues (< 100 results, loop breaks)
            {"number": 7, "title": title},             # PATCH update
        ]
        create_or_update_github_issues([finding], "owner/repo", "tok")
        patch_call = mock_api.call_args_list[2]
        self.assertEqual(patch_call[0][0], "PATCH")
        self.assertIn("/issues/7", patch_call[0][1])

    @patch("penten_cli._github_api_request")
    def test_create_or_update_creates_label_when_missing(self, mock_api) -> None:
        mock_api.side_effect = [
            None,                           # _ensure_github_label GET returns None (missing)
            {"name": "penten"},             # _ensure_github_label POST
            [],                             # list existing issues
            {"number": 1, "title": "t"},    # create issue
        ]
        create_or_update_github_issues([self._finding()], "owner/repo", "tok")
        post_label_call = mock_api.call_args_list[1]
        self.assertEqual(post_label_call[0][0], "POST")
        self.assertIn("/labels", post_label_call[0][1])


class ParserGitHubFlagTests(unittest.TestCase):
    def test_scan_github_issues_flag(self) -> None:
        parser = build_parser()
        args = parser.parse_args([
            "scan", "--url", "http://localhost:3000", "--model", "llama3",
            "--github-issues", "--github-repo", "owner/repo", "--github-token", "tok",
        ])
        self.assertTrue(args.github_issues)
        self.assertEqual(args.github_repo, "owner/repo")
        self.assertEqual(args.github_token, "tok")

    def test_scan_github_issues_defaults(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["scan", "--url", "http://localhost:3000", "--model", "m"])
        self.assertFalse(args.github_issues)
        self.assertEqual(args.github_repo, "")
        self.assertEqual(args.github_token, "")

    def test_navigate_github_issues_flag(self) -> None:
        parser = build_parser()
        args = parser.parse_args([
            "navigate", "--url", "http://localhost:3000", "--model", "llama3",
            "--github-issues", "--github-repo", "owner/repo",
        ])
        self.assertTrue(args.github_issues)
        self.assertEqual(args.github_repo, "owner/repo")

    def test_navigate_github_issues_defaults(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["navigate", "--url", "http://localhost:3000", "--model", "m"])
        self.assertFalse(args.github_issues)
        self.assertEqual(args.github_repo, "")
        self.assertEqual(args.github_token, "")


if __name__ == "__main__":
    unittest.main()
