import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from penten_cli import (
    build_parser,
    build_registration_value,
    configure_provider,
    generate_ai_payloads,
    is_internal_url,
    load_vault,
    path_from_url,
    resolve_provider_api_key,
    resolve_provider_url,
    save_vault,
    validate_local_url,
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

    def test_resolve_provider_url(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(resolve_provider_url("ollama", ""), "http://127.0.0.1:11434")
            self.assertEqual(resolve_provider_url("deepseek", ""), "https://api.deepseek.com")
            self.assertEqual(resolve_provider_url("glm", ""), "https://open.bigmodel.cn/api/paas/v4")
            self.assertEqual(resolve_provider_url("gemini", ""), "https://generativelanguage.googleapis.com")

    @patch.dict("os.environ", {"DEEPSEEK_API_KEY": "d", "GLM_API_KEY": "g", "GEMINI_API_KEY": "m"}, clear=False)
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


if __name__ == "__main__":
    unittest.main()
