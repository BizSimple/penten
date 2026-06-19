import unittest

from penten_cli import (
    build_registration_value,
    is_internal_url,
    path_from_url,
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


class URLHelpersTests(unittest.TestCase):
    def test_is_internal_url(self) -> None:
        self.assertTrue(is_internal_url("localhost", "/relative/path"))
        self.assertTrue(is_internal_url("localhost", "http://localhost/a"))
        self.assertFalse(is_internal_url("localhost", "http://127.0.0.1/a"))

    def test_path_from_url(self) -> None:
        self.assertEqual(path_from_url("http://localhost"), "/")
        self.assertEqual(path_from_url("http://localhost/x/y?q=1"), "/x/y")


class FormValueTests(unittest.TestCase):
    def test_registration_values(self) -> None:
        self.assertIn("@example.com", build_registration_value("email", "email", 1, False, "X"))
        self.assertEqual(build_registration_value("password", "password", 0, False, "X"), "StrongPass123!")
        self.assertIn("penten_user_", build_registration_value("username", "text", 0, False, "X"))

    def test_injected_prefers_payload_for_text(self) -> None:
        self.assertEqual(build_registration_value("name", "text", 0, True, "PAYLOAD"), "PAYLOAD")


if __name__ == "__main__":
    unittest.main()
