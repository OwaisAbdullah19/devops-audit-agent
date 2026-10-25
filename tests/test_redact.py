from redact import redact, register_secret


def test_literal_assignments_are_redacted():
    out = redact('password = "hunter2hunter2"\nAPI_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"')
    assert "hunter2" not in out and "abcdefghijklmnop" not in out
    assert "[REDACTED" in out


def test_env_lookups_and_placeholders_kept():
    for line in ['password = os.environ["PW"]', "token: ${{ secrets.TOKEN }}", "API_KEY=your_key_here",
                 "secret = get_secret_value", "password: str"]:
        assert redact(line) == line


def test_known_token_formats():
    assert "AKIA" not in redact("id AKIAABCDEFGHIJKLMNOP")
    assert "ghp_" not in redact("t ghp_" + "b" * 36)
    assert "pass123" not in redact("postgres://user:pass123456@host/db")


def test_private_key_block_preserves_line_count():
    text = "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\ndef\n-----END RSA PRIVATE KEY-----\nz"
    out = redact(text)
    assert "MIIE" not in out and out.count("\n") == text.count("\n")


def test_registered_secret_masked():
    register_secret("super-secret-llm-key-123")
    assert "super-secret" not in redact("key=super-secret-llm-key-123")
