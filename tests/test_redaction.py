"""Garante que o secret nao vaza pro stdout/log."""


def test_redact_short(module):
    assert module.redact("abc") == "***"


def test_redact_keeps_last_four(module):
    out = module.redact("ABCDEFGHIJKLMNOP")
    assert out.endswith("MNOP")
    assert "ABCDEFGHIJKL" not in out
    assert out.count("*") == 12


def test_redact_line_masks_only_match(module):
    line = 'token = "abcdefghijklmnopqrstuvwxyz1234567890"'
    matched = "abcdefghijklmnopqrstuvwxyz1234567890"
    out = module.redact_line(line, matched)
    assert "token =" in out
    assert matched not in out
    assert out.endswith('7890"')


def test_finding_preview_is_redacted(module):
    content = 'api_key = "abcdef1234567890abcdef1234567890"'
    findings = module.scan_content(content, module.Path("x"), "text", [])
    assert findings, "esperava encontrar a api_key"
    for f in findings:
        assert "abcdef1234567890abcdef1234567890" not in f.preview, (
            f"secret cru vazou no preview: {f.preview}"
        )
