"""Cada pattern: positivo (detecta) e negativo (nao gera ruido)."""

from __future__ import annotations

import pytest


def _scan(module, content: str, file_type: str = "text"):
    return module.scan_content(content, module.Path("dummy"), file_type, [])


# Positivos --------------------------------------------------------------

POSITIVE_CASES = [
    ("AWS Access Key", "key=AKIAIOSFODNN7EXAMPLE"),
    ("AWS Secret Key",
     'aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'),
    ("GitHub Token", "ghp_TESTtokenABCDEFGHIJKLMNOPQRSTUVWXYZ12"),
    ("GitLab PAT", "glpat-AAAAAAAAAAAAAAAAAAAA"),
    ("Slack Token", "xoxb-1234567890-abcdef1234567890abcdef"),
    ("Google API Key", "AIzaSyA-FAKE-KEY-FOR-TESTS-1234567890ab"),
    ("JWT Token",
     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
    ("Bearer Token", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890"),
    ("Generic API Key", 'api_key = "abcdef1234567890abcdef1234567890"'),
    ("Generic Secret", 'secret = "supersecretvalue"'),
    ("Generic Token", 'token = "abcdefghijklmnopqrstuvwxyz1234567890"'),
    ("Password Field", 'password = "MyTestPassword123"'),
    ("Private Key (PEM)", "-----BEGIN RSA PRIVATE KEY-----"),
    ("Kubernetes dockerconfigjson Secret",
     "type: kubernetes.io/dockerconfigjson"),
    ("Private IP Address", "host: 192.168.1.42"),
    ("Email Address", "contact me at user@example.com"),
    ("Internal System URL", "see https://gitlab.internal:8080/x"),
    ("iDRAC/BMC Address",
     "idrac-virtualmedia://10.0.0.100/redfish/v1/Systems/System.Embedded.1"),
]


@pytest.mark.parametrize("expected,content", POSITIVE_CASES)
def test_pattern_positive(module, expected, content):
    types = {f.type for f in _scan(module, content)}
    assert expected in types, f"missed: {expected} | got: {types}"


# Negativos --------------------------------------------------------------

NEGATIVE_CASES = [
    # AWS Access Key precisa ser maiusculo
    ("AWS Access Key", "key=akiaiosfodnn7example"),
    # AWS Access Key precisa de exatamente 16 chars apos AKIA
    ("AWS Access Key", "AKIA12345"),
    # JWT precisa de 3 segmentos, terceiro nao vazio
    ("JWT Token", "eyJabc.eyJdef."),
    # "Bearer" curto em prosa nao deve casar
    ("Bearer Token", "Bearer with"),
    # GitHub Token precisa de >=36 chars apos prefix
    ("GitHub Token", "ghp_short"),
    # PEM precisa do marcador BEGIN
    ("Private Key (PEM)", "this is not a private key"),
    # Email com TLD numerico nao deve casar
    ("Email Address", "ts@123.456"),
]


@pytest.mark.parametrize("not_expected,content", NEGATIVE_CASES)
def test_pattern_negative(module, not_expected, content):
    types = {f.type for f in _scan(module, content)}
    assert not_expected not in types, (
        f"falso positivo de {not_expected} em: {content!r} | got {types}"
    )


def test_clean_content_has_no_findings(module):
    benign = "def add(a, b):\n    return a + b\n# nothing sensitive here\n"
    assert _scan(module, benign) == []
