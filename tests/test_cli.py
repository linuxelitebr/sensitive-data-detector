"""Testes end-to-end via subprocess. Cobrem exit code e formato de saida —
o que pipelines de CI/GitOps consomem.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "sensitive-data-detector.py"


def run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=cwd,
    )


def test_exit_zero_on_clean_dir(fixtures_dir):
    result = run_cli(str(fixtures_dir / "clean"), "--quiet")
    assert result.returncode == 0, result.stdout + result.stderr


def test_exit_one_on_critical_leak(fixtures_dir):
    result = run_cli(str(fixtures_dir / "leaks"), "--quiet")
    assert result.returncode == 1, "esperava exit 1 quando ha critical"
    assert "CRITICAL" in result.stdout


def test_exit_two_on_invalid_directory(tmp_path):
    result = run_cli(str(tmp_path / "nope"))
    assert result.returncode == 2


def test_json_output_is_valid_and_has_summary(fixtures_dir):
    result = run_cli(str(fixtures_dir / "leaks"), "--json", "--quiet")
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert "summary" in payload
    assert payload["summary"]["critical"] > 0
    assert all("severity" in f for f in payload["findings"])


def test_json_output_redacts_secrets(fixtures_dir):
    result = run_cli(str(fixtures_dir / "leaks"), "--json", "--quiet")
    payload = json.loads(result.stdout)
    raw = json.dumps(payload)
    # Secrets crus que nao podem aparecer na saida
    assert "abcdef1234567890abcdef1234567890" not in raw
    assert "MyTestPassword123" not in raw


def test_fail_on_info_flag(tmp_path):
    f = tmp_path / "infra.txt"
    f.write_text("host=192.168.10.20\n")
    # sem flag: info nao falha
    r1 = run_cli(str(tmp_path), "--quiet")
    assert r1.returncode == 0
    # com flag: info falha
    r2 = run_cli(str(tmp_path), "--quiet", "--fail-on-info")
    assert r2.returncode == 1


def test_allowlist_file_suppresses_findings(tmp_path):
    leak = tmp_path / "leak.txt"
    leak.write_text("AKIAIOSFODNN7EXAMPLE\n")
    allow = tmp_path / "allow.txt"
    allow.write_text("# comment\nAKIAIOSFODNN7EXAMPLE\n")

    result = run_cli(str(tmp_path), "--quiet", "--allowlist", str(allow))
    assert result.returncode == 0


def test_openshift_pull_secret_triggers_critical(fixtures_dir):
    result = run_cli(str(fixtures_dir / "openshift"), "--json", "--quiet")
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    types = {f["type"] for f in payload["findings"]}
    assert "OpenShift Pull-Secret (decoded)" in types
