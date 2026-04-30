"""Scan de diretorio inteiro contra fixtures."""

from __future__ import annotations


def _run(module, directory):
    return module.scan_directory(
        directory,
        allowlist=[],
        ignore_dirs=module.DEFAULT_IGNORE_DIRS,
        max_bytes=10 * 1024 * 1024,
        ocr_timeout=5,
        quiet=True,
    )


def test_clean_dir_yields_no_findings(module, fixtures_dir):
    result = _run(module, fixtures_dir / "clean")
    assert result.findings == []
    assert result.scanned_files >= 2


def test_leaks_dir_yields_critical_findings(module, fixtures_dir):
    result = _run(module, fixtures_dir / "leaks")
    types = {f.type for f in result.findings}

    expected_critical = {
        "AWS Access Key",
        "GitHub Token",
        "GitLab PAT",
        "JWT Token",
        "Bearer Token",
        "Private Key (PEM)",
        "Generic API Key",
        "Generic Secret",
        "Generic Token",
        "Password Field",
    }
    missing = expected_critical - types
    assert not missing, f"patterns nao detectados: {missing}"


def test_leaks_dir_also_catches_infra(module, fixtures_dir):
    result = _run(module, fixtures_dir / "leaks")
    types = {f.type for f in result.findings}
    assert {"Private IP Address", "Internal System URL",
            "iDRAC/BMC Address", "Email Address"} <= types


def test_openshift_dir_findings(module, fixtures_dir):
    result = _run(module, fixtures_dir / "openshift")
    types = [f.type for f in result.findings]

    assert "OpenShift Pull-Secret (decoded)" in types
    assert "Kubernetes dockerconfigjson Secret" in types
    assert "Docker/OpenShift Pull-Secret (JSON)" in types


def test_max_bytes_skips_large_files(module, tmp_path):
    big = tmp_path / "huge.txt"
    big.write_text("AKIAIOSFODNN7EXAMPLE\n" + "x" * 1000)
    result = module.scan_directory(
        tmp_path,
        allowlist=[],
        ignore_dirs=module.DEFAULT_IGNORE_DIRS,
        max_bytes=100,
        ocr_timeout=5,
        quiet=True,
    )
    assert result.findings == []
    assert result.scanned_files == 0


def test_ignored_dirs_are_skipped(module, tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "leak.txt").write_text("AKIAIOSFODNN7EXAMPLE")
    (tmp_path / "clean.py").write_text("x = 1\n")
    result = _run(module, tmp_path)
    assert all(".git" not in f.file for f in result.findings)


def test_allowlist_suppresses_match(module, tmp_path):
    f = tmp_path / "demo.txt"
    f.write_text("AKIAIOSFODNN7EXAMPLE")
    import re
    findings = module.scan_file(
        f, "text", [re.compile(r"AKIAIOSFODNN7EXAMPLE")], 5,
        on_error=lambda *a: None,
    )
    assert findings == []


def test_walk_does_not_follow_symlinks(module, tmp_path):
    # symlink pra fora do diretorio nao deve ser seguido
    target = tmp_path.parent / "outside_target"
    target.mkdir(exist_ok=True)
    (target / "leak.txt").write_text("AKIAIOSFODNN7EXAMPLE")
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        import pytest
        pytest.skip("symlinks nao suportados nesse FS")

    result = _run(module, tmp_path)
    assert all(str(target) not in f.file for f in result.findings)
