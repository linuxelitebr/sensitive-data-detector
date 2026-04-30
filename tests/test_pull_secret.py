"""Casos espec\u00edficos de OpenShift / K8s pull-secrets."""

from __future__ import annotations


def test_decoded_pull_secret_finds_each_registry(module, fixtures_dir):
    findings = module.inspect_pull_secret_file(fixtures_dir / "openshift" / "pull-secret.json")
    types = [f.type for f in findings]
    registries = [f.preview for f in findings]
    assert types.count("OpenShift Pull-Secret (decoded)") == 2
    assert any("registry.redhat.io" in p for p in registries)
    assert any("quay.io" in p for p in registries)


def test_k8s_secret_yaml_decodes_dockerconfigjson(module, fixtures_dir):
    findings = module.inspect_pull_secret_file(fixtures_dir / "openshift" / "secret.yaml")
    assert any(f.type == "OpenShift Pull-Secret (decoded)" for f in findings), \
        "deveria decodificar o .dockerconfigjson e achar o auth"


def test_pull_secret_auth_value_is_redacted(module, fixtures_dir):
    findings = module.inspect_pull_secret_file(fixtures_dir / "openshift" / "pull-secret.json")
    for f in findings:
        # "dXNlcjpwYXNz" e o auth cru. Nao pode aparecer inteiro no preview.
        assert "dXNlcjpwYXNz" not in f.preview


def test_dockerconfigjson_regex_matches_yaml(module, fixtures_dir):
    raw = (fixtures_dir / "openshift" / "secret.yaml").read_text()
    types = {f.type for f in module.scan_content(
        raw, module.Path("secret.yaml"), "text", []
    )}
    assert "Kubernetes dockerconfigjson Secret" in types
    assert "dockerconfigjson Field" in types
