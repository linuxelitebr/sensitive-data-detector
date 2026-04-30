# sensitive-data-detector

[![tests](https://github.com/linuxelitebr/sensitive-data-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/linuxelitebr/sensitive-data-detector/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Static analysis tool to detect leaked credentials, tokens, and OpenShift
pull-secrets in source trees. Designed for GitOps pipelines and pre-flight
audits in regulated environments.

- **Output**: human-readable text or JSON (`--json`).
- **Exit codes**: `0` clean, `1` critical finding, `2` invalid input.
  Suitable for blocking commits, MR/PRs, and ArgoCD/Tekton sync.
- **Redaction by default**: secrets in stdout/CI logs come masked.
- **Allowlist**: regex-based, file-driven (one regex per line).
- **OpenShift / Kubernetes**: detects `kubernetes.io/dockerconfigjson`
  Secrets and decodes the `.dockerconfigjson` field to flag every
  `auths.<registry>.auth` entry.
- **OCR optional**: scans images (JPG, PNG, BMP, TIFF) when `pillow` and
  `pytesseract` are installed. Per-image timeout and decompression-bomb
  guard included.

## Install

The detector itself has no required dependencies. OCR is optional:

```bash
pip install pillow pytesseract
# plus tesseract-ocr on the host
#   macOS:        brew install tesseract
#   Debian/Ubuntu: sudo apt-get install tesseract-ocr
```

## Usage

```bash
python3 sensitive-data-detector.py <directory> [options]
```

Common options:

| flag | purpose |
| --- | --- |
| `--json` | emit a JSON report on stdout (for CI consumption) |
| `--quiet` | suppress per-file progress on stderr |
| `--allowlist FILE` | regex-per-line file; matching findings are dropped |
| `--fail-on-info` | exit 1 also for IPs, internal URLs and emails |
| `--max-bytes N` | skip files larger than N bytes (default 10MB) |
| `--ocr-timeout N` | per-image OCR timeout in seconds (default 30) |
| `--ignore-dir NAME` | extra directory name to skip (repeatable) |

Exit codes:

| code | meaning |
| ---  | --- |
| `0`  | nothing critical (or only info findings, without `--fail-on-info`) |
| `1`  | critical finding (or info finding with `--fail-on-info`) |
| `2`  | invalid arguments / not a directory |

## What it detects

**Credentials and tokens (critical):**

- AWS access keys (`AKIA...`) and secret keys
- GitHub tokens (`ghp_/ghs_/gho_/ghu_/ghr_`)
- GitLab personal access tokens (`glpat-`)
- Slack tokens (`xoxb-/xoxp-/xoxa-/xoxr-/xoxs-`)
- Google API keys (`AIza...`)
- Red Hat / Quay robot tokens
- JWTs (3-segment, non-empty)
- `Bearer ...` headers (length-bounded)
- Generic `api_key=`, `token=`, `secret=`, `password=` quoted assignments
- PEM private keys (RSA, OPENSSH, EC, DSA, ENCRYPTED, PGP)

**OpenShift / Kubernetes pull-secrets (critical):**

- Raw `~/.docker/config.json` / `pull-secret.json` with `auths.*.auth`
- `Secret` manifests with `type: kubernetes.io/dockerconfigjson`
- Base64-encoded `.dockerconfigjson` field. The detector decodes it and
  reports every embedded registry auth entry separately

**Infrastructure exposure (info, non-blocking by default):**

- Private IPv4 ranges (RFC 1918)
- Internal/management URLs (`*.local`, `*.internal`, `*.corp`, `*.lan`,
  `localhost`, `127.0.0.1`)
- iDRAC / iLO / IPMI / Redfish / BMC URLs
- Email addresses

## Example

```bash
$ python3 sensitive-data-detector.py tests/fixtures/openshift --quiet

FOUND 6 potential leak(s) (6 critical, 0 info):

[CRITICAL] OpenShift Pull-Secret (decoded)
  file:    tests/fixtures/openshift/pull-secret.json
  line:    1
  preview: registry=registry.redhat.io auth=********pass
--------------------------------------------------------------------------------
[CRITICAL] Kubernetes dockerconfigjson Secret
  file:    tests/fixtures/openshift/secret.yaml
  line:    5
  preview: type: kubernetes.io/dockerconfigjson
--------------------------------------------------------------------------------
...

Statistics:
  files scanned:  2
  critical:       6
  info:           0
$ echo $?
1
```

## Pipeline integration

Snippets to copy from [`examples/`](examples/):

| file | use case |
| --- | --- |
| [`pre-commit-hook.sh`](examples/pre-commit-hook.sh) | local Git hook, scans only staged files |
| [`.pre-commit-hooks.yaml`](examples/.pre-commit-hooks.yaml) | [pre-commit](https://pre-commit.com) framework |
| [`github-actions.yml`](examples/github-actions.yml) | GitHub Actions PR/push gate, JSON artifact upload |
| [`gitlab-ci.yml`](examples/gitlab-ci.yml) | GitLab CI security stage |
| [`argocd-presync-hook.yaml`](examples/argocd-presync-hook.yaml) | ArgoCD `PreSync` Job that blocks the sync if leaks are found |
| [`tekton-task.yaml`](examples/tekton-task.yaml) | Tekton Task to chain after `git-clone` |
| [`.sdd-allowlist.example`](examples/.sdd-allowlist.example) | sample allowlist |

The pre-commit hook copies staged blobs to a temp directory and scans
there. The result reflects what is about to be committed, not the working
tree.

## Allowlist

Plain text, one regex per line. Comments start with `#`. Whatever the regex
matches *inside the detected match* drops the finding:

```text
# fixtures-only:
AKIAIOSFODNN7EXAMPLE
# example doc emails:
docs@example\.com
```

Pass with `--allowlist .sdd-allowlist`.

## Tests

```bash
pip install pytest
python3 -m pytest tests/ -v
```

The suite covers each pattern with positive and negative cases, redaction,
allowlist behaviour, exit codes, JSON output, OpenShift pull-secret
decoding, file-size limits, ignored dirs, and symlink safety.

## Limitations

- Regex-based scanner. False positives happen. Review the findings.
- The text output is for humans. For machines, use `--json`.
- OCR needs `tesseract` and runs with a per-image timeout. Accuracy
  depends on image clarity.
- The detector reads files only. No network calls, no writes.

## License

MIT. See [LICENSE](LICENSE).
