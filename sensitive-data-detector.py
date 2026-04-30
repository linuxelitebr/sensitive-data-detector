#!/usr/bin/env python3
"""
sensitive-data-detector.

Static analysis tool to detect leaked credentials, tokens, and OpenShift
pull-secrets in source trees. Designed for GitOps pipelines and pre-flight
audits in regulated environments.

Saida em texto pra humano ou JSON pra maquina. Exit code != 0 quando acha
algo critico, pra travar o pipeline em pre-commit, CI ou GitOps sync.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import signal
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable

try:
    from PIL import Image
    import pytesseract
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False


# Limite anti-decompression-bomb pro PIL. Default do PIL apenas avisa; aqui
# bloqueia. 50MP cobre qualquer screenshot razoavel.
if OCR_AVAILABLE:
    Image.MAX_IMAGE_PIXELS = 50_000_000


# Cada pattern tem (regex, severidade). Severidade controla o exit code:
# critical => credencial real => exit 1; info => infra/contato => exit 0 mas
# reportado.
@dataclass(frozen=True)
class PatternDef:
    name: str
    regex: re.Pattern
    severity: str  # "critical" | "info"


def _c(name: str, pattern: str, severity: str, flags: int = 0) -> PatternDef:
    return PatternDef(name=name, regex=re.compile(pattern, flags), severity=severity)


# Patterns case-sensitive por padrao. IGNORECASE entra inline com (?i) so onde
# faz sentido (campos como "password", "api_key").
PATTERNS: tuple[PatternDef, ...] = (
    # Cloud / VCS tokens. Formato fixo, case-sensitive.
    _c("AWS Access Key", r"\bAKIA[0-9A-Z]{16}\b", "critical"),
    _c("AWS Secret Key",
       r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})\b",
       "critical"),
    _c("GitHub Token", r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b", "critical"),
    _c("GitLab PAT", r"\bglpat-[A-Za-z0-9_\-]{20,}\b", "critical"),
    _c("Slack Token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b", "critical"),
    _c("Google API Key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "critical"),
    _c("RH/Quay Robot Token", r"\b[a-z0-9_\-]+\+[a-z0-9_\-]+:[A-Z0-9]{40,}\b", "critical"),

    # JWT precisa dos 3 segmentos. Terceiro nao pode ser vazio.
    _c("JWT Token",
       r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b",
       "critical"),

    # Bearer com tamanho minimo no token, pra nao casar "Bearer foo" em texto corrido.
    _c("Bearer Token",
       r"[Bb]earer\s+[A-Za-z0-9\-._~+/]{20,}=*",
       "critical"),

    # Campos genericos
    _c("Generic API Key",
       r"(?i)\bapi[_\-]?key[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-]{20,})[\"']",
       "critical"),
    _c("Generic Secret",
       r"(?i)\bsecret[\"']?\s*[:=]\s*[\"']([^\"']{8,})[\"']",
       "critical"),
    _c("Generic Token",
       r"(?i)\btoken[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-\.]{20,})[\"']",
       "critical"),
    _c("Password Field",
       r"(?i)\bpassword[\"']?\s*[:=]\s*[\"']([^\"'\s$<{][^\"'\s]{2,})[\"']",
       "critical"),

    # PEM e case-sensitive de verdade.
    _c("Private Key (PEM)",
       r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED |PGP )?PRIVATE KEY-----",
       "critical"),

    # OpenShift / K8s pull-secrets
    # 1) JSON cru estilo ~/.docker/config.json ou /etc/pull-secret.json
    _c("Docker/OpenShift Pull-Secret (JSON)",
       r'"auths"\s*:\s*\{[^}]*"auth"\s*:\s*"[A-Za-z0-9+/=]{8,}"',
       "critical"),
    # 2) Secret K8s/OpenShift type kubernetes.io/dockerconfigjson
    _c("Kubernetes dockerconfigjson Secret",
       r"(?i)type\s*:\s*kubernetes\.io/dockerconfigjson",
       "critical"),
    # 3) Campo .dockerconfigjson em Secret YAML (base64 do JSON)
    _c("dockerconfigjson Field",
       r"(?i)\.dockerconfigjson\s*:\s*[A-Za-z0-9+/=]{40,}",
       "critical"),

    # Coisas de infraestrutura. Reportado como info, nao falha o build sozinho.
    _c("iDRAC/BMC Address",
       r"(?i)(?:idrac|redfish|ipmi|ilo|bmc)(?:-virtualmedia)?://"
       r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[^\s\"']*",
       "info"),
    _c("Private IP Address",
       r"\b(?:10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
       r"|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}"
       r"|192\.168\.[0-9]{1,3}\.[0-9]{1,3})\b",
       "info"),
    _c("Email Address",
       r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
       "info"),
    _c("Internal System URL",
       r"https?://(?:localhost|127\.0\.0\.1"
       r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
       r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
       r"|192\.168\.\d{1,3}\.\d{1,3}"
       r"|[\w\-]+\.(?:local|internal|corp|lan))(?::\d+)?[^\s\"']*",
       "info"),
)


CRITICAL_NAMES = frozenset(p.name for p in PATTERNS if p.severity == "critical")


# Binarios e formatos onde regex em texto cru nao serve.
IGNORE_EXTENSIONS = frozenset({
    ".exe", ".bin", ".so", ".dll", ".dylib", ".o", ".a",
    ".pyc", ".pyo", ".class", ".jar", ".war",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".7z", ".rar",
    ".mp3", ".mp4", ".mov", ".avi", ".webm", ".ogg",
    ".woff", ".woff2", ".ttf", ".eot",
})

IMAGE_EXTENSIONS = frozenset({".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".tif"})

DEFAULT_IGNORE_DIRS = frozenset({
    ".git", ".svn", ".hg",
    "node_modules", "bower_components",
    "venv", ".venv", "env", ".env",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "dist", "build", "out", "target", "bin", "obj",
    ".next", ".nuxt", ".cache",
    "coverage", ".coverage",
    "vendor",
    ".idea", ".vscode",
})


@dataclass
class Finding:
    type: str
    severity: str
    file: str
    line: int | str
    preview: str  # ja redacted

    def to_dict(self) -> dict:
        return asdict(self)


# ---------- Redaction --------------------------------------------------------

def redact(value: str, show: int = 4) -> str:
    """Mascara segredo deixando so os ultimos `show` chars visiveis.

    Usado pra nao vazar o secret no stdout/log de CI. Quem quiser o valor
    inteiro tem que abrir o arquivo na mao.
    """
    if not value:
        return value
    s = value.strip()
    if len(s) <= show:
        return "*" * len(s)
    return f"{'*' * (len(s) - show)}{s[-show:]}"


def redact_line(line: str, match_text: str, show: int = 4) -> str:
    """Aplica redact() so na parte do match, preservando contexto da linha."""
    if not match_text or match_text not in line:
        return redact(line, show=show)
    return line.replace(match_text, redact(match_text, show=show))


# ---------- File walking -----------------------------------------------------

def should_scan_file(path: Path, max_bytes: int) -> tuple[bool, str | None]:
    ext = path.suffix.lower()

    if ext in IGNORE_EXTENSIONS:
        return False, None

    # Checa tamanho antes de tudo. Vale tambem pra imagem: OCR em arquivo
    # gigante trava o pipeline.
    try:
        size = path.stat().st_size
    except OSError:
        return False, None
    if size > max_bytes:
        return False, None

    if ext in IMAGE_EXTENSIONS:
        return True, "image"
    if ext == ".svg":
        return True, "svg"
    return True, "text"


def walk_files(root: Path, ignore_dirs: frozenset[str]) -> Iterable[Path]:
    for dirpath, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for name in files:
            yield Path(dirpath) / name


# ---------- OCR --------------------------------------------------------------

class _OCRTimeout(Exception):
    pass


def _ocr_alarm(_signum, _frame):
    raise _OCRTimeout()


def extract_text_from_image(path: Path, timeout_seconds: int = 30) -> str | None:
    """Roda OCR com timeout. Retorna None se OCR indisponivel ou erro."""
    if not OCR_AVAILABLE:
        return None

    use_alarm = hasattr(signal, "SIGALRM")
    old_handler = None
    if use_alarm:
        old_handler = signal.signal(signal.SIGALRM, _ocr_alarm)
        signal.alarm(timeout_seconds)

    try:
        with Image.open(path) as img:
            img.load()  # forca decode dentro do timeout
            return pytesseract.image_to_string(img)
    except _OCRTimeout:
        return None
    except (OSError, ValueError):
        return None
    except Exception:
        # tesseract pode levantar varios tipos. Engole pra nao matar o scan
        # inteiro, mas devolve None pro chamador saber que falhou.
        return None
    finally:
        if use_alarm:
            signal.alarm(0)
            if old_handler is not None:
                signal.signal(signal.SIGALRM, old_handler)


# ---------- Scanning core ----------------------------------------------------

def _build_line_index(content: str) -> list[int]:
    """Indice de offsets de inicio de linha pra busca O(log n) por linha."""
    starts = [0]
    for i, ch in enumerate(content):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def _line_at(starts: list[int], offset: int) -> int:
    lo, hi = 0, len(starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= offset:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


def scan_content(
    content: str,
    file_path: Path,
    file_type: str,
    allowlist: list[re.Pattern],
) -> list[Finding]:
    if not content:
        return []

    findings: list[Finding] = []
    line_starts = _build_line_index(content) if file_type != "image" else []
    lines = content.split("\n") if file_type != "image" else []

    for pat in PATTERNS:
        for m in pat.regex.finditer(content):
            matched = m.group(0)
            if any(a.search(matched) for a in allowlist):
                continue

            if file_type == "image":
                preview = redact(matched[:120])
                line_ref: int | str = "N/A (OCR)"
            else:
                line_num = _line_at(line_starts, m.start())
                line_text = lines[line_num - 1] if line_num <= len(lines) else matched
                preview = redact_line(line_text.strip()[:200], matched)
                line_ref = line_num

            findings.append(Finding(
                type=pat.name,
                severity=pat.severity,
                file=str(file_path),
                line=line_ref,
                preview=preview,
            ))
    return findings


def scan_file(
    file_path: Path,
    file_type: str,
    allowlist: list[re.Pattern],
    ocr_timeout: int,
    on_error,
) -> list[Finding]:
    try:
        if file_type == "image":
            content = extract_text_from_image(file_path, timeout_seconds=ocr_timeout)
            if content is None:
                return []
            return scan_content(content, file_path, "image", allowlist)
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return scan_content(content, file_path, file_type, allowlist)
    except (OSError, UnicodeDecodeError) as e:
        on_error(file_path, e)
        return []


# ---------- Heuristica extra: dockerconfigjson decodificado ------------------

DOCKERCONFIG_JSON_NAMES = re.compile(
    r"(?:\.?dockerconfigjson|config\.json|pull[\-_]?secret(?:\.json)?)$",
    re.IGNORECASE,
)


def inspect_pull_secret_file(path: Path) -> list[Finding]:
    """Detecta pull-secret real em arquivo cujo nome bate com o padrao tipico
    (config.json, pull-secret.json, .dockerconfigjson). Decodifica o base64 de
    auths.<registry>.auth quando presente. Assim, alem do regex em texto cru,
    pega tambem casos onde o JSON ta dentro de um K8s Secret (campo
    data['.dockerconfigjson']).
    """
    findings: list[Finding] = []
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    candidates: list[str] = []

    try:
        obj = json.loads(raw)
        if isinstance(obj, dict) and "auths" in obj:
            candidates.append(raw)
    except json.JSONDecodeError:
        pass

    m = re.search(
        r"(?:^|\n)\s*\.?dockerconfigjson\s*:\s*([A-Za-z0-9+/=]+)",
        raw,
    )
    if m:
        try:
            decoded = base64.b64decode(m.group(1), validate=True).decode("utf-8", "replace")
            if '"auths"' in decoded:
                candidates.append(decoded)
        except (binascii.Error, ValueError):
            pass

    for cand in candidates:
        try:
            obj = json.loads(cand)
        except json.JSONDecodeError:
            continue
        for registry, entry in (obj.get("auths") or {}).items():
            if isinstance(entry, dict) and entry.get("auth"):
                findings.append(Finding(
                    type="OpenShift Pull-Secret (decoded)",
                    severity="critical",
                    file=str(path),
                    line=1,
                    preview=f"registry={registry} auth={redact(entry['auth'])}",
                ))
    return findings


# ---------- Driver -----------------------------------------------------------

@dataclass
class ScanResult:
    findings: list[Finding]
    scanned_files: int
    skipped_images: int
    errors: list[tuple[str, str]]


def scan_directory(
    directory: Path,
    *,
    allowlist: list[re.Pattern],
    ignore_dirs: frozenset[str],
    max_bytes: int,
    ocr_timeout: int,
    quiet: bool,
) -> ScanResult:
    findings: list[Finding] = []
    scanned = 0
    skipped_images = 0
    errors: list[tuple[str, str]] = []

    def on_error(p: Path, e: Exception) -> None:
        errors.append((str(p), f"{type(e).__name__}: {e}"))

    for path in walk_files(directory, ignore_dirs):
        ok, ftype = should_scan_file(path, max_bytes)
        if not ok:
            continue
        if ftype == "image" and not OCR_AVAILABLE:
            skipped_images += 1
            continue

        scanned += 1
        if not quiet:
            tag = ""
            if ftype == "image":
                tag = " (OCR)"
            elif ftype == "svg":
                tag = " (SVG)"
            print(f"[{scanned}] scanning: {path}{tag}", file=sys.stderr)

        file_findings = scan_file(path, ftype, allowlist, ocr_timeout, on_error)

        if DOCKERCONFIG_JSON_NAMES.search(path.name):
            file_findings.extend(inspect_pull_secret_file(path))

        findings.extend(file_findings)

    return ScanResult(
        findings=findings,
        scanned_files=scanned,
        skipped_images=skipped_images,
        errors=errors,
    )


# ---------- Reporters --------------------------------------------------------

def report_text(result: ScanResult, *, fail_on_info: bool) -> int:
    findings = result.findings
    critical = [f for f in findings if f.severity == "critical"]
    info = [f for f in findings if f.severity == "info"]

    if findings:
        print(f"\nFOUND {len(findings)} potential leak(s) "
              f"({len(critical)} critical, {len(info)} info):\n")
        for f in findings:
            tag = "CRITICAL" if f.severity == "critical" else "info"
            print(f"[{tag}] {f.type}")
            print(f"  file:    {f.file}")
            print(f"  line:    {f.line}")
            print(f"  preview: {f.preview}")
            print("-" * 78)
    else:
        print("\nNo sensitive data detected.")

    print("\nStatistics:")
    print(f"  files scanned:  {result.scanned_files}")
    if result.skipped_images:
        print(f"  images skipped: {result.skipped_images} (OCR unavailable)")
    print(f"  critical:       {len(critical)}")
    print(f"  info:           {len(info)}")
    if result.errors:
        print(f"  read errors:    {len(result.errors)}")
        for path, msg in result.errors[:10]:
            print(f"    - {path}: {msg}")

    if critical:
        return 1
    if info and fail_on_info:
        return 1
    return 0


def report_json(result: ScanResult, *, fail_on_info: bool) -> int:
    critical = [f for f in result.findings if f.severity == "critical"]
    info = [f for f in result.findings if f.severity == "info"]
    payload = {
        "summary": {
            "files_scanned": result.scanned_files,
            "images_skipped": result.skipped_images,
            "critical": len(critical),
            "info": len(info),
            "errors": len(result.errors),
        },
        "findings": [f.to_dict() for f in result.findings],
        "errors": [{"file": p, "error": m} for p, m in result.errors],
    }
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    if critical:
        return 1
    if info and fail_on_info:
        return 1
    return 0


# ---------- CLI --------------------------------------------------------------

def _load_allowlist(path: Path | None) -> list[re.Pattern]:
    if not path:
        return []
    out: list[re.Pattern] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            out.append(re.compile(line))
        except re.error as e:
            print(f"warning: invalid allowlist regex '{line}': {e}", file=sys.stderr)
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sensitive-data-detector",
        description="Static analysis for leaked credentials, tokens and "
                    "OpenShift pull-secrets in source trees.",
    )
    p.add_argument("directory", help="directory to scan")
    p.add_argument("--json", action="store_true", help="emit JSON report on stdout")
    p.add_argument("--quiet", action="store_true",
                   help="suppress per-file progress (recommended in CI)")
    p.add_argument("--allowlist", type=Path,
                   help="file with one regex per line; matches are ignored")
    p.add_argument("--max-bytes", type=int, default=10 * 1024 * 1024,
                   help="skip files larger than this (default: 10MB)")
    p.add_argument("--ocr-timeout", type=int, default=30,
                   help="OCR timeout per image in seconds (default: 30)")
    p.add_argument("--fail-on-info", action="store_true",
                   help="exit non-zero even for info-level findings (IPs, emails, internal URLs)")
    p.add_argument("--ignore-dir", action="append", default=[],
                   help="extra directory name to ignore (repeatable)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"error: '{args.directory}' is not a valid directory", file=sys.stderr)
        return 2

    ignore_dirs = DEFAULT_IGNORE_DIRS | frozenset(args.ignore_dir)
    allowlist = _load_allowlist(args.allowlist)

    if not args.quiet and not args.json:
        print(f"Scanning: {directory}", file=sys.stderr)
        print(f"OCR: {'enabled' if OCR_AVAILABLE else 'disabled (pip install pillow pytesseract)'}",
              file=sys.stderr)

    result = scan_directory(
        directory,
        allowlist=allowlist,
        ignore_dirs=ignore_dirs,
        max_bytes=args.max_bytes,
        ocr_timeout=args.ocr_timeout,
        quiet=args.quiet or args.json,
    )

    if args.json:
        return report_json(result, fail_on_info=args.fail_on_info)
    return report_text(result, fail_on_info=args.fail_on_info)


if __name__ == "__main__":
    sys.exit(main())
