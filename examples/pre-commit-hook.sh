#!/usr/bin/env bash
# .git/hooks/pre-commit
#
# Bloqueia commit se sensitive-data-detector achar credenciais nos arquivos
# staged. Copia esse arquivo pra .git/hooks/pre-commit e da chmod +x.
#
# Comportamento:
#   - escaneia so o que esta staged (nao o working tree inteiro)
#   - usa um diretorio temp pra evitar varrer o repo todo
#   - exit 1 do detector aborta o commit

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
DETECTOR="${REPO_ROOT}/sensitive-data-detector.py"

if [[ ! -x "$DETECTOR" && ! -f "$DETECTOR" ]]; then
  echo "pre-commit: detector nao encontrado em $DETECTOR" >&2
  exit 1
fi

STAGED="$(git diff --cached --name-only --diff-filter=ACMR)"
if [[ -z "$STAGED" ]]; then
  exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  mkdir -p "$TMP/$(dirname "$path")"
  git show ":$path" > "$TMP/$path" 2>/dev/null || true
done <<< "$STAGED"

python3 "$DETECTOR" "$TMP" --quiet --allowlist "${REPO_ROOT}/.sdd-allowlist" 2>/dev/null \
  || python3 "$DETECTOR" "$TMP" --quiet
rc=$?

if [[ $rc -ne 0 ]]; then
  echo
  echo "pre-commit: encontrei credenciais em arquivos staged. Commit abortado."
  echo "  - corrige o conteudo, ou"
  echo "  - adiciona um regex em .sdd-allowlist se for falso positivo, ou"
  echo "  - usa 'git commit --no-verify' por sua conta e risco."
  exit "$rc"
fi
