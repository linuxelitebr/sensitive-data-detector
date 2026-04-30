#!/usr/bin/env bash
# .git/hooks/pre-commit
#
# Bloqueia commit se sensitive-data-detector achar credenciais nos arquivos
# staged. Copia esse arquivo pra .git/hooks/pre-commit e da chmod +x.
#
# Comportamento:
#   - escaneia so o que esta staged (nao o working tree inteiro)
#   - usa um diretorio temp pra refletir o que vai virar commit
#   - exit 1 do detector aborta o commit

repo=$(git rev-parse --show-toplevel)
detector="$repo/sensitive-data-detector.py"

if [ ! -f "$detector" ]; then
  echo "pre-commit: detector nao encontrado em $detector" >&2
  exit 1
fi

staged=$(git diff --cached --name-only --diff-filter=ACMR)
[ -z "$staged" ] && exit 0

tmp=$(mktemp -d)
trap "rm -rf $tmp" EXIT

while read -r path; do
  [ -z "$path" ] && continue
  mkdir -p "$tmp/$(dirname "$path")"
  git show ":$path" > "$tmp/$path"
done <<< "$staged"

allow=()
[ -f "$repo/.sdd-allowlist" ] && allow=(--allowlist "$repo/.sdd-allowlist")

python3 "$detector" "$tmp" --quiet "${allow[@]}"
rc=$?

if [ $rc -ne 0 ]; then
  echo
  echo "pre-commit: encontrei credenciais em arquivos staged. Commit abortado."
  echo "  - corrige o conteudo, ou"
  echo "  - adiciona um regex em .sdd-allowlist se for falso positivo, ou"
  echo "  - usa 'git commit --no-verify' por sua conta e risco."
  exit $rc
fi
