#!/usr/bin/env bash
set -euo pipefail

data_dir=""
vault_dir=""
destination=""

while (($# > 0)); do
  case "$1" in
    --data-dir) data_dir="${2:-}"; shift 2 ;;
    --vault) vault_dir="${2:-}"; shift 2 ;;
    --destination) destination="${2:-}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

for value in "$data_dir" "$vault_dir" "$destination"; do
  [[ -n "$value" && "$value" != *'$'* ]] || {
    echo "all paths are required and must be resolved" >&2
    exit 2
  }
done
[[ "$destination" != "/" ]] || { echo "root is not a backup destination" >&2; exit 2; }
[[ -d "$data_dir" && ! -L "$data_dir" ]] || { echo "invalid data directory" >&2; exit 2; }
[[ -d "$vault_dir" && ! -L "$vault_dir" ]] || { echo "invalid vault directory" >&2; exit 2; }
[[ -d "$destination" && ! -L "$destination" ]] || { echo "invalid backup destination" >&2; exit 2; }
database_path="${data_dir%/}/link2vault.sqlite3"
[[ -f "$database_path" && ! -L "$database_path" ]] || { echo "database is missing" >&2; exit 2; }

backup_name="backup-$(date -u +%Y%m%dT%H%M%SZ)-$$"
partial_path="${destination%/}/.${backup_name}.partial"
final_path="${destination%/}/${backup_name}"
mkdir "$partial_path"
mkdir "$partial_path/vault"

python3 - "$database_path" "$partial_path/link2vault.sqlite3" <<'PY'
import sqlite3
import sys

source = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
target = sqlite3.connect(sys.argv[2])
with target:
    source.backup(target)
target.close()
source.close()
PY

rsync --archive "${vault_dir%/}/" "$partial_path/vault/"
printf 'schema_version=1\n' > "$partial_path/manifest.txt"
mv "$partial_path" "$final_path"
printf '%s\n' "$final_path"
