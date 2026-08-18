#!/usr/bin/env bash
set -euo pipefail

backup_dir=""
data_dir=""
vault_dir=""
confirmed=false

while (($# > 0)); do
  case "$1" in
    --backup) backup_dir="${2:-}"; shift 2 ;;
    --data-dir) data_dir="${2:-}"; shift 2 ;;
    --vault) vault_dir="${2:-}"; shift 2 ;;
    --confirm-restore) confirmed=true; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ "$confirmed" == true ]] || { echo "--confirm-restore is required" >&2; exit 2; }
for value in "$backup_dir" "$data_dir" "$vault_dir"; do
  [[ -n "$value" && "$value" != *'$'* && "$value" != "/" ]] || {
    echo "all paths must be resolved and non-root" >&2
    exit 2
  }
done
[[ -d "$backup_dir" && ! -L "$backup_dir" ]] || { echo "invalid backup" >&2; exit 2; }
[[ -f "$backup_dir/link2vault.sqlite3" ]] || { echo "backup database is missing" >&2; exit 2; }
[[ -d "$backup_dir/vault" && ! -L "$backup_dir/vault" ]] || { echo "backup vault is missing" >&2; exit 2; }
[[ ! -e "$data_dir" && ! -L "$data_dir" ]] || { echo "data destination already exists" >&2; exit 3; }
[[ ! -e "$vault_dir" && ! -L "$vault_dir" ]] || { echo "vault destination already exists" >&2; exit 3; }
[[ -d "$(dirname "$data_dir")" && ! -L "$(dirname "$data_dir")" ]] || { echo "invalid data parent" >&2; exit 2; }
[[ -d "$(dirname "$vault_dir")" && ! -L "$(dirname "$vault_dir")" ]] || { echo "invalid vault parent" >&2; exit 2; }

python3 - "$backup_dir/link2vault.sqlite3" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
result = connection.execute("PRAGMA integrity_check").fetchone()[0]
connection.close()
if result != "ok":
    raise SystemExit("backup database integrity check failed")
PY

mkdir "$data_dir" "$vault_dir"
cp "$backup_dir/link2vault.sqlite3" "$data_dir/link2vault.sqlite3"
rsync --archive "$backup_dir/vault/" "$vault_dir/"
