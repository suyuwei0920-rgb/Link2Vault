#!/usr/bin/env bash
set -euo pipefail

source_path=""
destination_path=""
dry_run=false

while (($# > 0)); do
  case "$1" in
    --source)
      (($# >= 2)) || { echo "--source requires a value" >&2; exit 2; }
      source_path="$2"
      shift 2
      ;;
    --destination)
      (($# >= 2)) || { echo "--destination requires a value" >&2; exit 2; }
      destination_path="$2"
      shift 2
      ;;
    --dry-run)
      dry_run=true
      shift
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

[[ -n "$source_path" ]] || { echo "source is required" >&2; exit 2; }
[[ -n "$destination_path" ]] || { echo "destination is required" >&2; exit 2; }
[[ "$source_path" != *'$'* && "$destination_path" != *'$'* ]] || {
  echo "unresolved variables are not allowed" >&2
  exit 2
}
[[ "$destination_path" != "/" ]] || { echo "root is not a destination" >&2; exit 2; }
[[ ! -L "$destination_path" ]] || { echo "symlink destination is not allowed" >&2; exit 2; }
[[ -d "$destination_path" ]] || { echo "destination must be an existing directory" >&2; exit 2; }

lock_path="${destination_path}.link2vault-sync.lock"
if ! mkdir "$lock_path" 2>/dev/null; then
  echo "sync is already running" >&2
  exit 3
fi
trap 'rmdir "$lock_path" 2>/dev/null || true' EXIT INT TERM

rsync_arguments=(
  --archive
  --partial
  --partial-dir=.partial
  --delay-updates
)
if [[ "$dry_run" == true ]]; then
  rsync_arguments+=(--dry-run)
fi

rsync "${rsync_arguments[@]}" "${source_path%/}/" "${destination_path%/}/"
