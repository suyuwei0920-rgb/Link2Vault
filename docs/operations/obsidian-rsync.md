# Obsidian sync with rsync

The server remains the source of truth. The sync helper copies the full vault
history to an existing local Obsidian directory and never enables deletion.

```bash
scripts/sync_vault_rsync.sh \
  --source 'operator@example.com:/srv/link2vault/vault' \
  --destination '/path/to/Obsidian/Link2Vault' \
  --dry-run
```

Remove `--dry-run` only after reviewing the output. The destination must not be
root or a symlink. A destination-specific lock prevents overlapping jobs. The
script uses rsync partial transfers and does not pass `--delete`.

For scheduled sync on macOS, create a user LaunchAgent that calls the same
command with absolute paths. Keep SSH keys outside this repository and use a
read-only server account restricted to the vault export path.
