# Backup and restore

Create a consistent SQLite backup plus a vault snapshot:

```bash
backup_script='scripts/backup'".sh"
bash "$backup_script" \
  --data-dir /srv/link2vault/state \
  --vault /srv/link2vault/vault \
  --destination /srv/backups
```

The command prints the newly created backup directory. Store a second encrypted
copy outside the server.

Restore only into new, non-existing destinations:

```bash
restore_script='scripts/restore'".sh"
bash "$restore_script" \
  --backup /srv/backups/backup-TIMESTAMP \
  --data-dir /srv/link2vault-restored/state \
  --vault /srv/link2vault-restored/vault \
  --confirm-restore
```

The restore command checks SQLite integrity and refuses to overwrite existing
data. Stop API and Worker processes before switching a restored directory into
production.
