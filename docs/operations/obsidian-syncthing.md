# Optional Obsidian sync with Syncthing

Syncthing can replace rsync when both devices are frequently online. Share only
the Link2Vault vault directory, not the SQLite database, media directory,
configuration, logs, or secret files.

Recommended folder policy:

- Server folder type: Send Only.
- Mac folder type: Receive Only.
- File versioning: enabled on the Mac.
- Ignore patterns: `.partial`, temporary editor files, and `.DS_Store`.

Resolve conflicts on the server first. Do not configure automatic deletion as
part of the initial rollout; full history is a product requirement.
