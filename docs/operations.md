# Operations

## Reloading

`systemctl reload systemd-creds-openbao` re-reads the configuration file without
dropping the socket or restarting the daemon:

- Added, changed and removed `[[credentials]]` rules apply to the next request.
- The daemon re-authenticates, picking up a rotated `token_file`,
  `role_id_file`, `secret_id_file` or `jwt_file`, including ones delivered as
  systemd credentials (the packaged unit sets `RefreshOnReload=credentials`).
  Changing the `BAO_*` environment or the listening socket takes a restart.
- A failed reload (an invalid file, a refused login, a failed token check) leaves
  the previous configuration serving. `systemctl reload` exits 0 either way,
  so the journal is the only signal.
- The token the previous configuration held is revoked shortly after the
  reload, and on shutdown right away, so audit logs show a revoke-self per
  replaced login. A token from `token_file` is never revoked, and a replaced
  token is left to its TTL when the daemon stops before the revocation runs.

On NixOS, `nixos-rebuild switch` applies a `settings` change as exactly this
reload. Changing `package` or `environment` restarts the daemon instead.

The service counts as started only once the daemon has authenticated.

## Failure behavior

The credential socket protocol has no error channel. A refused or failed
request surfaces to the consumer as an **empty credential**, and a payload
over systemd's 1 MiB credential limit is refused the same way. A write that
fails part way through leaves a truncated credential.

The reason is in the journal, with `UNIT=` and `CREDENTIAL=` fields on every
request and `SECRET_PATH=` once a secret was read:

```console
$ journalctl -u systemd-creds-openbao UNIT=myapp.service
$ journalctl -u systemd-creds-openbao SECRET_PATH=kv/myapp/database
```

`SECRET_PATH` is the path `bao kv get` (for `kv`) or `bao read` (for `raw`)
takes, not the `kv/data/...` form the policy uses.

[`-resolve`](cli.md#-resolve) shows which rule a request maps to and the
path it reads, without triggering one.

### Serving stale

Secrets remembered for [`serve_stale_for`](configuration.md#openbao) survive
a reload but not a restart, so the fallback covers a machine that fetched the
credential before the outage, not one that boots during it.

### Failing closed

To fail closed rather than start with an empty secret:

```ini
ExecStartPre=/bin/sh -c 'test -s "$CREDENTIALS_DIRECTORY/db-password"'
```
