# Operations

## Starting

The service counts as started only once the daemon has authenticated. A login
that fails on an outage (OpenBao down, sealed, unreachable) is retried for as
long as it takes, so `systemctl start` blocks until then (`--no-block` returns
at once). A login that OpenBao rejects outright (a wrong secret ID, an invalid
token, a server certificate that does not verify) fails the service instead,
and systemd keeps restarting it with a delay growing to a minute, so a
corrected credential is picked up without further action. OpenBao's user
lockout, on by default for `approle`, locks the role after five rejected
logins, which those restarts reach within a minute, so a corrected secret ID
can still be refused for the fifteen minutes the lockout lasts.

A consumer that starts before the daemon is ready blocks in its `LoadCredential=`
fetch until the daemon has authenticated. A `Type=exec` or `Type=notify`
consumer fails when its own start timeout runs out first, a `Type=simple` one
counts as running while it waits. To wait for as long as it takes, order the
consumer after the service:

```ini
[Unit]
Wants=systemd-creds-openbao.service
After=systemd-creds-openbao.service
```

This orders it after `network-online.target` as well. `Requires=` in place of
`Wants=` fails the consumer along with a rejected login, and also restarts it
whenever the daemon restarts, on a package upgrade or after a crash as much as
on `systemctl restart`.

## Reloading

`systemctl reload systemd-creds-openbao` re-reads the configuration file without
dropping the socket or restarting the daemon:

- Added, changed and removed `[[credentials]]` rules apply to the next request.
- The daemon re-authenticates, picking up a rotated `token_file`,
  `role_id_file`, `secret_id_file` or `jwt_file`, including ones delivered as
  systemd credentials (the packaged unit sets `RefreshOnReload=credentials`).
  Changing the `BAO_*` environment or the listening socket takes a restart.
- A failed reload (an invalid file, a rejected login or token, an outage that
  outlasts the 30 seconds a reload waits) leaves the previous configuration
  serving. `systemctl reload` exits 0 either way, so the journal is the only
  signal.
- The token the previous configuration held is revoked shortly after the
  reload, and on shutdown right away, so audit logs show a revoke-self per
  replaced login. A token from `token_file` is never revoked, and a replaced
  token is left to its TTL when the daemon stops before the revocation runs.

On NixOS, `nixos-rebuild switch` applies a `settings` change as exactly this
reload. Changing `package` or `environment` restarts the daemon instead, and
the switch blocks until it has authenticated ([Starting](#starting)).

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
credential before the outage, not one that boots during it. Consumers on that
machine wait for the daemon instead ([Starting](#starting)).

### Failing closed

To fail closed rather than start with an empty secret:

```ini
ExecStartPre=/bin/sh -c 'test -s "$CREDENTIALS_DIRECTORY/db-password"'
```
