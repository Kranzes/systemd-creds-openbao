# Operations

## Reloading

`systemctl reload systemd-creds-openbao` re-reads the configuration file without
dropping the socket or restarting the daemon:

- Added, changed and removed `[[credentials]]` rules apply to the next request.
  Requests in flight finish against the rules they started with.
- The daemon re-authenticates, so a rotated `token_file`, `role_id_file`,
  `secret_id_file` or `jwt_file` is picked up. The packaged unit sets
  `RefreshOnReload=credentials`, so the same reload first re-fetches the
  daemon's own credential files and the re-authentication picks up the
  fresh copies. The `BAO_*` environment and the
  listening socket are not re-read. Changing either needs a restart.
- A reload that cannot be completed (an unreadable or invalid file, a login
  OpenBao refuses) is logged and abandoned, and the configuration already in
  effect keeps serving. The login is bounded at 30s. A failed reload still
  exits 0, so the journal line is the only signal.

Under `Type=notify-reload` the daemon counts as started only once it has
authenticated.

## Failure behavior

The credential socket protocol has no error channel, so a refused or failed
request surfaces to the consumer as an **empty credential**. That includes a
payload over systemd's 1 MiB credential limit. The exception is a write that
fails part way through: bytes already sent cannot be taken back, so the
consumer can see a truncated credential, with the written byte count in the
journal line.

The reason is in the journal. Each message names the credential, where it came
from and who asked for it, so the default output is enough to work from:

```console
$ journalctl -u systemd-creds-openbao
served credential "db-password" from "kv/myapp/database" for "myapp.service"
refusing credential "db-password" for "myapp.service": secret "kv/myapp/database" has no field "password"
```

Log levels map to journal priorities, and the same details are attached as
fields for filtering: `UNIT=` and `CREDENTIAL=` on every request, plus
`SECRET_PATH=` once a rule has matched and the read has succeeded.

```console
$ journalctl -u systemd-creds-openbao UNIT=myapp.service
$ journalctl -u systemd-creds-openbao SECRET_PATH=kv/myapp/database
```

`SECRET_PATH` is written so it pastes into the CLI: mount-qualified for `kv`,
matching `bao kv get`, and the API path itself for `raw`, matching `bao read`.
It is not the policy path, which carries KV v2's `data/` infix
(`kv/data/myapp/database`).

### Serving stale

With [`serve_stale_for`](configuration.md#openbao) set, a read failing because
OpenBao could not answer falls back to the last successful response for that
secret, so a service can still (re)start during an outage. The journal carries
a warning with the same `SECRET_PATH=` field plus the age of what was served:

```console
read failed, serving stale secret data SECRET_PATH=kv/myapp/database AGE=4m12s
```

Entries live only in daemon memory: they survive a reload but not a restart,
so the fallback works for a machine that fetched the credential before the
outage, not for one that boots during it.

### Failing closed

To fail closed rather than start with an empty secret:

```ini
ExecStartPre=/bin/sh -c 'test -s "$CREDENTIALS_DIRECTORY/db-password"'
```
