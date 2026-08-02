# systemd-creds-openbao

Serve secrets from [OpenBao](https://openbao.org/) to systemd services as
[systemd credentials](https://systemd.io/CREDENTIALS/).

> [!WARNING]
> This project is experimental and not yet recommended for production use.
> It has not been audited, and the configuration format and behavior may
> change without notice.

`systemd-creds-openbao` listens on an `AF_UNIX` socket that any unit can point
`LoadCredential=` at:

```ini
# myapp.service
[Service]
LoadCredential=db-password:/run/systemd-creds-openbao.sock
RefreshOnReload=credentials
```

The secret is read from OpenBao when the service starts, and again on
`systemctl reload myapp`.

## How it works

The service manager connects from an abstract-namespace socket whose name
encodes the requesting unit and the credential ID
(`\0RANDOM/unit/myapp.service/db-password`, see
[systemd.exec(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#LoadCredential=ID:PATH)).
`systemd-creds-openbao` reads that peer name with `getpeername(2)`, matches it
against its rule list, reads the secret, writes the payload and closes. Every
request is a fresh read from OpenBao; nothing is served from memory unless
`serve_stale_for` is set and OpenBao cannot answer.

The peer name is the whole authentication, so the socket must only be reachable
by the service manager. The shipped socket unit makes it `root:root` mode
`0600`, and the daemon backs that with an `SO_PEERCRED` check that answers only
uid 0 or its own uid, which `PrivateUsers=identity` in the service unit keeps
meaningful.

## Configuration

A single TOML file, default `/etc/systemd-creds-openbao/config.toml`. Parsing is
strict, so an unknown key is an error. `-check` validates and exits,
`-print-policy` writes the OpenBao policy the rules need, `-log-level` takes
`debug`, `info`, `warn` or `error`.

```toml
[openbao.auth]
method = "token"
token_file = "${CREDENTIALS_DIRECTORY}/openbao-token"

[[credentials]]
unit = "myapp.service"
credential = "db-password"
path = "myapp/database"
field = "password"
```

### The connection

Address, TLS, namespace and timeout have no config keys. They come from the
[standard `BAO_*` environment variables](https://openbao.org/docs/commands/#environment-variables)
the client library reads, with `VAULT_*` fallbacks:

```ini
# /etc/systemd/system/systemd-creds-openbao.service.d/connection.conf
[Service]
Environment=BAO_ADDR=https://openbao.example.com:8200
Environment=BAO_CACERT=/etc/ssl/certs/openbao-ca.pem
```

### `[openbao]`

| Key | Default | Description |
| --- | --- | --- |
| `serve_stale_for` | off | Keep the last successful read of each secret in memory and serve it when a fresh read fails because OpenBao could not answer (unreachable, 5xx), for at most this long after it was fetched, e.g. `"30m"` or `"1h"` |

The fallback never replaces a fresh read: while OpenBao answers, every request
reaches it, and an authoritative refusal (permission denied, missing secret)
is passed through and drops the remembered value, so a revoked or deleted
secret cannot resurface during a later outage. Unset, nothing is retained in
memory. See [Failure behavior](#failure-behavior) for what serving stale
looks like.

### `[openbao.auth]`

| `method` | Required | Optional |
| --- | --- | --- |
| `token` (default) | `token_file` | |
| `approle` | exactly one of `role_id`/`role_id_file`, plus `secret_id_file` | `mount` (`approle`) |
| `cert` | `BAO_CLIENT_CERT`/`BAO_CLIENT_KEY` on the connection | `cert_role`, `mount` (`cert`) |
| `jwt` | `jwt_file` | `jwt_role`, `mount` (`jwt`) |

Confidential material has no inline key: `token_file`, `secret_id_file` and
`jwt_file` are file-only, while `role_id` may be inline. Deliver these files as
systemd credentials rather than through the environment, which systemd hands to
any local user that asks for the unit's properties. Every `*_file` path is
environment-expanded when read, so the daemon's own credentials can be delivered
as systemd credentials; an unset variable is an error rather than an empty
string, trailing newlines are trimmed, and an empty file is an error.

`cert_role` and `jwt_role` name a single role to log in against; unset, the
server tries every certificate role or the mount's default JWT role. The
certificate is read when the client is built, so a reload picks up a rotated
one, while `jwt_file` is re-read on every login attempt.

The daemon renews its token in the background. `approle`, `cert` and `jwt`
re-authenticate once renewal is exhausted; a static token cannot be re-acquired,
so the daemon logs and keeps serving until reads start failing.

### `[[credentials]]`

Each rule maps requests to a secret. Rules are tried in file order and the
first match wins; **requests matching no rule are refused**.

| Key | Default | Description |
| --- | --- | --- |
| `unit` | required | Glob matched against the requesting unit name; granting every unit takes an explicit `"*"` |
| `credential` | `*` | Glob matched against the requested credential ID |
| `backend` | `kv` | `kv` (KV v2 engine) or `raw` (verbatim API path read) |
| `mount` | `kv` | KV engine mount point; must not be set with `backend = "raw"` |
| `path` | required | Secret path below the mount, or the full API path for `raw` |
| `format` | `field` | `field` serves one field verbatim; `json` serves all data as JSON |
| `field` | `{credential}` | Which field of the secret data to serve; must not be set with `format = "json"` |

The `kv` backend only supports KV v2. A KV v1 mount can still be read through
`backend = "raw"` with the full API path.

Globs are Go's [`path.Match`](https://pkg.go.dev/path#Match) patterns, so `*`
does not cross a `/`, `?` and `[...]` work, and an invalid pattern fails
validation. `\` escapes the next character, so a unit name carrying systemd's
`\xNN` escaping needs `unit = 'dev-disk\\x2d*'` in a TOML literal string, or
four backslashes in a basic one.

With `format = "field"`, a string prefixed with `base64:` is decoded and served
as raw bytes, since JSON has no byte string and credentials may be binary, and
any non-string field is served JSON-encoded. `format = "json"` serves the data
map as it comes, `base64:` prefixes included.

`path`, `field`, and `mount` support placeholders, so one rule can cover a
whole convention. For unit `foo@bar.service` requesting credential `credx`:

| Placeholder | Value |
| --- | --- |
| `{unit}` | `foo@bar.service` |
| `{unit_name}` | `foo@bar` |
| `{prefix}` | `foo` |
| `{instance}` | `bar` (empty for non-templated units) |
| `{credential}` | `credx` |

Placeholder values come from the requester, so the expanded path and mount are
rechecked and an empty, `.` or `..` segment refuses the request. A rule whose
segment is exactly `{instance}` therefore never serves a non-templated unit.

Unlike `unit` and `credential`, `path` and `mount` are not globs: they are read
verbatim. Because they are also what the generated policy grants, a literal `+`
segment or a trailing `*` in either is rejected at load, since OpenBao's policy
syntax reads both as wildcards and the rule would grant a subtree it can never
serve from.

A convention where every unit reads fields of `kv/systemd/<unit name>` is one
rule:

```toml
[[credentials]]
unit = "*"
path = "systemd/{unit_name}"
```

Dynamic secrets engines work through the `raw` backend:

```toml
[[credentials]]
unit = "myapp.service"
credential = "db-creds"
backend = "raw"
path = "database/creds/myapp"
format = "json"
```

The daemon only ever issues a read, so a path that needs a write (PKI issuance,
transit) does not work, and it does not track the leases those reads create;
each one expires on its own.

### `[server]`

| Key | Default | Description |
| --- | --- | --- |
| `connection_timeout` | `"15s"` | Bounds the read from OpenBao and, separately, the write back, e.g. `"5s"` or `"1m"` |

## The daemon's own policy

The rule list is deny-by-default towards units, but the daemon's own token still
has to be allowed to read every path those rules resolve to. `-print-policy`
derives that policy from the configuration file:

```console
$ systemd-creds-openbao -config /etc/systemd-creds-openbao/config.toml -print-policy > policy.hcl
$ bao policy write systemd-creds-openbao policy.hcl
$ bao token create -policy=systemd-creds-openbao
```

When a rule's `unit` and `credential` globs carry no wildcards of their own they
match one request, so its placeholders resolve to one value and the policy names
it: `unit = "nginx.service"` with `path = "certs/{unit_name}"` grants
`kv/data/certs/nginx`. A placeholder the globs leave free becomes `+`, OpenBao's
single-segment wildcard, so `unit = "*"` with the same path grants
`kv/data/certs/+`. A free placeholder sharing a segment with literal text
(`site-{instance}`) cannot be expressed exactly, so the whole segment widens to
`+` and the output notes it in a comment above the path. Rules resolving to the
same path share one block, the only
capability granted is `read`, and renewal needs no rule of its own since
`auth/token/renew-self` is part of the built-in `default` policy. With no rules
configured it refuses to print, since an empty policy would revoke the access
the token already has.

On NixOS the module exposes the same policy as a read-only option:

```console
$ nix build .#nixosConfigurations.myhost.config.services.systemd-creds-openbao.policyFile
$ bao policy write systemd-creds-openbao result
```

## Reloading

`systemctl reload systemd-creds-openbao` re-reads the configuration file without
dropping the socket or restarting the daemon:

- Added, changed and removed `[[credentials]]` rules apply to the next request;
  requests in flight finish against the rules they started with.
- The daemon re-authenticates, so a rotated `token_file`, `role_id_file`,
  `secret_id_file` or `jwt_file` is picked up. The packaged unit sets
  `RefreshOnReload=credentials`, so systemd re-provisions those files before
  signalling and one command covers both halves. The `BAO_*` environment and the
  listening socket are not re-read; changing either needs a restart.
- A reload that cannot be completed (an unreadable or invalid file, a login
  OpenBao refuses) is logged and abandoned, and the configuration already in
  effect keeps serving. The login is bounded at 30s, so an unreachable OpenBao
  cannot hang the reload. A failed reload still exits 0, so the journal line is
  the only signal.

Under `Type=notify-reload` the daemon counts as started only once it has
authenticated, and `systemctl status` reports the rule count and auth method in
use, plus how many requests it has served and refused. Refused counts every
connection not answered with a credential, whatever the reason. The counters
survive a reload and start over on a restart.

## Failure behavior

The credential socket protocol has no error channel, so a refused or failed
request surfaces to the consumer as an **empty credential**. A payload over
systemd's 1 MiB credential limit is refused the same way rather than truncated,
since a larger credential would make the requesting unit fail to start.

The reason is in the journal. Each message names the credential, where it came
from and who asked for it, so the default output is enough to work from:

```console
$ journalctl -u systemd-creds-openbao
served credential "db-password" from "kv/myapp/database" for "myapp.service"
refusing credential "db-password" for "myapp.service": secret "kv/myapp/database" has no field "password"
```

Log levels map to journal priorities, and the same details are attached as
fields for filtering: `UNIT=` and `CREDENTIAL=` on every request, plus
`SECRET_PATH=` once a rule has matched and the read has succeeded. A request
refused before that point has no path to report, and says so in the message
instead.

```console
$ journalctl -u systemd-creds-openbao UNIT=myapp.service
$ journalctl -u systemd-creds-openbao SECRET_PATH=kv/myapp/database
```

`SECRET_PATH` addresses the secret the way the matching command does:
mount-qualified for `kv`, so it pastes into `bao kv get`, and the API path
itself for `raw`, so it pastes into `bao read`. It is not the policy path,
which carries KV v2's `data/` infix (`kv/data/myapp/database`).

With `serve_stale_for` set, a read failing because OpenBao could not answer
falls back to the last successful response for that secret, so a service can
still (re)start during an outage. The journal carries a warning with the same
`SECRET_PATH=` field plus the age of what was served:

```console
read failed, serving stale secret data SECRET_PATH=kv/myapp/database AGE=4m12s
```

A secret rotated during the outage is served in its pre-outage form until
OpenBao returns or the bound expires. Entries live only in daemon memory:
they survive a reload but not a restart, so the fallback covers a machine
that has fetched the credential before, not a boot during the outage.

To fail closed rather than start with an empty secret:

```ini
ExecStartPre=/bin/sh -c 'test -s "$CREDENTIALS_DIRECTORY/db-password"'
```

## How this differs from systemd-vaultd

[systemd-vaultd](https://github.com/numtide/systemd-vaultd) (and
[systemd-openbao](https://git.lix.systems/kiaragrouwstra/systemd-openbao/), the
same code renamed for OpenBao) never talks to Vault itself. It proxies between
systemd and a Vault Agent sidecar: the agent authenticates and renders secrets
through `template` blocks into
`/run/systemd-vaultd/secrets/<unit>.service.json`, and the proxy serves keys out
of whatever the agent last wrote. The credential socket is a pull protocol, so
an agent rendering on its own schedule is always a snapshot behind.

This project talks to OpenBao directly, so the agent, its auto-auth
configuration, its template files and the rendered secrets on tmpfs are all
gone, along with the startup race a good part of systemd-vaultd exists to
absorb. Authorization is a deny-by-default rule list rather than whatever the
templates happen to render.

What the agent model still offers is response caching and more built-in auth
methods.

## LLM disclosure

This project is developed with LLM assistance.
