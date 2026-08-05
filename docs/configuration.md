# Configuration

A single TOML file, default `/etc/systemd-creds-openbao/config.toml`,
overridden with `-config`. [`-check`](cli.md#-check) validates the file. A commented example ships as
[`go/contrib/config.toml`](../go/contrib/config.toml).

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

## The connection

Address, TLS, namespace and timeout have no config keys. They come from the
[standard `BAO_*` environment variables](https://openbao.org/docs/commands/#environment-variables)
the client library reads, with `VAULT_*` fallbacks:

```ini
# /etc/systemd/system/systemd-creds-openbao.service.d/connection.conf
[Service]
Environment=BAO_ADDR=https://openbao.example.com:8200
Environment=BAO_CACERT=/etc/ssl/certs/openbao-ca.pem
```

## `[openbao]`

| Key | Default | Description |
| --- | --- | --- |
| `serve_stale_for` | off | Keep the last successful read of each secret in memory and serve it when a fresh read fails because OpenBao could not answer (unreachable, 5xx), for at most this long after it was fetched, e.g. `"30m"` or `"1h"` |

The fallback never replaces a fresh read: while OpenBao answers, every request
reaches it, and an authoritative refusal (permission denied, missing secret)
is passed through and drops the remembered value, so a revoked or deleted
secret cannot resurface during a later outage. A permission error counts as
authoritative only while the daemon's own token is valid: when OpenBao rejects
the token itself, the refusal says nothing about the secret, so the fallback
still applies. See
[Failure behavior](operations.md#failure-behavior) for what serving stale
looks like.

## `[openbao.auth]`

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
as systemd credentials. Trailing newlines are trimmed.

`cert_role` and `jwt_role` name a single role to log in against. Unset, cert
login lets the server try every certificate role, and jwt login uses the
mount's default role. The certificate is read at startup and on reload, while
`jwt_file` is re-read on every login attempt.

The daemon renews its token in the background. `approle`, `cert` and `jwt`
re-authenticate once renewal is exhausted, while a static token just runs out:
the daemon logs it and keeps serving until reads start failing.

## `[[credentials]]`

Each rule maps requests to a secret. Rules are tried in file order and the
first match wins. **Requests matching no rule are refused.**

| Key | Default | Description |
| --- | --- | --- |
| `unit` | required | Glob matched against the requesting unit name. Granting every unit takes an explicit `"*"` |
| `credential` | `*` | Glob matched against the requested credential ID |
| `backend` | `kv` | `kv` (KV v2 engine) or `raw` (verbatim API path read) |
| `mount` | `kv` | KV engine mount point. Must not be set with `backend = "raw"` |
| `path` | required | Secret path below the mount, or the full API path for `raw` |
| `format` | `field` | `field` serves one field verbatim. `json` serves all data as JSON |
| `field` | `{credential}` | Which field of the secret data to serve. Must not be set with `format = "json"` |

The `kv` backend speaks KV v2. A KV v1 mount is read through `backend = "raw"`
with the full API path.

Globs are Go's [`path.Match`](https://pkg.go.dev/path#Match) patterns, so `*`
does not cross a `/`, and `?` and `[...]` work. `\` escapes the next character, so a unit name carrying systemd's
`\xNN` escaping needs `unit = 'dev-disk\\x2d*'` in a TOML literal string, or
four backslashes in a basic one.

With `format = "field"`, a string prefixed with `base64:` is decoded and served
as raw bytes, and any non-string field is served JSON-encoded. `format = "json"` serves the data
map as it comes, `base64:` prefixes included.

### Placeholders

`path`, `field`, and `mount` support placeholders, so one rule can cover a
whole naming convention. For unit `foo@bar.service` requesting credential `credx`:

| Placeholder | Value |
| --- | --- |
| `{unit}` | `foo@bar.service` |
| `{unit_name}` | `foo@bar` |
| `{prefix}` | `foo` |
| `{instance}` | `bar` (empty for non-templated units) |
| `{credential}` | `credx` |

Placeholder values come from the requester, so the expanded path and mount are
rechecked and an empty, `.` or `..` segment refuses the request.

Unlike `unit` and `credential`, `path` and `mount` are not globs: they are read
verbatim. Because they are also what the
[generated policy](cli.md#-print-policy) grants, a literal `+`
segment or a trailing `*` in either is rejected at load, since OpenBao's policy
syntax reads both as wildcards and the rule would grant a subtree it can never
serve from.

A `unit` or `credential` glob carrying no wildcard of its own fixes what its
placeholders expand to, so that rendering is known at load and is exactly what
the policy grants. The rendering is validated like a literal path, which
rejects a rule that pins a segment to `+` or pins one to nothing.

A convention where every unit reads fields of `kv/systemd/<unit name>` is one
rule:

```toml
[[credentials]]
unit = "*"
path = "systemd/{unit_name}"
```

### Dynamic secrets

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
transit) does not work. It does not track the leases those reads create, so
each one expires on its own.

## `[server]`

| Key | Default | Description |
| --- | --- | --- |
| `connection_timeout` | `"15s"` | Bounds the read from OpenBao and, separately, the write back, e.g. `"5s"` or `"1m"` |
