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
| `serve_stale_for` | off | Serve the last remembered secret when OpenBao is down or not answering, for at most this long, e.g. `"30m"` or `"1h"` |

A permission denial or a missing secret still fails the request and drops the
remembered secret, so a revoked secret cannot resurface during a later
outage. When the daemon cannot tell whether its own token caused a denial,
the denial counts as an outage and the remembered secret may still be
served.

## `[openbao.auth]`

| `method` | Required | Optional |
| --- | --- | --- |
| `token` (default) | `token_file` | |
| `approle` | exactly one of `role_id`/`role_id_file`, plus `secret_id_file` | `mount` (`approle`) |
| `cert` | `BAO_CLIENT_CERT`/`BAO_CLIENT_KEY` on the connection | `cert_role`, `mount` (`cert`) |
| `jwt` | `jwt_file` | `jwt_role`, `mount` (`jwt`) |

`token_file`, `secret_id_file` and `jwt_file` are file-only, while `role_id`
may be inline. Every `*_file` path
is environment-expanded when read, so secrets can be delivered as systemd
credentials (`${CREDENTIALS_DIRECTORY}/...`, as in the example above).
Trailing newlines are trimmed.

`cert_role` and `jwt_role` name a single role to log in against. Unset, cert
login lets the server try every certificate role, and jwt login uses the
mount's default role. The certificate is read at startup and on reload, while
`jwt_file` is re-read on every login attempt.

The daemon renews its token in the background. `approle`, `cert` and `jwt`
re-authenticate when renewal runs out. A static token eventually expires, so
rotate `token_file` and reload before it does.

## `[[credentials]]`

Each rule maps requests to a secret. Rules are tried in file order and the
first match wins. **Requests matching no rule are refused.**
[`-resolve`](cli.md#-resolve) answers which rule a given request hits.

| Key | Default | Description |
| --- | --- | --- |
| `unit` | required | Glob matched against the requesting unit name. Granting every unit takes an explicit `"*"` |
| `credential` | `*` | Glob matched against the requested credential ID |
| `backend` | `kv` | `kv` (KV v2 engine) or `raw` (verbatim API path read) |
| `mount` | `kv` | KV engine mount point. Must not be set with `backend = "raw"` |
| `path` | required | Secret path below the mount, or the full API path for `raw` |
| `format` | `field` | `field` serves one field verbatim. `json` serves all data as JSON |
| `field` | `{credential}` | Which field of the secret data to serve. Must not be set with `format = "json"` |
| `encoding` | `none` | `base64` decodes the field value before serving it. Must not be set with `format = "json"` |

The `kv` backend speaks KV v2. A KV v1 mount is read through `backend = "raw"`
with the full API path.

Globs are Go's [`path.Match`](https://pkg.go.dev/path#Match) patterns, so `*`
does not cross a `/`, and `?` and `[...]` work. `\` escapes the next character, so a unit name carrying systemd's
`\xNN` escaping needs `unit = 'dev-disk\\x2d*'` in a TOML literal string, or
four backslashes in a basic one.

With `format = "field"`, a non-string field is served JSON-encoded. A binary
credential is stored as base64 text and served decoded with
`encoding = "base64"`.

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

Placeholder values come from the requester, so a request expanding to an
empty, `.` or `..` segment is refused.

`path` and `mount` are read verbatim, not matched as globs. A literal `+`
segment or a trailing `*` in either is rejected, since the
[generated policy](cli.md#-print-policy) would read them as wildcards. The
same applies to a placeholder that can only expand to `+` or to nothing.

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
| `connection_timeout` | `"15s"` | Timeout for each read request from OpenBao |
