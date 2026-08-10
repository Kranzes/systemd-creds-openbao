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
`systemctl reload myapp`. Nothing touches disk, the daemon reads the secret
just in time.

## How it works

The service manager connects from an abstract-namespace socket whose name
encodes the requesting unit and the credential ID
(`\0RANDOM/unit/myapp.service/db-password`, see
[systemd.exec(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#LoadCredential=ID:PATH)).
`systemd-creds-openbao` reads that peer name with `getpeername(2)`, matches it
against its rule list, reads the secret, writes the payload and closes.

The peer name is the whole authentication, so the socket must only be reachable
by the service manager. The shipped socket unit makes it `root:root` mode
`0600`, and the daemon backs that with an `SO_PEERCRED` check that answers
only uid 0.

A rule list decides which unit may read which secret. Rules are tried in
order, the first match wins, and a request matching no rule is refused:

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

Placeholders like `{unit_name}` and `{credential}` let one rule cover a whole
naming convention, and `-print-policy` derives from the same rules the OpenBao
policy the daemon's own token needs. Every request is a fresh read. The
protocol has no error channel, so a refused or failed request surfaces to the
consumer as an empty credential, with the reason in the journal.

## Documentation

- [Installation](docs/installation.md)
- [Configuration](docs/configuration.md)
- [Command line](docs/cli.md)
- [Operations](docs/operations.md)

## How this differs from systemd-vaultd

[systemd-vaultd](https://github.com/numtide/systemd-vaultd) (and
[systemd-openbao](https://git.lix.systems/kiaragrouwstra/systemd-openbao/), the
same code renamed for OpenBao) never talks to Vault itself. It proxies between
systemd and a Vault Agent. The agent authenticates and writes secrets
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
