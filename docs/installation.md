# Installation

The host needs systemd 260 or newer.

systemd owns the `AF_UNIX` socket and starts the daemon on the first request,
so what gets enabled is the socket unit, not the service. The identity the daemon authenticates as needs an OpenBao
policy covering the configured rules, which
[`-print-policy`](cli.md#-print-policy) generates.

## NixOS

Pin the repository with your tool of choice (a `flake = false` flake input,
npins, niv, lon). The example assumes the pinned sources are available under
the `inputs` attrset:

```nix
{ pkgs, config, inputs, ... }:
let
  systemd-creds-openbao = import inputs.systemd-creds-openbao { inherit pkgs; };
in
{
  imports = [ systemd-creds-openbao.nixosModules.systemd-creds-openbao ];

  services.systemd-creds-openbao = {
    enable = true;
    environment.BAO_ADDR = "https://openbao.example.com:8200";
    settings = {
      openbao = {
        serve_stale_for = "1h";
        auth = {
          method = "approle";
          role_id = config.networking.hostName;
          secret_id_file = "\${CREDENTIALS_DIRECTORY}/openbao-secret-id";
        };
      };
      credentials = [
        {
          unit = "tailscaled-autoconnect.service";
          credential = "id-token";
          backend = "raw";
          path = "identity/oidc/token/tailscale";
          field = "token";
        }
        # Every systemd service can access its own secrets.
        {
          unit = "*";
          path = "${config.networking.hostName}/systemd/{unit_name}";
        }
      ];
    };
  };

  # The daemon's own AppRole secret ID, delivered as a systemd credential.
  systemd.services.systemd-creds-openbao.serviceConfig.LoadCredential =
    "openbao-secret-id:/etc/openbao/secret-id";
}
```

The options under `services.systemd-creds-openbao`:

| Option | Default | Description |
| --- | --- | --- |
| `enable` | `false` | Run the daemon |
| `package` | the repository's own build | Which package to run. The default is built against the `pkgs` the import above received, or the repository's own pin when `inherit pkgs;` is omitted |
| `socketPath` | `"/run/systemd-creds-openbao.sock"` | Where the credential socket lives, for referencing in consumers' `LoadCredential=` settings. Changing it overrides `ListenStream=` in the packaged socket unit |
| `environment` | `{ }` | Environment variables for the daemon, where the [`BAO_*` connection settings](configuration.md#the-connection) go. Unit files are world-readable, so connection settings only, no secrets |
| `settings` | `{ }` | The daemon's [TOML configuration](configuration.md) as a Nix attribute set |
| `policyFile` | read-only | The OpenBao policy [`-print-policy`](cli.md#-print-policy) derives from `settings` |

`settings` is rendered to TOML and validated with [`-check`](cli.md#-check)
at build time, so a misconfiguration fails the system build rather than the
running daemon. The generated policy is a derivation, buildable straight
from your system's configuration:

```console
$ nix build .#nixosConfigurations.myhost.config.services.systemd-creds-openbao.policyFile
$ bao policy write systemd-creds-openbao result
```

## Manual

Build the binary (the Go module lives in `go/`) and install it together with
the units from `go/contrib/systemd/`:

```console
$ cd go
$ go build ./cmd/systemd-creds-openbao
$ install -Dm755 systemd-creds-openbao /usr/local/bin/systemd-creds-openbao
$ install -Dm444 -t /etc/systemd/system contrib/systemd/*
```

Write the configuration to `/etc/systemd-creds-openbao/config.toml`, starting
from the commented example in
[`go/contrib/config.toml`](../go/contrib/config.toml), and give the daemon
its connection settings and its own token as a drop-in:

```ini
# /etc/systemd/system/systemd-creds-openbao.service.d/local.conf
[Service]
Environment=BAO_ADDR=https://openbao.example.com:8200
LoadCredential=openbao-token:/etc/openbao/token
```

Generate and attach the policy, then enable the socket:

```console
$ systemd-creds-openbao -print-policy > policy.hcl
$ bao policy write systemd-creds-openbao policy.hcl
$ bao token create -policy=systemd-creds-openbao
$ systemctl daemon-reload
$ systemctl enable --now systemd-creds-openbao.socket
```

To confirm authentication works before the first request, start the
service once by hand.
