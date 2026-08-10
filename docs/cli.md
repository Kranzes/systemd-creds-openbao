# Command line

```console
$ systemd-creds-openbao -help
Usage of systemd-creds-openbao:
  -check
    	validate the configuration
  -config string
    	path to the configuration file (default "/etc/systemd-creds-openbao/config.toml")
  -log-level string
    	log level: debug, info, warn, or error (default "info")
  -print-policy
    	print an OpenBao policy covering the configured rules
  -version
    	print the version
```

## `-check`

A valid file prints `configuration OK` and exits 0. An invalid one logs the
error and exits 1.

## `-print-policy`

Prints out an OpenBao policy granting read access to every path the
[`[[credentials]]`](configuration.md#credentials) rules can resolve to:

```console
$ systemd-creds-openbao -config /etc/systemd-creds-openbao/config.toml -print-policy > policy.hcl
$ bao policy write systemd-creds-openbao policy.hcl
$ bao token create -policy=systemd-creds-openbao
```

What a rule grants depends on how many values its placeholders can take,
which the `unit` and `credential` globs decide:

- `unit = "nginx.service"` matches one unit, so `{unit_name}` can only be
  `nginx`, and `path = "certs/{unit_name}"` grants `kv/data/certs/nginx`.
- `unit = "*"` matches any unit, so `{unit_name}` can be anything, and
  `path = "certs/{unit_name}"` grants `kv/data/certs/+`, OpenBao's
  single-segment wildcard.
- `unit = "worker@*.service"` allows any instance but only the prefix
  `worker`, so `path = "app/{prefix}/{instance}"` grants
  `kv/data/app/worker/+`.

A `+` covers a whole segment. When a placeholder that can be anything shares
its segment with literal text (`site-{instance}`), the whole segment becomes
`+`, and the policy marks that path with a comment.

The only capability granted is `read`.

On NixOS the same policy is exposed as the read-only `policyFile` option, see
[Installation](installation.md#nixos).
