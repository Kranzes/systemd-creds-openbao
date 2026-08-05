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

What a rule grants depends on how specific its globs are:

- When a rule's `unit` and `credential` globs carry no wildcards of their own
  they match one request, so its placeholders resolve to one value and the
  policy names it: `unit = "nginx.service"` with `path = "certs/{unit_name}"`
  grants `kv/data/certs/nginx`.
- A placeholder the globs leave free becomes `+`, OpenBao's single-segment
  wildcard: `unit = "*"` with the same path grants `kv/data/certs/+`.
- A template glob with a literal prefix still pins `{prefix}`:
  `unit = "worker@*.service"` fixes it to `worker` even though the
  instance varies, so `path = "app/{prefix}/{instance}"` grants
  `kv/data/app/worker/+`.
- A free placeholder sharing a segment with literal text (`site-{instance}`)
  cannot be expressed exactly, so the whole segment widens to `+` and the
  output notes it in a comment above the path.

The only capability granted is `read`.

On NixOS the same policy is exposed as the read-only `policyFile` option, see
[Installation](installation.md#nixos).
