{ pkgs, ... }:
let
  certs = import "${pkgs.path}/nixos/tests/common/acme/server/snakeoil-certs.nix";
  inherit (certs) domain;
in
{
  name = "systemd-creds-openbao";

  nodes.machine =
    {
      config,
      pkgs,
      lib,
      ...
    }:
    {
      security.pki.certificateFiles = [ certs.ca.cert ];

      networking.extraHosts = ''
        127.0.0.1 ${domain}
      '';

      environment.variables = {
        BAO_ADDR = config.services.openbao.settings.api_addr;
        BAO_FORMAT = "json";
      };

      services.openbao = {
        enable = true;
        settings = {
          listener.default = {
            type = "tcp";
            tls_cert_file = certs.${domain}.cert;
            tls_key_file = certs.${domain}.key;
          };
          cluster_addr = "https://127.0.0.1:8201";
          api_addr = "https://${domain}:8200";
          storage.raft.path = "/var/lib/openbao";
          seal.static = {
            current_key_id = "snakeoil-1";
            current_key = "file://" + pkgs.writeText "openbao-seal.key" "snakeoil-static-seal-key-32bytes";
          };
        };
      };

      services.systemd-creds-openbao = {
        enable = true;
        environment = {
          BAO_ADDR = "https://${domain}:8200";
          BAO_CACERT = "${certs.ca.cert}";
        };
        settings = {
          openbao.serve_stale_for = "1h";
          openbao.auth.token_file = "\${CREDENTIALS_DIRECTORY}/openbao-token";
          credentials = [
            {
              unit = "prometheus.service";
              credential = "web.yml";
              path = "systemd/{unit_name}";
            }
            # Three specific rules ahead of a catch-all: they only ever
            # serve if the first match really wins.
            {
              unit = "creds-test.service";
              credential = "binary";
              path = "systemd/{unit_name}";
              encoding = "base64";
            }
            {
              unit = "creds-test.service";
              credential = "json";
              path = "systemd/{unit_name}";
              format = "json";
            }
            # field = "data" is the KV v2 version envelope, not a secret key.
            {
              unit = "creds-test.service";
              credential = "raw";
              backend = "raw";
              path = "kv/data/systemd/creds-test";
              field = "data";
            }
            {
              unit = "creds-test.service";
              path = "systemd/{unit_name}";
              field = "fallback";
            }
          ];
        };
      };

      # Written by the test script once OpenBao is initialized.
      systemd.services.systemd-creds-openbao.serviceConfig.LoadCredential = [
        "openbao-token:/run/keys/openbao-token"
      ];

      # A settings-only change, switched to by the last subtest.
      specialisation.extra-rule.configuration = {
        services.systemd-creds-openbao.settings.credentials = [
          {
            unit = "extra.service";
            path = "systemd/{unit_name}";
          }
        ];
      };

      services.prometheus = {
        enable = true;
        webConfigFile = "/run/credentials/prometheus.service/web.yml";
      };

      systemd.services.prometheus = {
        # Started by the test script: at boot the secret does not exist
        # yet and web.yml would be served empty.
        wantedBy = lib.mkForce [ ];
        serviceConfig = {
          LoadCredential = [ "web.yml:${config.services.systemd-creds-openbao.socketPath}" ];
          # Prometheus re-reads the web config file on every request.
          RefreshOnReload = true;
        };
      };
    };

  testScript =
    { nodes, ... }:
    # python
    ''
      import base64
      import json

      SOCKET = "${nodes.machine.services.systemd-creds-openbao.socketPath}"
      METRICS = "${nodes.machine.services.prometheus.listenAddress}:${toString nodes.machine.services.prometheus.port}/metrics"

      binary_secret = bytes(range(256))
      binary_b64 = base64.b64encode(binary_secret).decode()


      def web_yml(password_hash):
          return f"basic_auth_users:\n  prom: {password_hash}"


      def bcrypt(password):
          return machine.succeed(f"mkpasswd -m bcrypt {password}").strip()


      def fetch_credentials(target, credentials):
          # The unit name has to be creds-test.service: that is what the
          # rules grant.
          loads = " ".join(f"-p LoadCredential={c}:{SOCKET}" for c in credentials)
          machine.succeed(
              f"systemd-run --collect --wait --unit=creds-test {loads} "
              f"cp -r \\''${{CREDENTIALS_DIRECTORY}} {target}"
          )


      def openbao_is_active(_last_try):
          # Unsealed is not writable: a restarted raft node rejoins a standby.
          status, output = machine.execute("bao status")
          return status == 0 and json.loads(output).get("is_self", False)


      start_all()
      machine.wait_for_unit("multi-user.target")

      with subtest("Initialize OpenBao"):
          machine.wait_for_unit("openbao.service")
          machine.wait_for_open_port(8200)
          init_output = json.loads(machine.succeed("bao operator init"))
          retry(openbao_is_active)
          machine.succeed(f"bao login {init_output['root_token']}")
          machine.succeed(f"umask 077; printf %s {init_output['root_token']} > /run/keys/openbao-token")

      with subtest("Store secrets"):
          # One secret per consumer unit, at the paths the rules expand to.
          machine.succeed("bao secrets enable -version=2 kv")
          machine.wait_until_succeeds(f"bao kv put -mount=kv systemd/prometheus 'web.yml={web_yml(bcrypt('password1'))}'")
          machine.succeed(
              f"bao kv put -mount=kv systemd/creds-test binary={binary_b64} fallback=fallback-value"
          )

      with subtest("Prometheus starts with basic auth served from OpenBao"):
          machine.succeed("systemctl start prometheus.service")
          machine.wait_for_open_port(${toString nodes.machine.services.prometheus.port})
          machine.fail(f"curl --fail --silent {METRICS}")
          machine.fail(f"curl --fail --silent -u prom:password2 {METRICS}")
          machine.succeed(f"curl --fail --silent -u prom:password1 {METRICS}")

      with subtest("A rotated password applies on reload, and not before"):
          machine.succeed(f"bao kv put -mount=kv systemd/prometheus 'web.yml={web_yml(bcrypt('password2'))}'")
          machine.succeed(f"curl --fail --silent -u prom:password1 {METRICS}")
          machine.fail(f"curl --fail --silent -u prom:password2 {METRICS}")
          machine.succeed("systemctl reload prometheus.service")
          machine.succeed(f"curl --fail --silent -u prom:password2 {METRICS}")
          machine.fail(f"curl --fail --silent -u prom:password1 {METRICS}")

      with subtest("Placeholders, base64, JSON format, raw backend"):
          # Each of the three credentials is resolved by a different rule.
          fetch_credentials("/tmp/creds", ["binary", "json", "raw"])
          t.assertEqual(machine.succeed("base64 -w0 /tmp/creds/binary").strip(), binary_b64)
          t.assertEqual(
              json.loads(machine.succeed("cat /tmp/creds/json")),
              {"binary": binary_b64, "fallback": "fallback-value"},
          )
          # The raw rule's "data" field is a map, so it is served JSON-encoded.
          t.assertEqual(
              json.loads(machine.succeed("cat /tmp/creds/raw")),
              {"binary": binary_b64, "fallback": "fallback-value"},
          )

      with subtest("Requests matching no rule are refused with an empty credential"):
          size = machine.succeed(
              f"systemd-run --collect --pipe --wait --unit=denied -p LoadCredential=web.yml:{SOCKET} "
              "stat -c %s \\''${CREDENTIALS_DIRECTORY}/web.yml"
          ).strip()
          t.assertEqual(size, "0")
          machine.succeed("journalctl -u systemd-creds-openbao UNIT=denied.service CREDENTIAL=web.yml --grep 'no credential rule matches'")

      with subtest("Reloading re-reads the configuration in place"):
          pid = machine.succeed("systemctl show -p MainPID --value systemd-creds-openbao.service").strip()
          machine.succeed("systemctl reload systemd-creds-openbao.service")
          t.assertEqual(
              machine.succeed("systemctl show -p MainPID --value systemd-creds-openbao.service").strip(),
              pid,
          )
          machine.succeed("journalctl -u systemd-creds-openbao --grep 'configuration reloaded'")
          # The counters cover every request so far: prometheus's start and
          # reload, the three creds-test fetches, and the denied request.
          t.assertEqual(
              machine.succeed("systemctl show -p StatusText --value systemd-creds-openbao.service").strip(),
              "serving ${toString (builtins.length nodes.machine.services.systemd-creds-openbao.settings.credentials)}"
              " credential rules, authenticated with token; 5 served, 1 refused",
          )
          # Requests are still served after the reload.
          machine.succeed("systemctl reload prometheus.service")
          machine.succeed(f"curl --fail --silent -u prom:password2 {METRICS}")

      with subtest("The generated policy grants every rule, and nothing else"):
          # The root token used so far is swapped for one carrying only
          # the generated policy.
          machine.succeed(
              "bao policy write systemd-creds ${nodes.machine.services.systemd-creds-openbao.policyFile}"
          )
          scoped = json.loads(machine.succeed("bao token create -policy=systemd-creds"))
          scoped_token = scoped["auth"]["client_token"]
          machine.succeed(f"umask 077; printf %s {scoped_token} > /run/keys/openbao-token")
          # Restart, so this checks the scoped token from a cold start. The
          # last subtest covers picking one up on reload.
          machine.succeed("systemctl restart systemd-creds-openbao.service")

          machine.succeed("systemctl reload prometheus.service")
          machine.succeed(f"curl --fail --silent -u prom:password2 {METRICS}")
          fetch_credentials("/tmp/creds-scoped", ["binary", "raw"])
          t.assertEqual(machine.succeed("base64 -w0 /tmp/creds-scoped/binary").strip(), binary_b64)
          t.assertEqual(
              json.loads(machine.succeed("cat /tmp/creds-scoped/raw")),
              {"binary": binary_b64, "fallback": "fallback-value"},
          )
          t.assertIn("deny", machine.succeed(f"bao token capabilities {scoped_token} kv/data/other"))

      with subtest("Reloading picks up the daemon's own rotated token"):
          # One reload both re-provisions the daemon's token file and
          # re-authenticates with it. Revoking the old token is what
          # proves the new one is in use.
          rotated = json.loads(machine.succeed("bao token create -policy=systemd-creds"))
          rotated_token = rotated["auth"]["client_token"]
          machine.succeed(f"umask 077; printf %s {rotated_token} > /run/keys/openbao-token")
          machine.succeed("systemctl reload systemd-creds-openbao.service")
          machine.succeed(f"bao token revoke {scoped_token}")

          fetch_credentials("/tmp/creds-rotated", ["binary"])
          t.assertEqual(machine.succeed("base64 -w0 /tmp/creds-rotated/binary").strip(), binary_b64)

      with subtest("Stale secrets are served while OpenBao is down"):
          machine.succeed("systemctl stop openbao.service")
          fetch_credentials("/tmp/creds-stale", ["binary"])
          t.assertEqual(machine.succeed("base64 -w0 /tmp/creds-stale/binary").strip(), binary_b64)
          machine.succeed(
              "journalctl -u systemd-creds-openbao SECRET_PATH=kv/systemd/creds-test --grep 'serving stale secret data'"
          )

      with subtest("Fresh reads resume once OpenBao is back"):
          machine.succeed("systemctl start openbao.service")
          machine.wait_for_open_port(8200)
          retry(openbao_is_active)
          # Rotating the secret is what proves the next read is fresh, not
          # the remembered response again.
          machine.succeed("bao kv put -mount=kv systemd/creds-test fallback=rotated-value")
          fetch_credentials("/tmp/creds-fresh", ["fallback"])
          t.assertEqual(machine.succeed("cat /tmp/creds-fresh/fallback"), "rotated-value")

      with subtest("A settings change on switch applies as a reload"):
          pid = machine.succeed("systemctl show -p MainPID --value systemd-creds-openbao.service").strip()
          machine.succeed("/run/current-system/specialisation/extra-rule/bin/switch-to-configuration test")
          t.assertEqual(
              machine.succeed("systemctl show -p MainPID --value systemd-creds-openbao.service").strip(),
              pid,
          )
          machine.succeed(
              "journalctl -u systemd-creds-openbao "
              "RULES=${
                toString (1 + builtins.length nodes.machine.services.systemd-creds-openbao.settings.credentials)
              } "
              "--grep 'configuration reloaded'"
          )
    '';
}
