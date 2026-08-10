{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.systemd-creds-openbao;
  format = pkgs.formats.toml { };

  configFile =
    let
      file = format.generate "systemd-creds-openbao-config.toml" cfg.settings;
    in
    pkgs.runCommand "systemd-creds-openbao-config-checked.toml" { } ''
      ${lib.getExe cfg.package} -config ${file} -check
      ln -s ${file} $out
    '';

  policyFile = pkgs.runCommand "systemd-creds-openbao-policy.hcl" { } ''
    ${lib.getExe cfg.package} -config ${configFile} -print-policy > $out
  '';
in
{
  options.services.systemd-creds-openbao = {
    enable = lib.mkEnableOption "systemd-creds-openbao, an OpenBao credential provider for systemd services";

    package = lib.mkPackageOption pkgs "systemd-creds-openbao" { };

    socketPath = lib.mkOption {
      type = lib.types.path;
      default = "/run/systemd-creds-openbao.sock";
      description = ''
        Path of the credential socket, for referencing in consumers'
        `LoadCredential=<id>:<socketPath>` settings. Changing it moves
        the socket by overriding `ListenStream=` in the packaged socket
        unit.
      '';
    };

    environment = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      example = {
        BAO_ADDR = "https://openbao.example.com:8200";
        BAO_CACERT = "/etc/ssl/certs/openbao-ca.pem";
      };
      description = ''
        Environment variables for the daemon. The connection to OpenBao
        (address, TLS, namespace, timeout) is configured entirely through
        the `BAO_*`/`VAULT_*` variables the client library reads. See
        [The connection](https://github.com/kranzes/systemd-creds-openbao/blob/master/docs/configuration.md#the-connection).

        These end up in the world-readable unit file, so they take connection
        settings only. Pass secret material as systemd credentials instead
        (see {option}`services.systemd-creds-openbao.settings`).
      '';
    };

    settings = lib.mkOption {
      inherit (format) type;
      default = { };
      example = lib.literalExpression ''
        {
          openbao.auth = {
            method = "token";
            token_file = "\''${CREDENTIALS_DIRECTORY}/openbao-token";
          };
          credentials = [
            {
              unit = "myapp.service";
              credential = "db-password";
              path = "myapp/database";
            }
          ];
        }
      '';
      description = ''
        Contents of the daemon's TOML configuration file:
        [`[openbao]`](https://github.com/kranzes/systemd-creds-openbao/blob/master/docs/configuration.md#openbao),
        [`[openbao.auth]`](https://github.com/kranzes/systemd-creds-openbao/blob/master/docs/configuration.md#openbaoauth),
        [`[[credentials]]`](https://github.com/kranzes/systemd-creds-openbao/blob/master/docs/configuration.md#credentials),
        and [`[server]`](https://github.com/kranzes/systemd-creds-openbao/blob/master/docs/configuration.md#server).

        Pass the token and any other confidential material to the daemon as
        systemd credentials, in whichever form fits your secret management:
        `LoadCredential=`, `ImportCredential=`, or their encrypted variants on
        {option}`systemd.services.systemd-creds-openbao.serviceConfig` (see
        {manpage}`systemd.exec(5)`). Each credential is readable by the daemon
        as `''${CREDENTIALS_DIRECTORY}/<name>`, which any of the `*_file`
        settings under `[openbao.auth]` can reference, as the example shows.
      '';
    };

    policyFile = lib.mkOption {
      type = lib.types.path;
      readOnly = true;
      default = policyFile;
      description = ''
        An OpenBao policy granting read access to the paths
        {option}`services.systemd-creds-openbao.settings.credentials` can
        resolve to, generated with `-print-policy`. A placeholder a rule's
        globs leave free costs a single-segment wildcard, so those rules grant
        one segment more than they reach. Attach it to whatever the daemon
        authenticates as.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.packages = [ cfg.package ];

    # The path the packaged unit's ExecStart reads, and the CLI's default,
    # so -resolve and -print-policy work against the live configuration
    # without a -config flag.
    environment.etc."systemd-creds-openbao/config.toml".source = configFile;

    # NixOS ignores [Install] in units coming from systemd.packages.
    systemd.sockets.systemd-creds-openbao = {
      wantedBy = [ "sockets.target" ];
      socketConfig.ListenStream = [
        ""
        cfg.socketPath
      ];
    };

    systemd.services.systemd-creds-openbao = {
      inherit (cfg) environment;
      # Otherwise a switch stops the socket along with the service, and units
      # fetching credentials while it is gone fail outright. Restarting only
      # the service keeps the socket listening, so callers queue instead.
      stopIfChanged = false;
      # A settings-only change applies as a reload, which keeps the stale
      # cache and serves without a gap. The unit file does not reference the
      # configuration, so nothing else about it changes.
      reloadTriggers = [ configFile ];
    };
  };
}
