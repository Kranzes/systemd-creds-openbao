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

    credentials = lib.mkOption {
      type = lib.types.attrsOf lib.types.externalPath;
      default = { };
      example = {
        openbao-token = "/run/secrets/openbao-token";
      };
      description = ''
        Credential files loaded into the daemon with `LoadCredential=`
        (see {manpage}`systemd.exec(5)`); each becomes readable by it as
        `''${CREDENTIALS_DIRECTORY}/<name>`, e.g. for
        {option}`services.systemd-creds-openbao.settings.openbao.auth.token_file`.
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
        the `BAO_*`/`VAULT_*` variables the client library reads; see
        [The connection](https://github.com/kranzes/systemd-creds-openbao#the-connection).

        These end up in the world-readable unit file, so they take connection
        settings only. Pass the token and any other confidential material with
        {option}`services.systemd-creds-openbao.credentials`.
      '';
    };

    settings = lib.mkOption {
      type = format.type;
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
        [`[openbao]`](https://github.com/kranzes/systemd-creds-openbao#openbao),
        [`[openbao.auth]`](https://github.com/kranzes/systemd-creds-openbao#openbaoauth),
        [`[[credentials]]`](https://github.com/kranzes/systemd-creds-openbao#credentials),
        and [`[server]`](https://github.com/kranzes/systemd-creds-openbao#server).
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

    # NixOS ignores [Install] in units coming from systemd.packages.
    systemd.sockets.systemd-creds-openbao = {
      wantedBy = [ "sockets.target" ];
      socketConfig.ListenStream = [
        ""
        cfg.socketPath
      ];
    };

    systemd.services.systemd-creds-openbao = {
      environment = cfg.environment;
      # Otherwise a switch stops the socket along with the service, and units
      # fetching credentials while it is gone fail outright. Restarting only
      # the service keeps the socket listening, so callers queue instead.
      stopIfChanged = false;
      serviceConfig = {
        ExecStart = [
          ""
          "${lib.getExe cfg.package} -config ${configFile}"
        ];
        LoadCredential = lib.mapAttrsToList (name: path: "${name}:${toString path}") cfg.credentials;
      };
    };
  };
}
