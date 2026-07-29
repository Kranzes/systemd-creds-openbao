{ inputs, withSystem, ... }:
{
  imports = [ inputs.treefmt-nix.flakeModule ];

  perSystem =
    { pkgs, config, ... }:
    {
      packages = {
        systemd-creds-openbao = pkgs.callPackage ./package.nix { };
        default = config.packages.systemd-creds-openbao;
      };

      devShells = {
        systemd-creds-openbao = pkgs.mkShell {
          name = "systemd-creds-openbao";
          inputsFrom = [ config.packages.systemd-creds-openbao ];
          packages = with pkgs; [
            gopls
          ];
        };
        default = config.devShells.systemd-creds-openbao;
      };

      treefmt = {
        projectRootFile = "flake.nix";
        programs.gofumpt.enable = true;
        programs.nixfmt.enable = true;
      };

      checks.nixos-test = pkgs.testers.runNixOSTest {
        imports = [ ./test.nix ];
        defaults.imports = [ inputs.self.nixosModules.default ];
      };
    };

  flake.nixosModules.default =
    { pkgs, lib, ... }:
    {
      imports = [ ./module.nix ];
      services.systemd-creds-openbao.package = lib.mkDefault (
        withSystem pkgs.stdenv.hostPlatform.system ({ config, ... }: config.packages.systemd-creds-openbao)
      );
    };
}
