{ pkgs, lib }:

rec {
  packages = lib.recurseIntoAttrs {
    systemd-creds-openbao = pkgs.callPackage ./package.nix { };
  };

  devShells = lib.recurseIntoAttrs {
    systemd-creds-openbao = pkgs.mkShell {
      name = "systemd-creds-openbao";
      inputsFrom = [ packages.systemd-creds-openbao ];
      packages = [
        formatter
        pkgs.golangci-lint
        pkgs.gopls
        pkgs.govulncheck
      ];
    };
  };

  formatter = pkgs.treefmt.withConfig {
    settings.formatter = {
      nixfmt = {
        command = lib.getExe pkgs.nixfmt;
        includes = [ "*.nix" ];
      };

      gofumpt = {
        command = lib.getExe pkgs.gofumpt;
        options = [ "-w" ];
        includes = [ "*.go" ];
      };
    };
  };

  nixosModules.systemd-creds-openbao = {
    imports = [ ./module.nix ];
    services.systemd-creds-openbao.package = lib.mkDefault packages.systemd-creds-openbao;
  };

  checks = lib.recurseIntoAttrs {
    formatting = formatter.check (
      lib.fileset.toSource {
        root = ../.;
        fileset = lib.fileset.gitTracked ../.;
      }
    );

    golangci-lint = packages.systemd-creds-openbao.overrideAttrs (old: {
      pname = old.pname + "-golangci-lint";
      nativeBuildInputs = old.nativeBuildInputs ++ [ pkgs.golangci-lint ];
      buildPhase = ''
        runHook preBuild
        HOME=$TMPDIR golangci-lint run
        runHook postBuild
      '';
      doCheck = false;
      installPhase = ''
        touch $out
      '';
      dontFixup = true;
    });

    nixos-test = pkgs.testers.runNixOSTest {
      imports = [ ./test.nix ];
      defaults.imports = [ nixosModules.systemd-creds-openbao ];
    };
  };
}
