{
  pkgs ? import (import ./lon.nix).nixpkgs { },
}:

import ./nix {
  inherit pkgs;
  inherit (pkgs) lib;
}
