{
  lib,
  buildGoModule,
}:

buildGoModule (finalAttrs: {
  pname = "systemd-creds-openbao";
  version = "0.1.0";

  __structuredAttrs = true;

  src = lib.fileset.toSource {
    root = ../go;
    fileset = lib.fileset.unions [
      (lib.fileset.fileFilter (f: f.hasExt "go") ../go)
      ../go/go.mod
      ../go/go.sum
      ../go/.golangci.yml
      ../go/contrib/systemd
    ];
  };

  goSum = ../go/go.sum;
  vendorHash = "sha256-ONyuAUUOHspXSs7eGDzFktiUmCJIaYwCUFSnfEKsDzA=";

  ldflags = [
    "-s"
    "-X main.version=${finalAttrs.version}"
  ];

  postInstall = ''
    install -Dm444 -t $out/lib/systemd/system contrib/systemd/*
    substituteInPlace $out/lib/systemd/system/${finalAttrs.pname}.service \
      --replace-fail "ExecStart=${finalAttrs.pname}" "ExecStart=$out/bin/${finalAttrs.pname}"
  '';

  meta = {
    mainProgram = finalAttrs.pname;
    license = lib.licenses.mit;
  };
})
