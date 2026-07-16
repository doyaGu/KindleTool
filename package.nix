{
  lib,
  rustPlatform,
}:

rustPlatform.buildRustPackage {
  pname = "kindletool";
  version = "2.0.1";
  src = lib.cleanSource ./.;

  cargoLock.lockFile = ./Cargo.lock;
  cargoBuildFlags = [
    "--package"
    "kindletool-cli"
  ];
  cargoTestFlags = [ "--workspace" ];

  postInstall = ''
    install -Dm644 kindletool.1 $out/share/man/man1/kindletool.1
  '';

  meta = with lib; {
    homepage = "https://github.com/doyaGu/KindleTool";
    description = "Inspect, verify, extract, and create Kindle update packages";
    license = licenses.gpl3Plus;
    mainProgram = "kindletool";
    platforms = platforms.unix;
  };
}
