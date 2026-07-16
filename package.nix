{
  lib,
  rustPlatform,
}:

rustPlatform.buildRustPackage {
  pname = "kindletool";
  version = "1.7.0";
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
    description = "Create, inspect, convert, and safely extract Kindle update packages";
    license = licenses.gpl3Plus;
    mainProgram = "kindletool";
    platforms = platforms.unix;
  };
}
