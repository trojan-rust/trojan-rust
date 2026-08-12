{ pkgs, lib, ... }:

{
  # Matches the toolchain CI builds with (.github/workflows/ci.yml).
  # The MSRV job pins 1.90; everything else runs stable.
  languages.rust = {
    enable = true;
    channel = "stable";
    components = [
      "rustc"
      "cargo"
      "clippy"
      "rustfmt"
      "rust-src"
    ];
  };

  packages =
    with pkgs;
    [
      # aws-lc-sys (rustls' crypto backend) builds C sources via CMake, and
      # generates bindings with libclang on targets without prebuilt ones.
      cmake
      perl
      pkg-config
      # libsqlite3-sys, built by the sql-sqlite auth feature.
      sqlite
    ]
    ++ lib.optionals stdenv.isDarwin [
      # aws-lc-sys reads `nm` while assembling its object list.
      darwin.cctools
    ];

  env.LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";

  enterShell = ''
    echo "trojan-rust dev shell — $(cargo --version)"
  '';
}
