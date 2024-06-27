{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    autoconf
    automake
    boost
    db4
    gcc
    libevent
    libtool
    openssl
    pkg-config
  ];
  shellHook =
    ''
      export BOOST_LIB_DIR="${pkgs.boost.out}/lib"
    '';
}
