{pkgs}: {
  deps = [
    pkgs.docker-compose
    pkgs.docker
    pkgs.zlib
    pkgs.c-ares
    pkgs.grpc
    pkgs.neo4j
    pkgs.pkg-config
    pkgs.arrow-cpp
    pkgs.glibcLocales
    pkgs.file
    pkgs.tesseract
    pkgs.openssl
    pkgs.postgresql
  ];
}
