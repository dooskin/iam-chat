{pkgs}: {
  deps = [
    pkgs.pkg-config
    pkgs.arrow-cpp
    pkgs.glibcLocales
    pkgs.file
    pkgs.tesseract
    pkgs.openssl
    pkgs.postgresql
  ];
}
