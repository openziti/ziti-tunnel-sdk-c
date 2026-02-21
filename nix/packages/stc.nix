{
  lib,
  stdenv,
  fetchFromGitHub,
  meson,
  ninja,
  pkg-config,
}:
stdenv.mkDerivation (finalAttrs: {
  pname = "stc";
  version = "5.0";

  src = fetchFromGitHub {
    owner = "stclib";
    repo = "STC";
    tag = "v${finalAttrs.version}";
    hash = "sha256-JiFyJN+hAbzTHqim1i6TJFmKfHlnOfP3yDLCZDE7uqo=";
  };

  nativeBuildInputs = [
    meson
    ninja
    pkg-config
  ];

  mesonFlags = [
    "-Dcheckscoped=disabled"
    "-Dtests=disabled"
    "-Dexamples=disabled"
  ];

  postInstall = ''
        # Ensure a pkg-config file exists for downstream consumers
        if [ ! -f "$out/lib/pkgconfig/stc.pc" ]; then
          mkdir -p $out/lib/pkgconfig
          cat > $out/lib/pkgconfig/stc.pc <<PCEOF
    Name: stc
    Description: Smart Template Containers for C
    Version: ${finalAttrs.version}
    Cflags: -I$out/include
    Libs: -L$out/lib -lstc
    PCEOF
        fi
  '';

  meta = {
    description = "Smart Template Containers for C";
    homepage = "https://github.com/stclib/STC";
    maintainers = with lib.maintainers; [ kiriwalawren ];
    license = lib.licenses.mit;
  };
})
