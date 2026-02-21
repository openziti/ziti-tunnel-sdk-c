{
  lib,
  stdenv,
  fetchFromGitHub,
  callPackage,
  cmake,
  json_c,
  libsodium,
  libuv,
  llhttp,
  openssl,
  pkg-config,
  protobufc,
  systemd,
  versionCheckHook,
  zlib,
}:
let
  inherit (lib) cmakeBool cmakeFeature;

  stc = callPackage ./stc.nix { };

  ziti_sdk_src = fetchFromGitHub {
    owner = "openziti";
    repo = "ziti-sdk-c";
    tag = "1.10.10";
    hash = "sha256-DtciHFGSiRnUCvVnKOE/5vRo8h/EA5CoRw0G37QUL6c=";
  };
  lwip_src = fetchFromGitHub {
    owner = "lwip-tcpip";
    repo = "lwip";
    rev = "STABLE-2_2_1_RELEASE";
    hash = "sha256-8TYbUgHNv9SV3l203WVfbwDEHFonDAQqdykiX9OoM34=";
  };
  lwip_contrib_src = fetchFromGitHub {
    owner = "netfoundry";
    repo = "lwip-contrib";
    rev = "STABLE-2_1_0_RELEASE";
    hash = "sha256-Ypn/QfkiTGoKLCQ7SXozk4D/QIdo4lyza4yq3tAoP/0=";
  };
  subcommand_c_src = fetchFromGitHub {
    owner = "openziti";
    repo = "subcommands.c";
    rev = "87350797774530b6ba9c00017f0f53dd57e6c38e";
    hash = "sha256-Gz0/b9jcC1I0fmguSMkV0xiqKWq7vzUVT0Bd1F4iqkA=";
  };
  tlsuv_src = fetchFromGitHub {
    owner = "openziti";
    repo = "tlsuv";
    tag = "v0.40.10";
    hash = "sha256-GvApttUIjsrumI5ZKXmrV+YIpZnLTJYRRC8mEiOvq88=";
  };
in
stdenv.mkDerivation (finalAttrs: {
  pname = "ziti-edge-tunnel";
  version = "1.10.10";

  src = fetchFromGitHub {
    owner = "openziti";
    repo = "ziti-tunnel-sdk-c";
    tag = "v${finalAttrs.version}";
    hash = "sha256-MWeWSzjLYVLSbEygWRRx8KI3zTZcB4boo7jy9tjqv7I=";
  };

  postPatch = ''
    # Workaround for broken llhttp package
    mkdir -p patched-cmake
    cp -r ${lib.getDev llhttp}/lib/cmake/llhttp patched-cmake/
    substituteInPlace patched-cmake/llhttp/llhttp-config.cmake \
      --replace 'set(_IMPORT_PREFIX "${llhttp}")' 'set(_IMPORT_PREFIX "${lib.getDev llhttp}")'

    # Patch hardcoded paths to systemd tools
    substituteInPlace programs/ziti-edge-tunnel/netif_driver/linux/resolvers.h \
      --replace '"/usr/bin/busctl"' '"${systemd}/bin/busctl"' \
      --replace '"/usr/bin/resolvectl"' '"${systemd}/bin/resolvectl"' \
      --replace '"/usr/bin/systemd-resolve"' '"${systemd}/bin/systemd-resolve"'
  '';

  preConfigure = ''
    # Prepend patched cmake to path
    export CMAKE_PREFIX_PATH=$(pwd)/patched-cmake''${CMAKE_PREFIX_PATH:+:}$CMAKE_PREFIX_PATH

    # lwip's Filelists.cmake uses configure_file which writes into the source
    # tree, so we need a writable copy; use absolute path to avoid fragility
    cp -r ${lwip_src} ./deps/lwip
    chmod -R +w ./deps/lwip
    cmakeFlagsArray+=("-DFETCHCONTENT_SOURCE_DIR_LWIP=$(pwd)/deps/lwip")
  '';

  cmakeFlags = [
    (cmakeBool "DISABLE_SEMVER_VERIFICATION" true)
    (cmakeBool "DISABLE_LIBSYSTEMD_FEATURE" true) # Disable direct integration to use resolvectl fallback
    (cmakeFeature "ZITI_SDK_DIR" "${ziti_sdk_src}")
    # Feed the CMake version parser (tag-tweak-slug format) so it derives
    # PROJECT_VERSION correctly instead of falling through to v0.0.0-unknown.
    (cmakeFeature "GIT_VERSION" "v${finalAttrs.version}-0-nixbld")
    (cmakeBool "FETCHCONTENT_FULLY_DISCONNECTED" true)
    # lwip path is set in preConfigure via cmakeFlagsArray (needs writable copy + absolute path)
    (cmakeFeature "FETCHCONTENT_SOURCE_DIR_LWIP-CONTRIB" "${lwip_contrib_src}")
    (cmakeFeature "FETCHCONTENT_SOURCE_DIR_SUBCOMMAND" "${subcommand_c_src}")
    (cmakeFeature "FETCHCONTENT_SOURCE_DIR_TLSUV" "${tlsuv_src}")
    (cmakeFeature "DOXYGEN_OUTPUT_DIR" "/tmp/doxygen")
    (cmakeFeature "CMAKE_BUILD_TYPE" "release")
  ];

  nativeBuildInputs = [
    cmake
    pkg-config
  ];

  buildInputs = [
    json_c
    libsodium
    libuv
    llhttp
    openssl
    protobufc
    stc
    zlib
  ];

  doInstallCheck = true;
  nativeInstallCheckInputs = [ versionCheckHook ];
  versionCheckProgramArg = "version";

  meta = {
    description = "provides protocol translation and other common functions that are useful to Ziti Tunnelers";
    changelog = "https://github.com/openziti/ziti-tunnel-sdk-c/releases/tag/v${finalAttrs.version}";
    homepage = "https://openziti.io/";
    maintainers = with lib.maintainers; [ kiriwalawren ];
    license = lib.licenses.asl20;
    mainProgram = "ziti-edge-tunnel";
  };
})
