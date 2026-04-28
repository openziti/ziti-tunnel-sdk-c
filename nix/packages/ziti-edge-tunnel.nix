{
  callPackage,
  cmake,
  fetchFromGitHub,
  json_c,
  lib,
  libsodium,
  libuv,
  llhttp,
  openssl,
  pkg-config,
  protobufc,
  stdenv,
  systemd,
  versionCheckHook,
  zlib,
}:
let
  inherit (lib) cmakeBool cmakeFeature;

  stc = callPackage ./stc.nix { };

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
    tag = "v0.41.1";
    hash = "sha256-mT1K8OpwE+brdEc6ik8jMhEsXGuEh5nqfY3urx7IQiA=";
  };
  ziti_sdk_src = fetchFromGitHub {
    owner = "openziti";
    repo = "ziti-sdk-c";
    tag = "1.11.8";
    hash = "sha256-5RqCvOPnpTnOiyFpAoA4PWdp0DU+TeVTBH6eCgFe+ws=";
  };
in
stdenv.mkDerivation (finalAttrs: {
  pname = "ziti-edge-tunnel";
  version = "1.11.4";

  src = fetchFromGitHub {
    owner = "openziti";
    repo = "ziti-tunnel-sdk-c";
    tag = "v${finalAttrs.version}";
    hash = "sha256-CGj8ysxycMnuc0VW2cPfGgBKH2g97XS0GyvrPlAcVf0=";
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
    (cmakeFeature "CMAKE_BUILD_TYPE" "release")
    (cmakeBool "DISABLE_SEMVER_VERIFICATION" true)
    (cmakeBool "DISABLE_LIBSYSTEMD_FEATURE" true) # Disable direct integration to use resolvectl fallback
    (cmakeFeature "DOXYGEN_OUTPUT_DIR" "/tmp/doxygen")
    (cmakeBool "FETCHCONTENT_FULLY_DISCONNECTED" true)
    # lwip path is set in preConfigure via cmakeFlagsArray (needs writable copy + absolute path)
    (cmakeFeature "FETCHCONTENT_SOURCE_DIR_LWIP-CONTRIB" "${lwip_contrib_src}")
    (cmakeFeature "FETCHCONTENT_SOURCE_DIR_SUBCOMMAND" "${subcommand_c_src}")
    (cmakeFeature "FETCHCONTENT_SOURCE_DIR_TLSUV" "${tlsuv_src}")
    # Feed the CMake version parser (tag-tweak-slug format) so it derives
    # PROJECT_VERSION correctly instead of falling through to v0.0.0-unknown.
    (cmakeFeature "GIT_VERSION" "v${finalAttrs.version}-0-nixbld")
    (cmakeFeature "ZITI_SDK_DIR" "${ziti_sdk_src}")
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

  postInstall =
    let
      systemdDir = "../programs/ziti-edge-tunnel/package/systemd";
    in
    ''
      # Install templated systemd unit files for non-NixOS Linux distros
      install -Dm644 -t $out/lib/systemd/system \
        ${systemdDir}/ziti-edge-tunnel.service.in
      install -Dm644 -t $out/share/ziti-edge-tunnel \
        ${systemdDir}/ziti-edge-tunnel.env.in
      install -Dm755 -t $out/share/ziti-edge-tunnel \
        ${systemdDir}/ziti-edge-tunnel.sh.in

      mv $out/lib/systemd/system/ziti-edge-tunnel.service{.in,}
      mv $out/share/ziti-edge-tunnel/ziti-edge-tunnel.env{.in,}
      mv $out/share/ziti-edge-tunnel/ziti-edge-tunnel.sh{.in,}

      substituteInPlace $out/lib/systemd/system/ziti-edge-tunnel.service \
        --replace-fail '@CPACK_BIN_DIR@/@SYSTEMD_SERVICE_NAME@' "$out/bin/ziti-edge-tunnel" \
        --replace-fail '@CPACK_ETC_DIR@/@SYSTEMD_SERVICE_NAME@' "$out/share/ziti-edge-tunnel/ziti-edge-tunnel"

      substituteInPlace $out/share/ziti-edge-tunnel/ziti-edge-tunnel.env \
        --replace-fail '@ZITI_IDENTITY_DIR@' '/opt/openziti/etc/identities' \
        --replace-fail '@ZITI_STATE_DIR@' '/var/lib/ziti-edge-tunnel'

      substituteInPlace $out/share/ziti-edge-tunnel/ziti-edge-tunnel.sh \
        --replace-fail '@ZITI_IDENTITY_DIR@' '/opt/openziti/etc/identities' \
        --replace-fail '@CPACK_BIN_DIR@/@SYSTEMD_SERVICE_NAME@' "$out/bin/ziti-edge-tunnel"
    '';

  doInstallCheck = true;
  nativeInstallCheckInputs = [ versionCheckHook ];
  versionCheckProgramArg = "version";

  meta = {
    description = "The Ziti Tunneler SDK provides protocol translation and other common functions that are useful to Ziti Tunnelers";
    changelog = "https://github.com/openziti/ziti-tunnel-sdk-c/releases/tag/v${finalAttrs.version}";
    homepage = "https://openziti.io/";
    maintainers = with lib.maintainers; [ kiriwalawren ];
    license = lib.licenses.asl20;
    mainProgram = "ziti-edge-tunnel";
  };
})
