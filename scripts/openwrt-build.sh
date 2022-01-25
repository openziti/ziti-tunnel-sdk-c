#!/usr/bin/env bash

die() {
    echo "$@" >&2
    exit 1
}

usage() {
  echo "Usage: $0 -s <openwrt sdk dir> -t <target> "
}

script_dir=$(realpath $(dirname "$0"))
ziti_src=$(dirname "$script_dir")
toolchain_file=./toolchain.cmake

openwrt_sdk=
target=

while getopts "s:t:" opt; do
  case "$opt" in
  s)
    openwrt_sdk=${OPTARG}
    ;;
  t)
    target=${OPTARG}
    ;;
  *) usage
    exit 1
    ;;
  esac
done

staging_dir=$openwrt_sdk/staging_dir

if [ -z "$target" ]; then
eval $(grep '^CONFIG_TARGET_ARCH_PACKAGES=' $openwrt_sdk/.config)
echo "OpenWRT SDK is configured for $CONFIG_TARGET_ARCH_PACKAGES"
target=$CONFIG_TARGET_ARCH_PACKAGES
fi

[ -d "$openwrt_sdk" ] || die "OpenWRT SDK dir '$openwrt_sdk' is not valid"
[ -d "$staging_dir" ] || die "$staging_dir is not found. please build OpenWRT SDK for your target"

toolchains=($staging_dir/toolchain-${target}*)
targets=($staging_dir/target-${target}*)

toolchain_dir="${toolchains[0]}"
target_dir="${targets[0]}"

[ -f "$toolchain_dir/info.mk" ] || die "toolchain is invalid. missing $toolchain_dir/info.mk"

echo
echo "Using $(basename $toolchain_dir) to build"
echo
toolchain_dir=$(realpath ${toolchain_dir})
target_dir=$(realpath ${target_dir})
. $toolchain_dir/info.mk
toolchain_info=(${TARGET_CROSS//-/ })

toolchain_triple="${toolchain_info[0]}-${toolchain_info[1]}-${toolchain_info[2]}"

echo ${toolchain_info[@]}

echo
echo "creating toolchain file..."
echo

cat <<EOF > "$toolchain_file"
set(triple "${toolchain_triple}")

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR "${toolchain_info[0]}")

set(CMAKE_SYSROOT $target_dir)
set(CMAKE_C_COMPILER "$toolchain_dir/bin/${toolchain_triple}-gcc")
set(CMAKE_CXX_COMPILER "$toolchain_dir/bin/${toolchain_triple}-g++")
set(INCLUDE_DIRECTORIES $target_dir/usr/include)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

EOF

CMAKE_OPTS="-DCMAKE_C_FLAGS=-I${target_dir}/usr/include"

if [ -x /usr/bin/ninja ]; then
  CMAKE_OPTS="$CMAKE_OPTS -G Ninja"
fi

if [ -f "$target_dir/usr/include/openssl/opensslv.h" ]; then
  CMAKE_OPTS="$CMAKE_OPTS -DUSE_OPENSSL=on"
fi

if [ -f "$target_dir/usr/include/sodium.h" ]; then
  CMAKE_OPTS="$CMAKE_OPTS -DHAVE_LIBSODIUM=on"
fi

if [ -f "$target_dir/usr/include/uv.h" ]; then
  CMAKE_OPTS="$CMAKE_OPTS -DHAVE_LIBUV=on"
fi

echo $CMAKE_OPTS

CMAKE_OPTS="$CMAKE_OPTS -DCMAKE_TOOLCHAIN_FILE=$toolchain_file"
export STAGING_DIR=$staging_dir
cmake $CMAKE_OPTS "${ziti_src}"

#echo
#echo "Ready to build. run 'STAGING_DIR=$staging_dir cmake --build .' to build"
#echo

echo
echo Starting the buid
echo

cmake --build . --target bundle

echo
echo Build complete
echo


