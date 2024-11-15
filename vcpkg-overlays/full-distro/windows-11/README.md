# How to Avoid Building All Dependencies with vcpkg

vcpkg supports a trick that lets you get a dependency from an external source (like a package manager) instead of
building it. The only explanation of the trick that I've seen is a [blog post from microsoft](https://devblogs.microsoft.com/cppblog/using-system-package-manager-dependencies-with-vcpkg/),
but I've put it to use it on Linux (with apt/dnf dependencies), macOS (homebrew), and Windows (msys2).

You can probably get away with using a different package manager, as long as the packages that it installs are
registered with the pkg-config that your build uses. I've been getting pkg-config from msys2 on Windows, so I
stayed with msys2 for the dependency packages as well. I imagine chocolatey would work too if that's your thing.

Anyway, here's what worked for me:

1. Install [msys2](https://www.msys2.org)

2. Install pkg-config and ziti-tunnel-sdk-c dependencies from an `msys2` prompt:

       pacman -S mingw-w64-x86_64-pkg-config mingw-w64-x86_64-protobuf-c mingw-w64-x86_64-json-c mingw-w64-x86_64-libuv \
           mingw-w64-x86_64-libsodium mingw-w64-x86_64-openssl 

3. Add `c:\msys64\mingw64\bin` to your PATH.

4. Add the following to your cmake preset:

       "cacheVariables": {
          "VCPKG_OVERLAY_PORTS": "${sourceDir}/vcpkg-overlays/full-distro/windows-11"
       },
       "environment": {
          "OPENSSL_ROOT_DIR": "c:/msys64/mingw64"
       },

   The openssl variable was needed because [cmake's FindOpenSSL module](https://cmake.org/cmake/help/latest/module/FindOpenSSL.html)
   does not consult `pkg-config` on Windows.

5. Remove your build directory, and re-run cmake.
