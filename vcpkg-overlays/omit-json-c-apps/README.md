This overlay disables building apps in the json-c package. We don't need the apps, and the app build
currently fails with cmake 4.0.

Remove this overlay from ziti-tunnel-sdk-c when https://github.com/json-c/json-c/pull/888
is merged and referenced in our vcpkg baseline - currently 2025.01.13.