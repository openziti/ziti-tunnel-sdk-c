
# Release Process for ziti-edge-tunnel

## Releaser Steps

1. [Create a release in GitHub](https://github.com/openziti/ziti-tunnel-sdk-c/releases) with the "Set as a pre-release" box ticked. This finalizes the version of downstream packages and container images and stages them for immediate use by prerelease consumers.
1. At your discretion, allow some time for prerelease consumers to validate the release.
1. Promote the release by [editing it in GitHub](https://github.com/openziti/ziti-tunnel-sdk-c/releases) to un-tick the "Set as a pre-release" box. This triggers the promotion of downstream packages and container images.

The rest of this document describes these steps in greater detail.

## Release Artifacts

A release produces these artifacts.

* binary executables attached to [the GitHub Release](https://github.com/openziti/ziti-tunnel-sdk-c/releases/latest)
* Linux packages in Artifactory
  * DEBs for Debian distros ([doc](https://openziti.io/docs/reference/tunnelers/linux/debian-package))
  * RPMs for RedHat distros ([doc](https://openziti.io/docs/reference/tunnelers/linux/redhat-package))
* Docker images in Docker Hub
  * `openziti/ziti-edge-tunnel` for `run` proxy mode in a container ([K8S doc](https://openziti.io/docs/reference/tunnelers/kubernetes/kubernetes-daemonset))
  * `openziti/ziti-host` for `run-host` reverse-proxy mode in a container ([Docker doc](https://openziti.io/docs/reference/tunnelers/docker/), [K8S doc](https://openziti.io/docs/reference/tunnelers/kubernetes/kubernetes-host))

## Create a Release

Creating a release in GitHub triggers these workflows.

1. Build release artifacts (CMake): binary executables are uploaded to the GitHub Release.
1. CI package (CPack): Linux packages are uploaded to testing repos in Artifactory.
    1. [the testing repo for RPMs](https://netfoundry.jfrog.io/ui/repos/tree/General/zitipax-openziti-rpm-test?projectKey=zitipax)
    1. [the testing repo for DEBs](https://netfoundry.jfrog.io/ui/repos/tree/General/zitipax-openziti-deb-test?projectKey=zitipax)
1. Docker images are uploaded to Docker Hub.
    1. [ziti-edge-tunnel](https://hub.docker.com/r/openziti/ziti-edge-tunnel/tags)
    1. [ziti-host](https://hub.docker.com/r/openziti/ziti-host/tags)

## Promote Downstream Releases

Newly created GitHub Releases default to a full "latest" release, implying `prerelease: false`. GitHub fires the one-time release event `released`, triggering the "Promote Downstream Releases" workflow when a release is created with `prerelease: false` (implied by and mutually exclusive to the default `make_latest: true`) or updated with `prerelease: false`.

1. Linux packages in Artifactory are copied from the "test" repositories to the "stable" repositories in Artifactory.
    1. [the release repo for RPMs](https://netfoundry.jfrog.io/ui/repos/tree/General/zitipax-openziti-rpm-stable?projectKey=zitipax)
    1. [the release repo for DEBs](https://netfoundry.jfrog.io/ui/repos/tree/General/zitipax-openziti-deb-stable?projectKey=zitipax)
1. Previously-uploaded Docker images in Docker Hub are tagged `:latest`.
1. There are no effects for the executable binaries that were previously uploaded to the GitHub Release.
