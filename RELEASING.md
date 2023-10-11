
# Release Process for ziti-edge-tunnel

## Releaser Steps

1. [Create a release in GitHub](https://github.com/openziti/ziti-tunnel-sdk-c/releases).
1. Run ["Promote Downstream Releases"](https://github.com/openziti/ziti-tunnel-sdk-c/actions/workflows/promote-downstreams.yml)
   on the release tag you created in the first step.

The rest of this document describes these two steps in greater detail.

## Release Artifacts

A release produces these artifacts.

* binary executables attached to [the GitHub Release](https://github.com/openziti/ziti-tunnel-sdk-c/releases/latest)
* Linux packages in Artifactory
  * DEBs for Debian distros ([doc](https://openziti.io/docs/reference/tunnelers/linux/#installing-the-deb))
  * RPMs for RedHat distros ([doc](https://openziti.io/docs/reference/tunnelers/linux/#installing-the-rpm))
* Docker images in Docker Hub
  * `openziti/ziti-edge-tunnel` for `run` proxy mode in a container ([doc](https://openziti.io/docs/reference/tunnelers/linux/container/#use-case-intercepting-proxy-and-nameserver))
  * `openziti/ziti-host` for `run-host` reverse-proxy mode in a container ([doc](https://openziti.io/docs/reference/tunnelers/linux/container/#use-case-hosting-openziti-services))

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

Running the "Promote Downstream Releases" workflow has these effects in downstream repositories.

1. Linux packages in Artifactory are promoted to the release repositories in Artifactory.
    1. [the release repo for RPMs](https://netfoundry.jfrog.io/ui/repos/tree/General/zitipax-openziti-rpm-stable?projectKey=zitipax)
    1. [the release repo for DEBs](https://netfoundry.jfrog.io/ui/repos/tree/General/zitipax-openziti-deb-stable?projectKey=zitipax)
1. Previously-uploaded Docker images in Docker Hub are tagged `:latest`.
1. There are no effects for the executable binaries that were previously uploaded to the GitHub Release.

## GitHub Pre-Release vs. Latest Release

Newly-created GitHub Releases set as the "latest" release in GitHub by default. The Releaser may override the latest
label by marking any release as "latest" in the GitHub UI or Releases API. The Releaser may mark a release as
"prerelease" instead of "latest" when creating the release in the GitHub UI or Releases API. This has no effect on
downstream builds for Artifactory or Docker Hub and only running the "Promote Downstream Releases" workflow will
cause those downstreams to advertise a new release as "latest".
