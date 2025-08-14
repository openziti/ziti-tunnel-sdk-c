
# Release Process for ziti-edge-tunnel

## How to Publish a Prerelease

1. Merge changes to the default branch, `main`.
1. The release drafter workflow will create a release draft in GitHub with the "Set as a pre-release" box ticked.
1. [In GitHub.com](https://github.com/openziti/ziti-tunnel-sdk-c/releases), edit the release draft to finalize the version, notes, etc.
1. Creating a prerelease in GitHub triggers these workflows.
    1. Build release artifacts (CMake): binary executables are uploaded to the GitHub Release.
    1. CI package (CPack): Linux packages are uploaded to testing repos in Artifactory.
        1. [the testing repo for RPMs](https://netfoundry.jfrog.io/ui/repos/tree/General/zitipax-openziti-rpm-test?projectKey=zitipax)
        1. [the testing repo for DEBs](https://netfoundry.jfrog.io/ui/repos/tree/General/zitipax-openziti-deb-test?projectKey=zitipax)
    1. Docker images are uploaded to Docker Hub.
      1. [ziti-edge-tunnel](https://hub.docker.com/r/openziti/ziti-edge-tunnel/tags) - for `run` proxy mode in a container ([K8S doc](https://openziti.io/docs/reference/tunnelers/kubernetes/kubernetes-daemonset))
      1. [ziti-host](https://hub.docker.com/r/openziti/ziti-host/tags) - for `run-host` reverse-proxy mode in a container ([Docker doc](https://openziti.io/docs/reference/tunnelers/docker/), [K8S doc](https://openziti.io/docs/reference/tunnelers/kubernetes/kubernetes-host))

## How to Promote a Stable Release

1. [In GitHub.com](https://github.com/openziti/ziti-tunnel-sdk-c/releases), edit the release to un-tick the "Set as a pre-release" box. This triggers the promotion of downstream packages and container images. Optionally, also mark the stable release as "latest." This has no effect on artifacts or release CI, but will update GitHub.com to advertise this particular stable release as the preferred version.
1. GitHub fires the one-time release event `released`, triggering the "Promote Downstream Releases" workflow when a release is created or updated with `prerelease: false`.
  1. Linux packages in Artifactory are copied from the "test" repositories to the "stable" repositories in Artifactory.
    1. [the release repo for RPMs](https://netfoundry.jfrog.io/ui/repos/tree/General/zitipax-openziti-rpm-stable?projectKey=zitipax)
    1. [the release repo for DEBs](https://netfoundry.jfrog.io/ui/repos/tree/General/zitipax-openziti-deb-stable?projectKey=zitipax)
  1. Previously-uploaded Docker images in Docker Hub are tagged `:latest`.
  1. There are no effects for the executable binaries that were previously uploaded to the GitHub Release.
