# OpenZiti Tunnel Build Action

## Example

```yaml
  package:
    runs-on: ubuntu-20.04
    # optionally override entire container image:tag string
    container: ${{ matrix.distro.container || format('{0}:{1}', matrix.distro.name, matrix.distro.version) }} 
    # only override container image name and tag is distro version
    #container: ${{ matrix.distro.container || matrix.distro.name }}:${{ matrix.distro.version }}
    strategy:
      matrix:
        distro:
          - name: ubuntu
            version: "20.04"
            type: deb
          - name: redhat
            version: "8"
            type: rpm
            container: docker.io/library/rockylinux:8

    steps:
      - name: configure build action for distro version
        env:
          DISTRO_LABEL: ${{ format('{0}-{1}', matrix.distro.name, matrix.distro.version) }}
        shell: bash
        run: |
          mv -v ./.github/actions/openziti-tunnel-build-action/${DISTRO_LABEL}/* ./.github/actions/openziti-tunnel-build-action/

      # entrypoint.sh uses the value of arch to select the cmake preset
      - name: build binary and package
        uses: ./.github/actions/openziti-tunnel-build-action
        with:
          arch: ${{ matrix.arch.cmake }}
          config: Release

      - name: run binary artifact
        run: |
          /build/programs/ziti-edge-tunnel/ziti-edge-tunnel version
```

These example steps will:

1. checkout this action to your workspace
1. move one of the Dockerfiles to the effective path 'Dockerfile'
1. build the action container from 'Dockerfile'
1. compile and execute the binary artifact
1. build the deb or rpm package artifact

## required inputs

None

## required outputs

None

## optional inputs

None

## optional outputs

None

## secrets

None

## environment variables

None
