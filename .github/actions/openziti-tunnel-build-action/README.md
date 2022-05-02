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
          - name: ubuntu
            version: "18.04"
            type: deb
          - name: redhat
            version: "7"
            type: rpm
            container: quay.io/centos/centos:7
          - name: redhat
            version: "8"
            type: rpm
            container: quay.io/rockylinux/rockylinux:8

      - name: configure build action for distro version
        env:
          DISTRO_LABEL: ${{ format('{0}:{1}', matrix.distro.name, matrix.distro.version) }}
        shell: bash
        run: |
          for FILE in Dockerfile entrypoint.sh; do
            mv -v ./.github/actions/openziti-tunnel-build-action/${FILE}.${DISTRO_LABEL} \
                  ./.github/actions/openziti-tunnel-build-action/${FILE}
          done

      - name: build cmake target "package"
        uses: ./.github/actions/openziti-tunnel-build-action

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
