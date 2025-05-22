# FIPS 140-3 Compliance

[FIPS](https://www.nist.gov/itl/fips-general-information) (Federal Information Processing Standards) are security
standards developed by NIST (National Institute of Standards and Technology), a U.S. government agency responsible for
promoting innovation and industrial competitiveness through standards and technology.

This software is built to comply with the FIPS 140-3 program, specifically with OpenSSL as of May 2025. The software is
considered "FIPS 140-3 compliant", it is **not FIPS validated**. Per the FAQ found at
https://csrc.nist.gov/Projects/cryptographic-module-validation-program/faqs:

> FIPS 140-3 "compliant" means a vendor believes its product implementation meets the FIPS 140-3 requirements,
> but the product has not gone through the CMVP validation process.

## Enabling FIPS Compliance

FIPS-compliance can be initiated in one of two ways: environment variable or by placing an `openssl.cnf` file adjacent to
the ziti-edge-tunnel executable. Both options will trigger the statically linked OpenSSL code within the ziti-edge-tunnel
to attempt to initialize FIPS-compliance. If specified, the `OPENSSL_CONF` environment variable takes precedence over
an `openssl.cnf` file located adjacent to the ziti-edge-tunnel binary.

The format of the OpenSSL configuration file is specified by the OpenSSL doc located at
https://docs.openssl.org/master/man7/fips_module/#making-all-applications-use-the-fips-module-by-default

Using FIPS mode requires the following:

- An OpenSSL v3 FIPS module
- Executing the openssl executable against the FIPS module to produce a `fipsmodule.cnf` file
- An OpenSSL v3 FIPS configuration that references the `fipsmodule.cnf`

## Acquiring OpenSSL FIPS Module

A properly validated FIPS module requires strict adherence to the instructions documented on the 
[OpenSSL FIPS source](https://openssl-library.org/source/) page. Pay careful attention as there are only a few versions
that are actually validated. Per the referenced page:

> Please follow the Security Policy instructions to download, build and install a validated OpenSSL FIPS provider.
> Other OpenSSL Releases MAY use the validated FIPS provider, but MUST NOT build and use their own FIPS provider.

The source reference page contains links to the 
[FIPS CMVP](https://csrc.nist.gov/Projects/Cryptographic-Module-Validation-Program) certificate as well. The OpenZiti 
project provides this software as is and is not responsible if you erroneously claim FIPS validation or  

### Building an OpenSSL FIPS Module From Source for Development

It's relatively straightforward to build OpenSSL from source and the OpenSSL doc site provides clear instructions.
Since vcpkg is necessary to build ziti-edge-tunnel. You can opt to use vcpkg to build an openssl executable and the fips
shared library using vcpkg.

Using vcpkg -- replace `<platform>` with `x64-linux`, `arm64-osx`, `x64-windows` etc., depending on your target
platform. This will generate a shared object into the vcpkg directory under 
`installed/openssl_<platform>-dynamic/lib/ossl-modules` or `./installed/x64-windows/bin/fips.dll` (on Windows).

These example commands build/retrieves:
* core: Base OpenSSL components (libraries, headers).
* fips: Enables building the FIPS provider (`fips.dll`, `fips.so`, or `fips.dylib`).
* [optional] tools: Includes CLI tools like `openssl.exe` or `openssl` binary.

**Linux/MacOS**
```sh
# probably not necessary to build the openssl binary but add `core` or `tools` as needed 
vcpkg install "openssl[core,fips,tools]:<platform>-dynamic"

# installs it into vcpkg directory under `packages/openssl_<platform>-dynamic/lib/ossl-modules`. 
```

**Windows**
```
# windows will most likely **require** tools to build openssl.exe as it's generally not availalbe by default
.\vcpkg.exe install "openssl[core,fips,tools]:x64-windows"
```

## OpenSSL FIPS Configuration

Follow the instructions listed at [OpenSSL FIPS User Guide](https://docs.openssl.org/master/man7/fips_module) 
to configure the OpenSSL FIPS module. An example is shown below.


### Example Enabling FIPS on Windows

An example `openssl.cnf` file might look something like the one shown below. Note the file includes the location of the
`fipsmodule.cnf` as well as the location of the shared library to be loaded. Specifying these files in the configuration
file can help configure FIPS-compliance correctly.

Also note the `fipsmodule.cnf` must be generated on each and every machine in order to claim FIPS-compliance using
the openssl binary. For example, on Windows you might use a command such as this to generate the `fipsmodule.cnf`:

```text
openssl.exe fipsinstall -out "C:/path/to/fips/config/fipsmodule.cnf" -module "C:/path/to/shared-library/fips.dll"
-- or -- 
openssl fipsinstall -out /tmp/fipsmodule.cnf -module ./installed/x64-linux-dynamic/lib/ossl-modules/fips.so
```

**Example FIPS config for Linux**
By default, linux installs likely have a default file at `/etc/ssl/openssl.cnf`. If you modify this file you can configure
your instance to use FIPS by default. Otherwise set the `OPENSSL_CONF` environment variable pointing to the config file
you want to use.

**Example FIPS config file for Linux**
```text
openssl_conf = openssl_init

.include "/tmp/fipsmodule.cnf"

[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
fips = fips_sect

[fips_sect]
module = "/home/cd/gitwsl/github/microsoft/vcpkg/installed/x64-linux-dynamic/lib/ossl-modules/fips.so"
activate = 1

[algorithm_sect]
default_properties = fips=yes
```


**Example FIPS config file for Windows**
```text
openssl_conf = openssl_init

.include "/tmp/fipsmodule.cnf"

[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
fips = fips_sect

[fips_sect]
module = "/home/cd/gitwsl/github/microsoft/vcpkg/installed/x64-linux-dynamic/lib/ossl-modules/fips.so"
activate = 1

[algorithm_sect]
default_properties = fips=yes
```

## Running with FIPS Module

If everything is configured correctly, you should see the following in the log:

```
(9729)[        0.010]    INFO ziti-sdk:ziti.c:540 ziti_start_internal() ztx[0] enabling Ziti Context
(9729)[        0.010]    INFO ziti-sdk:ziti.c:557 ziti_start_internal() ztx[0] using tlsuv[v0.33.9.1/OpenSSL 3.3.1 4 Jun 2024 [FIPS]]
```
