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
to attempt to initialize FIPS-compliance.

The format of the OpenSSL configuration file is specified by the OpenSSL doc located at
https://docs.openssl.org/master/man7/fips_module/#making-all-applications-use-the-fips-module-by-default

### Example openssl.cnf

An example openssl.cnf file might look something like the one shown below. Note the file includes the location of the 
`fipsmodule.cnf` as well as the location of the shared library to be loaded. Specifying these files in the configuration
file can help configure FIPS-compliance correctly.

Also note the `fipsmodule.cnf` must be generated on each and every machine in order to claim FIPS-compliance.

```text
openssl_conf = openssl_init

.include "C:/path/to/fips/config/fipsmodule.cnf"

[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
fips = fips_sect

[fips_sect]
module = "C:/path/to/shared-library/fips.dll"
activate = 1

[default_sect]
activate = 1

[algorithm_sect]
default_properties = fips=yes
```