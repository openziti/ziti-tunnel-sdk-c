# FIPS Compliance

FIPS (Federal Information Processing Standards) are security standards developed by NIST (National Institute of
Standards and Technology), a U.S. government agency responsible for promoting innovation and industrial competitiveness
through standards and technology.

This software is built to comply withe the FIPS 140-3 program, specifically with OpenSSL as of May 2025. The software is
considered "FIPS 140-3 compliant", it is **not FIPS validated**. 


the  FIPS 140-2 validated cryptographic modules to meet U.S. federal security requirements. 
It ensures that all cryptographic operations conform to strict government standards for protecting sensitive data. 
FIPS mode is optional and can be enabled as needed.

Specifically, OpenSSL 3.1.2 was used to create a shared library "fips.dll" 

https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985

The https://csrc.nist.gov/Projects/cryptographic-module-validation-program/faqs