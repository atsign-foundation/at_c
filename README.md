<img width=250px src="https://atsign.dev/assets/img/atPlatform_logo_gray.svg?sanitize=true">

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/atsign-foundation/at_c/badge)](https://api.securityscorecards.dev/projects/github.com/atsign-foundation/at_c)

# at_c

`at_c` is the client C implementation of the atProtocol

## Packages

- `atchops` stands for cryptographic and hashing operations catered for the atProtocol, uses [MbedTLS crypto](https://github.com/Mbed-TLS/mbedtls) as a dependency.
- `atclient` is the core dependency for anything Atsign technology related. atclient depends on [atchops](./packages/atchops/README.md) and [MbedTLS](https://github.com/Mbed-TLS/mbedtls)
- `repl` is a demo application using atclient