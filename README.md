<img width=250px src="https://atsign.dev/assets/img/atPlatform_logo_gray.svg?sanitize=true">

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/atsign-foundation/at_c/badge)](https://api.securityscorecards.dev/projects/github.com/atsign-foundation/at_c)

# at_c

`at_c` is the client C implementation of the atProtocol

## Packages

- [atchops](./packages/atchops/README.md) stands for cryptographic and hashing operations catered for the atProtocol, uses [MbedTLS crypto](https://github.com/Mbed-TLS/mbedtls) as a dependency.
- [atclient](./packages/atclient/README.md) is the core dependency for anything Atsign technology related. atclient depends on [atchops](./packages/atchops/README.md) and [MbedTLS](https://github.com/Mbed-TLS/mbedtls)
- [atclient_espidf](./packages/atclient_espidf/README.md)

## Examples

- [repl](./examples/repl/README.md) is a command line interface for interacting with the atProtocol. Works on Desktop Linux/MacOS.

## Contributing

Read [CONTRIBUTING.md](./CONTRIBUTING.md) for information on how to properly fork and open a pull request.

When creating source files, include headers, or tests to certain packages, please follow the documentation in their according README files.

## Maintainers

- [XavierChanth](https://github.com/XavierChanth)
- [JeremyTubongbanua](https://github.com/JeremyTubongbanua)