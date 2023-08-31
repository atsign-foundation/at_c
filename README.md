<img width=250px src="https://atsign.dev/assets/img/atPlatform_logo_gray.svg?sanitize=true">

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/atsign-foundation/at_c/badge)](https://api.securityscorecards.dev/projects/github.com/atsign-foundation/at_c)

# at_c

`at_c` is the client C implementation of the atProtocol

## Packages

- [atchops](./packages/atchops/README.md) stands for cryptographic and hashing operations catered for the atProtocol, uses [MbedTLS crypto](https://github.com/Mbed-TLS/mbedtls) as a dependency.
- [atclient](./packages/atclient/README.md) is the core dependency for anything Atsign technology related. atclient depends on [atchops](./packages/atchops/README.md) and [MbedTLS](https://github.com/Mbed-TLS/mbedtls)
- [atclient_espidf](./packages/atclient_espidf/README.md) build atclient for ESP-IDF

## Examples

- [atclient_esp32_source](./examples/atclient_esp32_source/README.md) is an example of how to use atclient in your ESP-IDF with the source code.
- [atclient_esp32_static_components](./examples/atclient_esp32_static_components/README.md) is an example of how to use atclient in your ESP-IDF project with static libraries in separated components built from [atclient_espidf](./packages/atclient_espidf/README.md).
- [atclient_esp32_static_no_components](./examples/atclient_esp32_static_no_components/) is an example of how to use atclient in your ESP-IDF project with static libraries without components built from [atclient_espidf](./packages/atclient_espidf/README.md).
- [repl](./examples/repl/README.md) is a command line interface for interacting with the atProtocol. Works on Desktop Linux/MacOS.
- [repl](./examples/repl_esp32/README.md) is a command line interface for interacting with the atProtocol. Works on ESP32, not tested on other devices that can run the IDF.

## Contributing

Read [CONTRIBUTING.md](./CONTRIBUTING.md) for information on how to properly fork and open a pull request.

When creating source files, include headers, or tests to certain packages, please follow the documentation in their according README files (for example [atclient Contributing](./packages/atclient/README.md)).

## Maintainers

- [XavierChanth](https://github.com/XavierChanth)
- [JeremyTubongbanua](https://github.com/JeremyTubongbanua)