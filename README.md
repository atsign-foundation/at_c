<a href="https://atsign.com#gh-light-mode-only"><img width=250px src="https://atsign.com/wp-content/uploads/2022/05/atsign-logo-horizontal-color2022.svg#gh-light-mode-only" alt="The Atsign Foundation"></a><a href="https://atsign.com#gh-dark-mode-only"><img width=250px src="https://atsign.com/wp-content/uploads/2023/08/atsign-logo-horizontal-reverse2022-Color.svg#gh-dark-mode-only" alt="The Atsign Foundation"></a>

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/atsign-foundation/at_c/badge)](https://securityscorecards.dev/viewer/?uri=github.com/atsign-foundation/at_c&sort_by=check-score&sort_direction=desc)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/8138/badge)](https://www.bestpractices.dev/projects/8138)

# at_c

`at_c` is the alpha C implementation of the atSDK

## Packages

- [atchops](./packages/atchops/README.md) stands for cryptographic and hashing operations catered for the atProtocol, uses [MbedTLS crypto](https://github.com/Mbed-TLS/mbedtls) as a dependency.
- [atclient](./packages/atclient/README.md) implements the atProtocol and will be the core dependency for most applications. atclient depends on [atchops](./packages/atchops/README.md) and [MbedTLS](https://github.com/Mbed-TLS/mbedtls).
- [atclient_espidf](./packages/atclient_espidf/README.md) is a package for helping you build atclient for ESP-IDF (Espressif IoT Development Framework) based projects.

## Examples

Check out the [examples](./examples/README.md) directory for examples on how to implement and use the C SDK.

## Contributing

Read [CONTRIBUTING.md](./CONTRIBUTING.md) for information on how to properly fork and open a pull request.

When creating source files, include headers, or tests to certain packages, please follow the documentation in their according README files (for example [atclient Contributing](./packages/atclient/README.md)).

## Maintainers

[Atsign](https://atsign.com/) maintains this repository. Feel free to contact us about anything at [info@atsign.com](mailto:info@atsign.com)

- [XavierChanth](https://github.com/XavierChanth)
- [JeremyTubongbanua](https://github.com/JeremyTubongbanua)
- [realvarx](https://github.com/realvarx)
- [cpswan](https://github.com/cpswan)
