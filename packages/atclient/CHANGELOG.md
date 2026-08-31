## 0.4.0

- fix: atchops_rsa_encrypt takes an output-buffer-size bound (**breaking API
  change**: callers must pass ciphertext_size and may receive the written
  length via a new optional ciphertext_len out-param)

## 0.3.11

- fix: route the enroll connection through 'proxy:' root specs with from:

## 0.3.10

- feat: at_activate supports 'proxy:' root server specs (activation via 443)

## 0.3.9

- build(deps): Bump MbedTLS to 3.6.7

## 0.3.8

- build(deps): Bump MbedTLS to 3.6.6

## 0.3.7

- build(deps): Bump MbedTLS to 3.6.5

## 0.3.6

- build(deps): Bump cJSON to 1.7.19

## 0.3.5

- feat: Add Conan based SBOM creation with sbomify

## 0.3.4

- build(deps): Bump MbedTLS to 3.6.4

## 0.3.3

- fix: monitor resiliency
  - Added a new monitor message which represents an empty message after a timeout

## 0.3.2

- Fix unused include warnings in notify

## 0.3.1

- **Breaking changes** to `atclient_atkey_metadata` and `atclient_notify_params`
  - Some `int64_t` definitions were stored as `uint64_t` in the struct
  - `uint64_t` type for `notification_expiry` changed to `int64_t` since it also maps to a dart int (int64)

## 0.3.0

- **Breaking changes** to `atclient_atkey_metadata` and `atclient_notify_params`
  - `long` and `int` type changed to `int64_t` (metadata: `ttb`, `ttr`, `ttl`; notify: `latest_n`)
  - `unsigned long` type changed to `uint64_t` (notify: `notification_expiry`)

## 0.2.0

- New release to use MbedTLS 3.6.1 to resolve a bug when building NoPorts on arm64 with musl libc

## 0.1.0

- Initial MVP release

