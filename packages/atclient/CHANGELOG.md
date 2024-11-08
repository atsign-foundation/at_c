## 0.3.0

- **Breaking changes** to `atclient_atkey_metadata` and `atclient_notify_params`
  - `long` and `int` type changed to `int64_t` (metadata: `ttb`, `ttr`, `ttl`; notify: `latest_n`)
  - `unsigned long` type changed to `uint64_t` (notify: `notification_expiry`)

## 0.2.0

- New release to use MbedTLS 3.6.1 to resolve a bug when building NoPorts on arm64 with musl libc

## 0.1.0

- Initial MVP release

