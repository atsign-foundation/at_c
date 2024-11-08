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

