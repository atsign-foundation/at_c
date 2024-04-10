
#ifndef ATCLIENT_CONSTANTS_H
#define ATCLIENT_CONSTANTS_H

#define ATCLIENT_ATSIGN_INNER_LEN 55                                                             // 55 utf7 chars
#define ATCLIENT_ATSIGN_FULL_LEN (1 + ATCLIENT_ATSIGN_INNER_LEN)                                 // '@' + 55 utf7 chars
#define ATCLIENT_ATKEY_KEY_LEN 55                                                                // 55 utf7 chars
#define ATCLIENT_ATKEY_NAMESPACE_LEN 55                                                          // 55 utf7 chars
#define ATCLIENT_ATKEY_COMPOSITE_LEN (ATCLIENT_ATKEY_KEY_LEN + 1 + ATCLIENT_ATKEY_NAMESPACE_LEN) // {key}.{namespace}
#define ATCLIENT_ATKEY_FULL_LEN                                                                                        \
  (ATCLIENT_ATSIGN_FULL_LEN + 1 + ATCLIENT_ATKEY_COMPOSITE_LEN +                                                       \
   ATCLIENT_ATSIGN_FULL_LEN) // {full_atsign}:{composite_key}{full_atsign}

#define ATCLIENT_DEFAULT_NOTIFIER "SYSTEM"

#define ATCLIENT_MONITOR_BUFFER_LEN 4096 // max chunk size monitor can read at once
#endif
