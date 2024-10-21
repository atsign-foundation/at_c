#include <atclient/atclient.h>
#include <atclient/atkeys.h>
#include <atlogger/atlogger.h>

#define TAG "test_atkeys_write"

#define ATKEYS_8INCANTEATER                                                                                            \
  "{\"aesPkamPublicKey\":\"+Jp1VdQuMANVkktasZhnZ9UStUMW0JMnNNYAqXWhyMHDB1PQMpCMWDzAQwF+IdXlJ10Hx2Q6iz0bgDOi6PKj+"      \
  "uxPIcYejBsHrKLNQsWru6eCj+ZmGG35K+BePqowbReP0FNp7eWlOxP8Ee9WEK0QDUPqhAZwN6dzqYoqsmdsfJbISqfj4sD+"                    \
  "iunJ5l6zmMRguXpe9IOPLKsR42kqQCkV3uibw0xhNNarAeSZwbBstiJCUJAu59ks7DyL/HdWQcQnCFaLPZIZZGh6iLzJHUpf5dY2JTln/4vs/"      \
  "DFxnhRKfM+TU2UzoESHKvcyJ1aAF9t1LeNc9nuEyqg+ZP5/"                                                                    \
  "iIW81KKdioXFDxsrktpdlQDKrCGqA9+FtLRwHaf7FT2v+DHbLUwq4OFGymyrIhIl1DG9ktqvaJTX8W8LE+sRPsRUx2z1/"                      \
  "hGSLQEDtiMakNKBhMr4pVv88jsdzqxdZ7MTEoa63Q//"                                                                        \
  "L82SWBvOElbGUnQevVRj2cgLu1AhAK+y3PciChs0AGVm8S7UEtTU6Fo9w9Dn0Q==\",\"aesEncryptPublicKey\":\"+"                     \
  "Jp1VdQuMANVkktasZhnZ9UStUMW0JMnNNYAqXWhyMHDB1PQMpCMWDzAQwF8Ear5HWcA7mkC1j403yOvl4K53LkLM8MCugsRmIDZQJWYssSvkpJ8Pmy" \
  "LS7NCJ74OcC+mz1xF7/iBEDiRXPpOCKdSEW3v7GR/LY0WoJ4epj9GSc+zI9/P+OL7p+fplXKkxeNchUEbsP/"                               \
  "3KI4L2n0GIB15xcGX5m9DJc31PfeC861qknVKScMDx8V0/GilzhZQRucjElq3VoNrCQ50kpe2XmIA/"                                     \
  "a4VJXFO6+TNyztyizJ8LZOAJVwtj23Ncu0bcRiQGtclMcsqzmPZy68/a78gg8ibwISxl8H+FwEwjNhGmw7gnVaKAoqKvYZSPf/"                 \
  "YSxyjwGuVI34o9fF0/120KAd38Qmhi9WrSbiLqWMIcJ04EftB2VL2/"                                                             \
  "hCafEA4hnIAmtK7tYHQsCvc7hEmwo4TKbNyDYr0yGrPMJeJIgjFZW7RBEolgEVtovoQqXASAMnx/"                                       \
  "sIUCi5+QkNm8S7UEtTU6Fo9w9Dn0Q==\",\"aesEncryptPrivateKey\":\"+"                                                     \
  "Jp1UusVOA9WsWFlm5RlUYQO7EZu9uYjNMYKrHWxo8PMBXnlFpCUcTz2QwFTO7PsLUcM/"                                               \
  "FJswRwZ2CW2oo7f1tc6IqI58Qo0laLeSYSSm7rPpbosIhSpDeJ8BY0Fb0/"                                                         \
  "p72FW7MeoADaKPdUgF78RJCbVww99RrcSkp8nmUplfsD3Pqb4oMDghcDdww6quP9epUZ9k7PUVqUjtFBKDxNNysie921SPODhG+"                \
  "6r9vJS6CNqeapA6MU12xzt6SZUZfU4LU+JHp8FfVRw89WIHUMAkMs8YhlD7dLG6C92iClNC9yETkULuUqbNL5reBWQQdFkJt8J9j6+"             \
  "ldICb4URpKq9yKicsbL4FEUOzuNAuS2sgC+VPLWnv7FgYNvXaj6M4zebGWhLwJZ9xjKyExMe6SeCk8nzL6Kno39gSPVJP+"                     \
  "o52UXWj2yreTFDsycBnsyttLntvW3E9Sc63oRJZqkULZDs6AvEQsq/"                                                             \
  "UBS9CXmHKVA5uTVC8ZtprAgdKazNyfYVawsmAkJkwwrSKqedhx93ipmqmj5TTwIihQHanQ/RzGHwN5/"                                    \
  "G1vj6axYYkob5KNNd3zMNTQ8LazXauMBqCe2bzP2CuFlyl7I82tA8Nsph3LQOgKgPgx/"                                               \
  "uUbnhTDd1g+hKSf5AbJlZecaEsauCoD3x8Xaq4tMp2OKg0Ssde+d8I6tJP512XoltJfOc9G0U75tc6+doqWtpV8F+jfs1Iwxy/"                 \
  "b9ctX7w1Tf2KdA0YQA1a1Me/"                                                                                           \
  "vPGGk+E7MoRRHKKWh4WfAJj1G6ejOVELmFlsktOjgA1fxNKktXzTqmzv+RPh+"                                                      \
  "zW5NtFKUIaDuYKZs09HrHTmdpG5qA5aarzIqotvzoJBEA2vNGKatJaEHmCV4EmS+DFKfU7PHNtw4aPf2pGidDPsaJuVFIDt1zKbdmkBvJXuC/"      \
  "2erLMhIW26RiPnCVnQtfYFD5UqKG0/OqKCzsG6aHbJThNvkxoz0ut7VoOBh3q5T7Kpdd/HX3AbGWaG5Qk5UElo2/"                           \
  "bwxqG92tPWgFJFWdb5NdZfOfAfEpd+MP6sZbc42DT/wQ6+swBnXMChTS5LUm1iNnnPYfoJcFB4WVPewtVZ3CxtftBqASSf1g2sZjFFv+Dg9nXZb/"   \
  "+bn8dTCouDz8LhTW2SptAoYRL4zrr7T/EtboN7vIfB//"                                                                       \
  "i5exnUMAruHta9uSs1eHZuamOyrsftV2+tCF8ZTj3ytiIp2vWTnMKaqVMzKgepuFOfjDyNmJcLJkAkSyS43eNVodm0TNmWOIri6cVI/"            \
  "EbtzkBAiRkWoeyKiT9tgnIBR94elq25PJVYaeFX0eMRIK/vTFh5RLI5D8QgM00kqNocE/e4IH27BqQRh4RsbWdzg9JBL9LTX72SXYvA0i+Zb/"      \
  "sy1eqOGsUfwE+0AMDgJsWAZQokRtNOtDhFScVM9UM/zZqPnnNJintRFeA0Og5LiokEdWQEQ7qDs48P1zJA42Ktv8qTsWHvGHKTTxLMMGnq/"        \
  "dBTDD4BL6GgbpkaZqQ/"                                                                                                \
  "eOBqfUW8v068oUg7GkddUfj4VKIcZJT2NGKEmVc6pq3WKaW3UG951yiYV0LONyEPB4mh20IbdU3r1PiIlII+sRiSmpZHk8u9/"                  \
  "SGNUc50ZyWri58S4UhZGMNjrc7MC2NDiNqpk3AwUjNFsd0fWW4CkCk3t6i2qZ/"                                                     \
  "qYFR2wDkFqLBbpqJjdbhFCHaRwMVoIU+2k8bTtg6UdTy7qKKAaeIHf3sZb6WsakOqb8Fu6kFOqUg1G9ImJkssA6V7EnWkWFkaDonAW7xSmKz1+"     \
  "qazCLD1EdeYmtJZNn4zxg48IhyYv6+O/AA9J3Wpezkc3qOhV1HSjS1tV2/Zuu00BsJC+uPjF/"                                          \
  "qI8ApvFKjgYb6JuztNr5eOuyjfPdfNFxNjqUo5DAMwZ2dkB1DS4H2eZPmnjo7p7gMNBJtQTKwknoW1mgaGgyKzMjyOdcMFtja4/"                \
  "kgjdx71N938eGah/"                                                                                                   \
  "MNxh6UlKOfmOHyEiHTrgPpVrbw7psQ5vREtrBUHDK2efqS4lStFjEsxyXZse8ebjJ2mdytPTD0jLps6izyTA+"                              \
  "ariIFEOfhAFUyPPGfHl5wpkhMklfSh6Xsdb4Ru9t6eU4QcFQoO7/ZQKu6cyrt4a+zS6r7K4CMG3EN/"                                     \
  "qItGp3XlZdWcICVRr13CgSAZFvudjvTADA+GgpviKbja0Z33N9TW2W/SAoU\",\"selfEncryptionKey\":\"ErES7LlWlIJAUEEwfvwqhjyi/"    \
  "NvTQ964uojS8KYcHvI=\",\"@8incanteater\":\"ErES7LlWlIJAUEEwfvwqhjyi/"                                                \
  "NvTQ964uojS8KYcHvI=\",\"apkamSymmetricKey\":\"Z7LAVzBhtBpkZHleFmINyPW2jTofBOph3oqaTipJWCE=\",\"enrollmentId\":"     \
  "\"865839ed-856a-4c97-b475-7a8ead295f17\",\"aesPkamPrivateKey\":\"+"                                                 \
  "Jp1UusjOA9WsWFlm5RlUYQO7EZu9uYjNMYKrHWxo8PMBX3lFpCUcDz2QwFTO7PsLUcMyDRtzwIZijG7qYO9/+o6FsYDpXM/"                    \
  "lrrvfaGdjsWFtbBlFzPmVp5gOasMUEGu/0Vt//GtckGMJdNTHqQPLnzK6iZMJslNzuYznmlnR57qMYvulNf9h/PH7VqQpvpEhlx2iJ/"            \
  "jTOIa5F4cGwRZ6MO24VJiXdzPCsGf0+kq6nAKRpwO2PlI9j2S/"                                                                 \
  "3EucPddL2u3PJkvOnUO9aOWQzIi46klcj1M2PnyyiE7ukhcJOaqf1ghkH7TLbh2BEuGWMtYF8BY6UWKw60+"                                \
  "PfB7gq65xbyti5jDMxw3iMpCqgPMrSedAoupvo5JDe7OGxm3hVXaBlxfztp5/"                                                      \
  "EWMBBwf0Ri7qfiqU52siUhCRq4VGvdC7XbytjC0JwEcryceuun8rZnPg0vC9Bp4mrN2A98XCvHK0jXZLPSWHgW7ZUSBFmktljZKpvAtokgQCqD04Ow" \
  "xAA5/Ripc5QvvYOSdhx93ipmqmj5TTwIq6Rzjv1+6yXHPNZ/"                                                                   \
  "D8NjrbWde+avcYvRcwUwCQAFIFzed6YtyFMWJsc3vjnRwy4Iq3tUTGd9Et4w6vtgBlF6nCb/vFhIWk+ZdZt8kZrhkcsD2idaDpg617k23+cY98Yq6/" \
  "mpKStkqcOR6BZtUfpFrD//D8QZswLxC9pRouw9yI8BstdJ4TBIK1ew23nHloQjTN+kyf2p/KiAWuaXeKjyXgfsEfRuKEx8GGgBS/"               \
  "m2QuOwOdhtlnQcynwtHWwRumtbJT5Pd47023sTq/"                                                                           \
  "6IsLkpcU8kabsEbMafr1K1ygs5be+"                                                                                      \
  "3eOKZUwhh1MkxvsJO0SM8GCmCOV6gDbazCLtkPF31F99PAckNV08rIuPRGD2tx1y3oPaeMfuNB9zuwWZCTpri34EO5xnkELrSFBloo8JG8ye7eU28j" \
  "kryXMjNFjUAd8HWD5GYJBAHlwxjcw75vXiixVnGRGZQk5UElownH/jimyjZcSCxAAGt4tfs6VPygUwhwwL/r7JziuGmNxSgPu9dC/UsLg2icKyLTk/" \
  "7Ff63kZbQs2xJQflEARRCmpPN/"                                                                                         \
  "oR2Lew89jaToHbSJiKToTN+"                                                                                            \
  "geS4MVmwkIFgxnQ2EcLx0heQWpRmougCY1Ndo0fdQFrTA1Js7SMoytCN9t6GQ87vJq5m10q4v60Gt2kJEREmkko3v3BCSFFwJa9dO7b1dnMtKSQeUN" \
  "mJcLJkAxTOh+QLRfLt0wXJNZ5lXl+ssX5sBixIlAk9iKs+7Txb+kGnNEB45X06N0eRSZIa+D07CZ5no4FJiqkvu9TE/idVjsbVVRXL/"            \
  "3d3q3wiwRDta0aruxStvSs0pWWObXkweEW3UYqPvkWi0G14hLTQ/"                                                               \
  "yw5ZraJYTvQJ7W1oUvfib1ESK8Mw2D1RI3nHKUjzc3W7xddTKDg7POfME1XmHMlFeB/"                                                \
  "0Pfaxm+spSrChvGHKXyhvUuCay809fhnDc9GGt+83aNvU+7PJnNg/"                                                              \
  "+89skbAizHJWZ3jl+"                                                                                                  \
  "VLsbNMQifTMJl5dm5WxeoWu43Hi4WuMdG0tcN2rOyIdk3dfeJIJx3HkYTNK3fFhSXt6VkwjkIa5MGgv97rKkBt8Ho0MR0wo6MQVKHuMKVIkrh209kv" \
  "fP8B8XiSie3+6/8iN+qd/trRKqWfKJtjdXIWcqd7pCwGnfkIzvZs65GZzG/"                                                        \
  "gycur+7ZWQG4T5OPHEVILkzYoJsJIusJh1L45d0BFoleRKphGe90LEnxt3Pjl5PDjsBmuC2+ij+m+"                                      \
  "7yi5cSGdoY5yf6C0gyrxjQvq7Yb8F3erHkO6obWPdiGFjEzeGjCKpcfGKyUcJWtiNkESsCPorvmfwkvWhDfCOTIEmI/"                        \
  "m+H4kENxVVuLMb81UN9Lq2qwR5cI79BIzY1UVkmLwAPRdiYDG7oEIJzW1bdyCBrN/xbeYGHtbZ/"                                        \
  "NcUtOQg69lD07OFs6sewWSih8H1p96cbBrgnQfDGIfB44IFzPlDi81XZSukQ9et4UqiJmQJuB39ldEhc0ho3Ne4ICOw/P99ygvsMhDg/"           \
  "3UEBaT1IVQ6M8+HHg9KjA5ZlwDH3K7rLKxKoK17F0AMZBsSYa73eoGGKVWw7u+"                                                     \
  "oCunTPuaSC2g5proxG4DwuspUdZLTc4V3FhiNJF3McjOKL0t4DHoWv5qAVAZQo99TW2W/SAoU\"}"

#define ATKEYS_8INCANTEATER_1_FILE_PATH "@8incanteater_key1.atKeys"

int main(int argc, char *argv[]) {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  atclient_atkeys atkeys1;
  atclient_atkeys_init(&atkeys1);

  atclient atclient1;
  atclient_init(&atclient1);

  if ((ret = atclient_atkeys_populate_from_string(&atkeys, ATKEYS_8INCANTEATER)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "failed to populate atkeys from string\n");
    goto exit;
  }

  // log what fields are initializwed
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_pkam_public_key_base64_initialized: %d\n", atclient_atkeys_is_pkam_public_key_base64_initialized(&atkeys));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_pkam_private_key_base64_initialized: %d\n", atclient_atkeys_is_pkam_private_key_base64_initialized(&atkeys));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_encrypt_public_key_base64_initialized: %d\n", atclient_atkeys_is_encrypt_public_key_base64_initialized(&atkeys));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_encrypt_private_key_base64_initialized: %d\n", atclient_atkeys_is_encrypt_private_key_base64_initialized(&atkeys));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_self_encryption_key_base64_initialized: %d\n", atclient_atkeys_is_self_encryption_key_base64_initialized(&atkeys));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_apkam_symmetric_key_base64_initialized: %d\n", atclient_atkeys_is_apkam_symmetric_key_base64_initialized(&atkeys));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_enrollment_id_initialized: %d\n", atclient_atkeys_is_enrollment_id_initialized(&atkeys));

  if ((ret = atclient_atkeys_write_to_path(&atkeys, ATKEYS_8INCANTEATER_1_FILE_PATH))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "failed to write to path\n");
    goto exit;
  }

  if ((ret = atclient_atkeys_populate_from_path(&atkeys1, ATKEYS_8INCANTEATER_1_FILE_PATH))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "failed to populate from path\n");
    goto exit;
  }

  // log what fields are initializwed
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_pkam_public_key_base64_initialized: %d\n", atclient_atkeys_is_pkam_public_key_base64_initialized(&atkeys1));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_pkam_private_key_base64_initialized: %d\n", atclient_atkeys_is_pkam_private_key_base64_initialized(&atkeys1));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_encrypt_public_key_base64_initialized: %d\n", atclient_atkeys_is_encrypt_public_key_base64_initialized(&atkeys1));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_encrypt_private_key_base64_initialized: %d\n", atclient_atkeys_is_encrypt_private_key_base64_initialized(&atkeys1));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_self_encryption_key_base64_initialized: %d\n", atclient_atkeys_is_self_encryption_key_base64_initialized(&atkeys1));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_apkam_symmetric_key_base64_initialized: %d\n", atclient_atkeys_is_apkam_symmetric_key_base64_initialized(&atkeys1));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_enrollment_id_initialized: %d\n", atclient_atkeys_is_enrollment_id_initialized(&atkeys1));

  // compare the two atkeys
  if (strcmp(atkeys.pkam_public_key_base64, atkeys1.pkam_public_key_base64) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pkam_public_key_base64 mismatch\n");
    goto exit;
  }

  if (strcmp(atkeys.pkam_private_key_base64, atkeys1.pkam_private_key_base64) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pkam_private_key_base64 mismatch\n");
    goto exit;
  }

  if (strcmp(atkeys.encrypt_public_key_base64, atkeys1.encrypt_public_key_base64) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "encrypt_public_key_base64 mismatch\n");
    goto exit;
  }

  if (strcmp(atkeys.encrypt_private_key_base64, atkeys1.encrypt_private_key_base64) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "encrypt_private_key_base64 mismatch\n");
    goto exit;
  }

  if (strcmp(atkeys.self_encryption_key_base64, atkeys1.self_encryption_key_base64) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "self_encryption_key_base64 mismatch\n");
    goto exit;
  }

  if (strcmp(atkeys.apkam_symmetric_key_base64, atkeys1.apkam_symmetric_key_base64) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "apkam_symmetric_key_base64 mismatch\n");
    goto exit;
  }

  if (strcmp(atkeys.enrollment_id, atkeys1.enrollment_id) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "enrollment_id mismatch\n");
    goto exit;
  }

  if ((ret = atclient_pkam_authenticate(&atclient1, "@8incanteater", &atkeys1, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "failed to pkam auth\n");
    goto exit;
  }

exit: {
  atclient_atkeys_free(&atkeys);
  atclient_atkeys_free(&atkeys1);
  atclient_free(&atclient1);
  return ret;
}
}