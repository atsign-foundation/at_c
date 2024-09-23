#include <atclient/atkeys.h>
#include <atlogger/atlogger.h>

#define TAG "test_atkeys_from_string"

#define ATKEYS                                                                                                         \
  "{\"aesPkamPublicKey\":\"r/"                                                                                         \
  "ierjIIT6E3sp5X6at5j2+OzSe7U3KykExPLEtxRnlV6MLqML8sr3xa7ZoGjsXXIsaG+"                                                \
  "0Wd9KUQXUiVtxH9gb7MOsp7uGGUELiJJJ2NMxBJnNdvdRMapk6+PzK5JBw46HGumm0qlMrbvqOlAuo4nV7x7Ghi0FpXzEHQY7GdFWqN+"           \
  "gdUcwGHRqSnnMjvtfDXaKxeDIZot2AMMwNAQS6drEtn8/i2UfbuXjVWD1HDKOcwqu6OwNpLP4jJ7xEunGN97urgO/7oCUioxiFpiGGQRTSB//"      \
  "XayAKPLAtcnjHEh/JtQJKVnQQB6EhV44l1mCOkNTc1jX7iEJpkiPcUcAFosMI+SlaLlxsmkCpM7zZdXKbZklo65pNZTYiZDLGj2eAzZu6m3Xfg14P/" \
  "Ple0YiWQv/05VkeyKKXCO2/adKcAr7efvj2hTMXXKxSeKhtgEz1FOWOYladpnp21wmJag3veWdtJRFjg9euVSmLqcukgIPMdFiXbyH8Kn0/"        \
  "WNcbPAK29fbXbyCjqkJseLNhURd+sSg==\",\"aesPkamPrivateKey\":\"r/"                                                     \
  "ieqQ0FR600kbRow6d7uT6SlCLDdQe2kFxFKUthLXta6uzfFL80h3xs7Zos0/7/DtD1/"                                                \
  "Vek468kR1yrlTjchba3C9ZLkBqCIeadOIefcA8rgt9UaEoY42adNjP/N0ok6UKzwEEaytT/uei7O/"                                      \
  "AT7Hfn4zlm6ChA80SgYJPZOF6bryB5RjrXPPbcjOTEkNfjbYZsAoRDohQ1Czl3fCeygGsJgOywKuPiYgozOWvNL8QwoLGg0vItM73FzXU0lAkO1c2v" \
  "IqflL1ytvR4DrFyZbkGEwuix8waZJzUKnxbA9/BrNpjej2JEpxZ3jKJ5ySKqOic65CKjJoZelpJXNR5/"                                   \
  "zZkacHXIsScJ3AlOjy1kXove4lsH1u1vMZaSK7/GjJNpddb6/Gu39Ki/"                                                           \
  "DiWpYC3kmvhGe3b3NZLWPFfLddJLiYf12QabQIvGCni2UydhFgVoQV6LmeZYqo3P10J0uQfvTP14WXfC5OK2ZRLfdYo1XcQeFi3W3yIImRz4L+"     \
  "3DM5iDD93q4yzau+xXQ50eDJbhATHpWWN5QjQdQzQRVxKcA7uIIcrwFWKW4vfHPgr4g5Ryh0JMQr7SE5SDJ14AUjBMEec+LgUJk4cgGNbS7c/"      \
  "fGBmfiNeOhw+5v2VE8ZuJJw4Q8IFs+fQ0bnhesoQ+dtY3a81ZGDj1XjGHw9zlxF/UFJbBHolhDw0bSL4Yhq/YIehCdbVVf2gkCBT8+WTY4ktkx/"    \
  "1HqPhrmeU5OlybwOlc/pfpRLq7XDCea+XvvDzNKn8VkE3ccUrRplbEawswvY/wgLoy1/KOuY/"                                          \
  "eEhOZLQZXuMB40npBrRAcKZ0fMVeXIENIkCYo8PzHcZBdowDofQdeZ4+OeNRdVmZ1ti9L+"                                             \
  "TWZ16ck5ByLiNXWf8tlDwQUuhzpHbVtoGijqnDSYIh80c0+"                                                                    \
  "5IxWHb1zCMPSHdJvyHCIfohhRUca9t47NYLQySNKVEpSj7n91YVOoe3R6h6j0hv1rNzG1DZNaBqf84K40cFLALIrVJbyS9ikvR2zh2W1mgRAhSygtQ" \
  "ZOoMATjdiiUjyqeWGkL9cIdqLJkJ5ny3P6rwDOP/"                                                                           \
  "7D3NmJnZTRVKIgUq7Xi53hU2zYfYkEyb+CcXFXpilZ3unBPh6WRLTgIzCoWerLwt6dnqGJaFdssHorRD8t8xRwFVX6y046yaMyF+"               \
  "ayVhsosgIp5MZR0wNjPgGKo9xGAhc2YUbnmzyaZMrTgTSZM8ZM6k+0AVytU/0GaHOpAkxYlvjg6NyrhCrQmKYKAc8trW9gUo/"                  \
  "MCdkKd2KXLk3rjvMSQPLUBl5xAIemHTIszoKwzOXbcYSFtYD6EvL9ob3lZAMYLK/F7kPv1zB+HqNU2zw+wTfWDAnoc0GVaJlm/"                 \
  "dve9FMJecf5HFD5thgUKdFyZ7Wx/7iMzPSzJ25wbxamsgGBOmRn77RWk43OBrXO0+vYpRFO7LGa+NQex0Q7IjHe4y7aP7pDPHf6W0y/"            \
  "XB0oMfT51kkssqMFKy3Kigl1pcBkPg8g2gpQ7bHSWZY5AMDH9xJiR32ubHvFX3eRV+TkYYl8DHJd9DoYMNkH90eXlued+"                      \
  "4FElNc65gtMkxVij4p5TAMIrH5QVPtXr7QHY40t0sU0FxGMoMYj6fi4n8KbJEnVnmhVntG1uzt98tjl0N14alSMOyalBz0E/"                   \
  "xzhG5DU7j8qUpKcNEsTk+EMB46pIchjDVfspkN1KWHE1Aqwcpd167HbMHF19yxvxBx0g/+1FM7TdYcGT/68VaCFCIXe66Yx3C5RfTx/5/i11Y/"     \
  "lu1Kha3ZXoXZD8xh0EtVrApvwEYIKMdffkIRjPSBrSrZaNu2PCHJ/"                                                              \
  "nu0NNzlpor7NIHVyf1s8TvY6zEIwFKMA4zgs3bSZNJXVk1JjNiHsU26IkB58OaOT9SAy2lCXnY9jHYAnqUfcTrhAAOZ3UyBJ1KlWDZ73suFnNF/"    \
  "Sq42I1Hg41SELJbBB/"                                                                                                 \
  "PxnRV9KxC2bdXEEBFL4i1FQEGJhqLTeft1KOhEUOTKIhrNFFPhXj2oHjpBLU0UpcmpvIbXxJvcygHed3GW44LWO55DbM8uDRWoKWOXNhC8uNRGm3n9" \
  "7jNcxQRpv+HA5z1P4KK9adFZbZNczCJlNfKhc6eIi/zHOS/"                                                                    \
  "vvEIfLXbuXc9IEQizQJCknYkDO8sk42j9SpX1SUVXT2UYtoyqvGdLz4YvFuVkohhOw\",\"aesEncryptPublicKey\":\"r/"                  \
  "ierjIIT6E3sp5X6at5j2+OzSe7U3KykExPLEtxRnlV6MLqML8sr3xa7Zoc5s3UJdWFy3yk/"                                            \
  "68JWlj3qS+i4ZCPOctjsDfvE7HIM4CyAwk2nKNOFGQe4xqXY1bUD2ZD1yf3gWMejs3y5uKPR+0C62ai0zwA7zYXsGjYRJWjdn+l/"               \
  "jlVZACpIM2g2ZTHpvT9SM1gHptJgBQeBhhvQB7gyxZ+kM6Cb9qTPRgGEmvhANZ3hbGC9PRXAoHCyRMRjXlPqZP0aJK+CkmuvBJCh1WadTSt5/"      \
  "La2yimGRUUji6m8MhuPMmPshNCjiZu9YJp73vVPUo3xnCnL+NSjs4QQFNk8JIldkWOkjhK7mBc9hlIY5XSyEA08Y5ncZfHK4eCxN4+"             \
  "OcT43xnhwICeNja1XQrkvc4Vc32uGr6gZV7OBvgr64Wi9z+qb+61cBXQZjFkaw4PdHGaupZAs9vU0E56nSOVXe5KeVibxs/"                    \
  "TX27qbskoMNAEEgbQ7wcXnB7lLczGEIG2OJPbyCjqkJseLNhURd+sSg==\",\"aesEncryptPrivateKey\":\"r/"                          \
  "ieqQ0jR600kbRow6d7uT6SlCLDdQe2kFxFKUthLXta6tLfFL80hXxs7Zos0/7/DtD12Vie57gWcWix1Bbx5OayV+ZIqAydC+qeEaKOLxNNoZdiNWc/" \
  "42OAbG/NGhgL/mKH2VAT6o7kobmYM7ZanHj28FpB5T5K2F77dsmNKT6HihRJRGSMNOfch/"                                             \
  "Dws5zrYo1VG4BVoDQeICFpUluFlRNyoYaDfezpRjAbGTLtTtd7+"                                                                \
  "6yy5vpkLLL20xs3rx1u6fvjBauwT0Gci2JmuFniITeK8NTMwSibL1BDnBz48c1kTp/"                                                 \
  "YsGFy7RFZ2Ppi2wXODz8T1xe6N61eo9cRZERvuIAkLUO0oRo/4wJK0DYFX4/"                                                       \
  "z4WMi8fMGUYnuVeaAqN9vNK2Mxh2Z44usChbKaziVuNsZdlO1D4TiEWjxCqcArK+XxAmgX+nXKni+"                                      \
  "ewdjBRVse3mLwbtqgKOo3EhEvxv1efQneEbz5MmIZ0XSV/AEDdg0GT/"                                                            \
  "09i05owrfEJHXFZ6jZoHZyi7p479XQ50eDJbhATHpWWNFAh8vfHM7QSvcD72fGpHSRm2z397QPAnhl6FjqlxWeI/"                           \
  "fA6XfIE4yfz9JDYs5G2oIudw+YOPf6PnPETG004qUpCyyrBlqu4ezFVJSyfNZ/"                                                     \
  "b90e2QfzI8pZNRVYNNAMTPuXiui88XsxHPiTYq6Erh3Cydxettpsf+odv0Cf7YUJnV1LwDk4BXO9VBpptVfmPsRoNMJAEuxpLxOw+fEa+"          \
  "6GRRmfbLSDsEH5AWoEuXX1Sh+Jj2TtQhYFkrPHgrUDqq+ild6yCQ+hCSZD6thpnERD3F8qIbItVUXoIB9F+"                                \
  "l80tdvgPbNvnTyvXy1cPqSjce4lUSZNkSIIuy647PguyxnRuvuhVtR2KiUV5wikZr1MpiWBt2T6EL5O/"                                   \
  "dEUtLEXCcB4C9vdfZ9xtXu3ZJgNHnMdy40ZMqXP9F9JUlcOwoTp0/"                                                              \
  "dwusqY8kC6zlLxgvzx6Vp9ZyaP8IK40cFLAJo+RoDTJevOwyCXoHSH5l1J+yzTowBKoudSq47dSjeSSGqCfPUPA+HSufw0sHzRrAa4aYXE5b+"      \
  "nw53xU7kdUonng+LKan7hGJUfxY2OHitRkyd4+/GrKx6Ye/mAYC6nRcre9MP8+7SEY1xDs2pXXi0dxj1eLlXgkVQc9KIFRvORXjcYkiw/uv0/"      \
  "rSJEMw+ItopGJiw8YFjjqkacda/0x0epIc1E32+3DFSMU/"                                                                     \
  "0GaHOpGl5g6piaseu+"                                                                                                 \
  "vTXBupQYQPVO9R0RYrHkL5YXakahHzXch40LQOfxLktCG9qmIAEvxIunyb3bbZyVhpa8MtHkjJnIVBoTBYbezHrj0yd2doRtmy9f3hKVBAjFcXa/"   \
  "BdhUrICE4msOd7b2ImHk8BsxWvNeXIvIxI2YqtLIIGZOalK2kTWHVx1YkIlX8rH7HqfSsOfkkwRu0ZKLgZJowEoGQDSY/XWVdZUpMC7cW0y/"       \
  "Vwopb5fZwygkjZ8tcSz+gwNpjKpDFAc7ygIS8+/AWY8CF9T30wx0fiWaVUbeM1XdYejASvIUCHI5+wdhPa0/"                               \
  "llb82NKMnL9gkv86zzRcnTZThIBbP187nkxyQJBRgaIgV9EEl/J6X13wou0W2dKZr966WkPLp3IOva/UkwEr4/b22eVjVAKLVRr9RyYv43/"        \
  "WUsuk4ksXdKqDeQxfrJRRDLbRAZQDBCP9qkhrKWHE1xuSTJASzLynElFa/w9w/HtH6NK0E/vvQY0FV8LEf+bbPY/"                           \
  "Ws5kpqzkrWUQI4Zipx6X1tV2vOnVX7Ups/"                                                                                 \
  "TgwbPlBC43DavIMAdiPkeBUPWVudrZ0EfeUKjcsh8sWWD8ir4LtS2hQPkwadPJwmX1HL6Uy4QAt5ZmWVqamoxdpJTuhD2+EuDFObI+"             \
  "87jIA5R6T4PZoba0O+nPgAN9KNuxSFwlvstduCY/"                                                                           \
  "2yvlcaXr0nYi45QctjywNKahKmqthD0QKohzDMQATHkXbzlo3DiAqhMbWQchQJXtcBTra7rcFKfge13cw17xFfFkqcnd6DMr6EO4uthibuSn9+"     \
  "ve11u2vd7mgVV86fOWqnAYwMhXT5X5KoflZUC975HQ3zWzEJq1KOAJmSK8SJtFsVec8mOQinRaXVqaQTq3WY6uyEsEjQSLwQytXOSXg2c1bxggt+"   \
  "BpeXAmvu2w8vkiXccaclovFuVkohhOw\",\"selfEncryptionKey\":\"REqkIcl9HPekt0T7+rZhkrBvpysaPOeC2QL1PVuWlus=\",\"@"       \
  "sitaram🛠\":\"REqkIcl9HPekt0T7+rZhkrBvpysaPOeC2QL1PVuWlus=\"}"

// define each json key
#define AES_PKAM_PUBLIC_KEY_TOKEN "aesPkamPublicKey"
#define AES_PKAM_PRIVATE_KEY_TOKEN "aesPkamPrivateKey"
#define AES_ENCRYPT_PUBLIC_KEY_TOKEN "aesEncryptPublicKey"
#define AES_ENCRYPT_PRIVATE_KEY_TOKEN "aesEncryptPrivateKey"
#define SELF_ENCRYPTION_KEY_TOKEN "selfEncryptionKey"

// define each json key value
#define AES_PKAM_PUBLIC_KEY_VALUE                                                                                      \
  "r/"                                                                                                                 \
  "ierjIIT6E3sp5X6at5j2+OzSe7U3KykExPLEtxRnlV6MLqML8sr3xa7ZoGjsXXIsaG+"                                                \
  "0Wd9KUQXUiVtxH9gb7MOsp7uGGUELiJJJ2NMxBJnNdvdRMapk6+PzK5JBw46HGumm0qlMrbvqOlAuo4nV7x7Ghi0FpXzEHQY7GdFWqN+"           \
  "gdUcwGHRqSnnMjvtfDXaKxeDIZot2AMMwNAQS6drEtn8/i2UfbuXjVWD1HDKOcwqu6OwNpLP4jJ7xEunGN97urgO/7oCUioxiFpiGGQRTSB//"      \
  "XayAKPLAtcnjHEh/JtQJKVnQQB6EhV44l1mCOkNTc1jX7iEJpkiPcUcAFosMI+SlaLlxsmkCpM7zZdXKbZklo65pNZTYiZDLGj2eAzZu6m3Xfg14P/" \
  "Ple0YiWQv/05VkeyKKXCO2/adKcAr7efvj2hTMXXKxSeKhtgEz1FOWOYladpnp21wmJag3veWdtJRFjg9euVSmLqcukgIPMdFiXbyH8Kn0/"        \
  "WNcbPAK29fbXbyCjqkJseLNhURd+sSg=="
#define AES_PKAM_PRIVATE_KEY_VALUE                                                                                     \
  "r/ieqQ0FR600kbRow6d7uT6SlCLDdQe2kFxFKUthLXta6uzfFL80h3xs7Zos0/7/DtD1/Vek468kR1yrlTjchba3C9ZLkBqCIeadOIefcA8rgt9UaEoY42adNjP/N0ok6UKzwEEaytT/uei7O/AT7Hfn4zlm6ChA80SgYJPZOF6bryB5RjrXPPbcjOTEkNfjbYZsAoRDohQ1Czl3fCeygGsJgOywKuPiYgozOWvNL8QwoLGg0vItM73FzXU0lAkO1c2vIqflL1ytvR4DrFyZbkGEwuix8waZJzUKnxbA9/BrNpjej2JEpxZ3jKJ5ySKqOic65CKjJoZelpJXNR5/zZkacHXIsScJ3AlOjy1kXove4lsH1u1vMZaSK7/GjJNpddb6/Gu39Ki/DiWpYC3kmvhGe3b3NZLWPFfLddJLiYf12QabQIvGCni2UydhFgVoQV6LmeZYqo3P10J0uQfvTP14WXfC5OK2ZRLfdYo1XcQeFi3W3yIImRz4L/3DM5iDD93q4yzau+xXQ50eDJbhATHpWWN5QjQdQzQRVxKcA7uIIcrwFWKW4vfHPgr4g5Ryh0JMQr7SE5SDJ14AUjBMEec+LgUJk4cgGNbS7c/fGBmfiNeOhw+5v2VE8ZuJJw4Q8IFs+fQ0bnhesoQ+dtY3a81ZGDj1XjGHw9zlxF/
#define AES_ENCRYPT_PUBLIC_KEY_VALUE                                                                                   \
  "r/ierjIIT6E3sp5X6at5j2+OzSe7U3KykExPLEtxRnlV6MLqML8sr3xa7Zoc5s3UJdWFy3yk/"                                          \
  "68JWlj3qS+i4ZCPOctjsDfvE7HIM4CyAwk2nKNOFGQe4xqXY1bUD2ZD1yf3gWMejs3y5uKPR+0C62ai0zwA7zYXsGjYRJWjdn+l/"               \
  "jlVZACpIM2g2ZTHpvT9SM1gHptJgBQeBhhvQB7gyxZ+kM6Cb9qTPRgGEmvhANZ3hbGC9PRXAoHCyRMRjXlPqZP0aJK+CkmuvBJCh1WadTSt5/"      \
  "La2yimGRUUji6m8MhuPMmPshNCjiZu9YJp73vVPUo3xnCnL+NSjs4QQFNk8JIldkWOkjhK7mBc9hlIY5XSyEA08Y5ncZfHK4eCxN4/"             \
  "OcT43xnhwICeNja1XQrkvc4Vc32uGr6gZV7OBvgr64Wi9z+qb+61cBXQZjFkaw4PdHGaupZAs9vU0E56nSOVXe5KeVibxs/"                    \
  "TX27qbskoMNAEEgbQ7wcXnB7lLczGEIG2OJPbyCjqkJseLNhURd+sSg=="
#define AES_ENCRYPT_PRIVATE_KEY_VALUE                                                                                  \
  "r/ieqQ0jR600kbRow6d7uT6SlCLDdQe2kFxFKUthLXta6tLfFL80hXxs7Zos0/7/"                                                   \
  "DtD12Vie57gWcWix1Bbx5OayV+ZIqAydC+qeEaKOLxNNoZdiNWc/42OAbG/NGhgL/"                                                  \
  "mKH2VAT6o7kobmYM7ZanHj28FpB5T5K2F77dsmNKT6HihRJRGSMNOfch/Dws5zrYo1VG4BVoDQeICFpUluFlRNyoYaDfezpRjAbGTLtTtd7/"       \
  "6yy5vpkLLL20xs3rx1u6fvjBauwT0Gci2JmuFniITeK8NTMwSibL1BDnBz48c1kTp/"                                                 \
  "YsGFy7RFZ2Ppi2wXODz8T1xe6N61eo9cRZERvuIAkLUO0oRo/4wJK0DYFX4/"                                                       \
  "z4WMi8fMGUYnuVeaAqN9vNK2Mxh2Z44usChbKaziVuNsZdlO1D4TiEWjxCqcArK+XxAmgX+nXKni/"                                      \
  "ewdjBRVse3mLwbtqgKOo3EhEvxv1efQneEbz5MmIZ0XSV/AEDdg0GT/"                                                            \
  "09i05owrfEJHXFZ6jZoHZyi7p479XQ50eDJbhATHpWWNFAh8vfHM7QSvcD72fGpHSRm2z397QPAnhl6FjqlxWeI/"                           \
  "fA6XfIE4yfz9JDYs5G2oIudw+YOPf6PnPETG004qUpCyyrBlqu4ezFVJSyfNZ/b90e2QfzI8pZNRVYNNAMTPuXiui88XsxHPiTYq6Er"
#define SELF_ENCRYPTION_KEY_VALUE "REqkIcl9HPekt0T7+rZhkrBvpysaPOeC2QL1PVuWlus="

static int test_1_atkeys_from_string();

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  if ((ret = test_1_atkeys_from_string()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_1_atkeys_from_string: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_atkeys_from_string: %d\n", ret);

exit: { return ret; }
}

static int test_1_atkeys_from_string() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_atkeys_from_string Begin\n");

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  if ((ret = atclient_atkeys_populate_from_string(&atkeys, ATKEYS)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_populate_from_string: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_atkeys_populate_from_string: %d\n", ret);

  if (!atclient_atkeys_is_pkam_public_key_base64_initialized(&atkeys)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_is_pkam_public_key_base64_initialized: %d\n", ret);
    goto exit;
  }

  if (!atclient_atkeys_is_pkam_private_key_base64_initialized(&atkeys)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_is_pkam_private_key_base64_initialized: %d\n",
                 ret);
    goto exit;
  }

  if (!atclient_atkeys_is_encrypt_public_key_base64_initialized(&atkeys)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_is_encrypt_public_key_base64_initialized: %d\n",
                 ret);
    goto exit;
  }

  if (!atclient_atkeys_is_encrypt_private_key_base64_initialized(&atkeys)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_is_encrypt_private_key_base64_initialized: %d\n",
                 ret);
    goto exit;
  }

  if (!atclient_atkeys_is_self_encryption_key_base64_initialized(&atkeys)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_is_self_encryption_key_base64_initialized: %d\n",
                 ret);
    goto exit;
  }

exit: {
  atclient_atkeys_free(&atkeys);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_atkeys_from_string End: %d\n", ret);
  return ret;
}
}