#include <atclient/atclient.h>
#include <atclient/atkeys.h>
#include <atlogger/atlogger.h>

#define TAG "test_atkeys_write"

#define ATKEYS_8INCANTEATER                                                                                            \
  "{\"aesPkamPublicKey\":\"+Jp1VdQuMANVkktasZhnZ9UStUMW0JMnNNYAqXWhyMHDB1PQMpCMWDzAQwEkI8/UVCY33Xot6BUTvTjMqJj/"       \
  "qbwCTbth+HE32qL6dKSiub6gs+5zYhWPN7x4O+QSBxiNrXgWjvy3Gz74B9EnOZsOKUHnxRFkMpxGlL0T7zRoV/"                             \
  "P4IInXj9vBtLDV0EGawJEUiDhY7OLpTeYUxH0pGSlh8sjNhG1FW9DSA9eMruhLnWdMdZsJ0fdd3QGT2hReHOpcAxWcV7oFe3N5l7/"              \
  "IGEQi7NcoWSl8gIn+7gcqiRAaBueQKlgV3XmkcrgUeVifWtlJPMcB7HbBiYggPKUnus2k+f+"                                           \
  "bvNnvCBgjsfFCiyDPijTdL7S3lo9dO9bzG22c90yIDgIo78Zb7HSHVhFs4QGmtNLQSKCp/"                                             \
  "39RTopHPMh+zFnRsj+YFBknsHUYss+LsLql+UfA7kEb3L8PM4FRd/"                                                              \
  "XF5BfiI9S+ETvwF0DdJA8jo3F744YT2hMdG8r384keSxd7Y2Vm8S7UEtTU6Fo9w9Dn0Q==\",\"aesPkamPrivateKey\":\"+"                 \
  "Jp1UusFOA9WsWFlm5RlUYQO7EZu9uYjNMYKrHWxo8PMBUPlFpCUcjz2QwFTO7PsLUcL7Uc78Bciqxy0htHQq8QgEaZ8hTQjsrviaKufvY6DkrJPMSu" \
  "lMoZLYbIVcT2S7xwd186mAhaFQPdlaJULFTjXy2wxBqxGvp4lqHV7JcbjQb6Qr8n4p8LJnFCvu/"                                        \
  "1O+SB0k4zAQqtQygUOPygHwfqm0GhvFtezEdij4+l1m39ZEY8h/Pos1iivkQYzYMkLFhK/Fbh3GUhU55yJfVoA7/Qhdg88/"                    \
  "tPtxw477khFP+yfWkMdiX2WNOEyP1arNtd8FPE0jmeCkaITcZIF+YaY+f+"                                                         \
  "unr7tCEw3ltkMuhfAhSiCBbuLoKdAD978bS3d3XmBKFdo5OVVvnHRDGx3uTKTtNLrS6KJ8nNpX50mBrFFwFbPojiPJy0gzVFAmP2Qi8a3mC/"       \
  "wxxcjm7BNG7dOA+zWqzmiAMTECwLeDn7RU3cwhnZs7vkOjGQUZcm8jc1eUiZGQXhN8hvWasKdhx93ipmqmj5TTwIK6B2ivWeE9XX7Ep/C3an/"      \
  "SjkM5LDPZdVM/"                                                                                                      \
  "hsOL2wWaCud+"                                                                                                       \
  "sMrbuiouO2eogAr0sINp5thItlWw7Fu8Owpt3XlT5bpFjdRrJVKQ6EldLwqXITolOmqvwO70yDq4eMc977gwUlKTN80IetSN4k3SIlBK5/"         \
  "EzXMa3odO7OF0oRteVvAg7upaH1tvyOppsGLg+3+sOMkcREAralsN++DIHUK6peYRZ0K4IWICXQRw8Q+w7ZwacWdfvHQe9y1MZi5/"              \
  "lPfEfaKc6+9MupOSgNNQE38mVYQkf5IQAofe7YFxgZMqT/DiX7dwnTknBVlzjNzDP/QnPECFbJZFNpb3G/I7I1Vf/"                          \
  "7iRAUN0zcjFuK4WfEN98k7jLZySENV2+S+nZc6Jjq330gPomH9MTbfYZl8ooYCy+"                                                   \
  "sWfVi11l5ifHT50vGZL8mPYwHh1Mi272hHfv7sVbg67Wxe0HZQk5UElo233pxSj/XEEHTBeG2JqnuUWUd6hL1wZ77TPi7r641KjgB4H7/"          \
  "lD6l4SnheQJkSyjMrkd537ApY+uW1SVw4DYifTnplCyVmDSRpbhKfANvmczdzBX+2VGAICcSpMJW86p3m7YotEk/lRhxfC/gHY1sE/"             \
  "zptdE4rd16JjWPZFpWBAqceM6tz0pomM4K8B81u/"                                                                           \
  "8yAFWAWZmvbR4hXSUl4xGawvmIQGgfNUair5EGJcLJkHgA2B8Hz8bJJsxlRmWbxStu85d6heqi4HGxB1eNqVaS/A+Fe2NhNMAFGc1ZN/"           \
  "ROb0dlegcI2jukh61xS9/UkPi5E6grVcX2/F+oX9wR2/bTMrrY3goC9mKrQbRmuuVQkMGWXnCYfBik2DCX0/NT0jyRl/"                       \
  "uIIWc+A75RY8LOiHEFs+AuM0wyJVBF3rKy3UenOLxckkciE6BuPBFAqcAsgUZF+eEICyg9EUQpSHvGHKTRp2U/Wiw/"                         \
  "JEWAPEdey5pdhaWoKkx+HXotd5wPQ0l6wx5logDib8g3KMS8xvjqyyJXZs67zhXZ2Qjlbb1T2yUnUUDvi1KRQRtlQlSpQkzymxcF1I/"            \
  "Y1xAGpQB3MZ86rYNH0a97y6mkosRYYMAU0MiJQtHgGfKiNksxmf8nXaHNB8LDiPAB/"                                                 \
  "l08Kj1IkesqRB2wngCYPDVLmvoNPBNCHhbQUBn7035nAAJosGUdTy7pGUF4KLOMXkM4+imPAd1eQmiYMuYZsm7gxKi8IEmTCu+"                 \
  "WjJkRp5IlJiExeWOTXSxuDq+RO5yjEAKHltdIbJ4SBaxK97VsO5fcB76re+0czyM3ry939bGSmliFimHs+PkTcaAfCYk0+"                     \
  "mNskjkkyFjbHaObSrTflJManufdMKNhd/tMA39X00yaGAsSk7Up/"                                                               \
  "kOZrS1Sw+"                                                                                                          \
  "sOUvMFBXdBeLqnof03UkWSmj7seVMdcMFtzo3vAXvux7q8xb7dSFlN4x8mSXwpuBuJv5aCrXhAO8P7fwtpUm2ehXu808X364cfK7hHbAEW4x7W+"    \
  "8gOErRGtom+jWBQDw8rsZ/Bf9KTPco3wnGKb6PGBtFPSfSSVK+nZOnSXt3PL0TYxNh/"                                                \
  "hYAnBxeBEyAuT4B52mbD38zKy6bPTcIb2HMGYxo4s6FaHTsKJNUaKucKVKECeeH1K8cDvIHkRlIHofkKPIZyUD3N9TW2W/"                     \
  "SAoU\",\"aesEncryptPublicKey\":\"+"                                                                                 \
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
  "NvTQ964uojS8KYcHvI=\",\"@8incanteater\":\"ErES7LlWlIJAUEEwfvwqhjyi/NvTQ964uojS8KYcHvI=\"}"

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

  if ((ret = atclient_atkeys_write_to_path(&atkeys, ATKEYS_8INCANTEATER_1_FILE_PATH))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "failed to write to path\n");
    goto exit;
  }

  if ((ret = atclient_atkeys_populate_from_path(&atkeys1, ATKEYS_8INCANTEATER_1_FILE_PATH))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "failed to populate from path\n");
    goto exit;
  }

  if((ret = atclient_pkam_authenticate(&atclient1, "@8incanteater", &atkeys1, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "failed to pkam auth\n");
    goto exit;
  }

exit: { 
    atclient_atkeys_free(&atkeys);
    atclient_atkeys_free(&atkeys1);
    atclient_free(&atclient1);
    return ret; }
}