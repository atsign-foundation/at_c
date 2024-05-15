#include "atchops/base64.h"
#include "atlogger/atlogger.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "test_base64"

// #define SRC_STRING "1DPU9OP3CYvamnVBMwGgL7fm8yB1klAap0Uc5Z9R79g="
#define SRC_STRING                                                                                                     \
  "yY9vOA8bbzyADNGOxFPdT6bGxySKmNd6usP5/"                                                                              \
  "LBufYo4oBJt4ntFCecxESIjZuCqX5ALV8YNujt9V7s5f5QdfEuLAX7pa8apJp23BwDP7j7e3qz5NVbGocGpChdQBX8ni2aoMOrKZyMjtls8G4cCG0b" \
  "7QIDSSEk1sv6fH50lToBZ/4fNSKonHZ0JvsbkE/1vg7VrcQ8tqwZJNfSfZaoP6zQpROknfjgRyYGJfy/Rao/"                               \
  "vJRoSicH5sOcXKg+41BUa0Uc8Iqz4wJrzkI+uz7sJUIBZ3b5ZLdHXmk5z5cee3Suh58+"                                               \
  "yE2p29hcF2Dzpygx2KdT8ValH2PdB9u4B4DzTikQBKDqP9mDPPR4K/"                                                             \
  "TGBvI90vsX2vZo2LSRpx2NC7aZxvx5RXdjjfFNffYCAwX2n0SKvyUBhXmYu2zdgx99MDsfwp/7LG7Noy5q/InfDb/"                          \
  "dQdvJAGdWcsnqdHIANVen1+"                                                                                            \
  "cQFKPk79MMcSsBQI6WAYYZAI2ctWju6y2SN5MhSOAdWehWRS8P3fv4j30KqAHKnXiNzqfTb8135u2hsDCCP6H6fdf3IKQmqVasFUs2AgUcdIVEQxOf" \
  "RNu5URemIk7imJ0pGP/P47gCb2TwThObE7XCPcNfgyY51cRgKQc5vQXyqJw4gKE49QmuDIsMyoSdroYhnn/"                                \
  "1nhfO7AxG74+3y76CHvhcqsNT5LK1Nr9ecdAeKTEqp4SvVcxxA7CJcjbjv6GuSAQovv04uxiOGjMFoWeU+CaVi0jNAYa+bE/"                   \
  "TBpdL7Meg8EStK8p3Sb2AQc46LHVHEW7OMDT9JG2jgtL3wjjYbhm+o7W+yEkGZL5p274749LFMCeHafW5qKougjUuR3g1AUzW9TeL84J52/"        \
  "ZaqHPOpk0+7uhVzUhnNvKofVypyV3bGnGyqUeAx5uRbBjrFJdor+cZ6NmsnOHyVlzXHOsFItmB5STth+zSTyZ/"                             \
  "53SZkTP9NoTiZMl3iuJAffzRXjmvouA6JstxdXYbAfGNVRz+VIvHPlqYbrS/SopijypqEZ1Hnju3y0HexsUc4xilDXvy+XaTUibAbi6hHy8QfRd1/"  \
  "KU6DgOVNjlOsvELjsa3f+hLE9Zu+QOrC42vpzR3BVC+rh2X5RXEn+"                                                              \
  "aY5i4oejYH2HiRQo00gUfrffL79NCpfvn10NMawlWQxRiVLbJ0qi6TN4hsKr2HAzTmuh1lN+tC4VciexHfy87Bs2l8/"                        \
  "oXCFzAT6TdpTXBaTWXzmXBy8YaQwXxMb3xNV+LaEaYy1AlDTypPZdkkIkpJkG9Tkbw4JXt7RKQ0oS/"                                     \
  "sFp2MkHKjkbJjHaFm+Fi55uMKMht3200PWwTQSHS/GupZhTIlXm86HbQHUUAbxe/"                                                   \
  "Dgpup6NQ96TMgYOi3t+FG78TY7QXJMejkAHNpS57deB0EmeFhbJRCgSEc0amwjEk7AIKYbg0J+j7lYcJvB/"                                \
  "uiUj2GSfBBU75iudTrvMJ60VnbQF055piUwlRlYc9TUf/43Oa7wszCq+oPI/Kjaho/GO4cO2mnc92sgw7wR/+hv/8Bd8/"                      \
  "j2gSssraQgepEkjVL1HKvrxil+OuJo5hy+bM88CjB8Q04to0gkLApPbirL6w2ZlOCn2LRrGuSkajl0QgviL95GEM8zNqZscPkBiV2yVUw403G+T5+"  \
  "3ERtbZ1kJrgKuTSnjPTt8bFMYEdJVQ1+Z1mtnWX4AxR/"                                                                       \
  "j6vC2H+DSuGfOyaH1vociT+nNeDtq3axck5sf8h443Yw9jSbMVjyE+HkZWvxzyD4MjSvnEVp1Sso0/eDKFyTVRPn4dsw09+ltOm0F8CGeH/"        \
  "FAoXLF8CGrEoFe//"                                                                                                   \
  "Tlk8b+PbW1FVIph42cnQXpwHLrlsSAGjHmg4mWK8QXcRLjykdYpH4sX+Wd1wxHvlKAWEDBlZB1NSHkTgrprovr7xxqUCA3vRkRRD1RzG+Q6ikb0/"   \
  "1PmBPlOW3v8Dwr1BGuu9a7fruisMrl88LuPVXgxBpjANa4aq3nVmcZ2WMduDEgH1bWWqaciT3IkYm/"                                     \
  "97QMIQRyFTfQ5tWY9ZcsP9DKluqM222whKBsLz3sL4F9gL5L2HECz3y5EGX4J5QSrU4y4Y8HE5KNz9SqwlTdYSj87dm/"                       \
  "e5l8mVNVR8gMFtzbd9MqNaCoNPm8GfWvx+QIctKNR3zEjxqWrMkiyezZU0PxC98eeHIkef0s1OPcDLMRiwIl"
#define DST_SIZE 4096

#define SMALL_TEXT "hi"

#define MEDIUM_TEXT "Hello, World!!! 123 123 456 \n ?? << >>"

#define LONG_TEXT                                                                                                      \
  "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Praesent porttitor ligula eget sapien elementum aliquam. " \
  "Cras commodo ullamcorper velit, cursus pulvinar lorem euismod a. Mauris dapibus turpis elit, ac porta justo "       \
  "elementum in. In hac habitasse platea dictumst. Vivamus rutrum metus nec erat consequat, sed porta metus blandit. " \
  "Quisque pellentesque sapien quis odio vehicula tempus. Mauris vitae odio convallis, ullamcorper dui eget, iaculis " \
  "enim. Donec malesuada dolor massa, congue maximus nulla fermentum id. Maecenas eget nibh finibus diam fringilla "   \
  "posuere. Morbi non arcu ac neque tristique euismod at ac lectus.Vestibulum dolor libero, pharetra eget eleifend "   \
  "semper, lacinia sit amet sem. Cras tincidunt massa id mattis aliquet. Aenean porttitor a quam vitae pharetra. "     \
  "Vestibulum dui enim, vulputate vel pulvinar sit amet, fermentum vestibulum diam. Vestibulum condimentum quam "      \
  "purus, efficitur ultrices nulla blandit sed. Etiam aliquam eros felis, luctus malesuada ligula vestibulum vel. "    \
  "Nulla pellentesque ultricies urna, a imperdiet sapien. Mauris vel sagittis lectus. Maecenas ultricies, nulla id "   \
  "dapibus congue, erat nisl ornare nisl, ut condimentum enim est pulvinar odio. Sed posuere lorem vel semper "        \
  "dignissim. Sed in condimentum felis. Duis id commodo velit, id tempor odio. Donec eros libero, ultricies non "      \
  "lobortis eget, sollicitudin ut justo. Donec sollicitudin ante quam, vestibulum commodo massa suscipit nec. Nam "    \
  "accumsan eget arcu non ornare.Ut nec tincidunt diam. Sed sed est eget erat facilisis gravida. Suspendisse vitae "   \
  "odio vel eros aliquet porta. Nulla ut quam luctus, iaculis felis non, tristique arcu. Praesent hendrerit felis "

static int calculate_buffer_size_helper(const char *src, const size_t srclen);
static int test_2_calculate_small_buffer();
static int test_3_calculate_medium_buffer();
static int test_4_calculate_large_buffer();

int main() {
  int retval;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  const char *src = SRC_STRING;
  const size_t srclen = strlen(src);
  printf("src (%lu): %s\n", srclen, src);

  const size_t dstsize = DST_SIZE;
  unsigned char dst[dstsize];
  memset(dst, 0, sizeof(unsigned char) * dstsize);
  size_t dstlen = 0;

  const size_t dst2size = DST_SIZE;
  unsigned char dst2[dst2size];
  memset(dst2, 0, sizeof(unsigned char) * dst2size);
  size_t dst2len = 0;

  retval = atchops_base64_decode((unsigned char *)src, srclen, dst, dstsize, &dstlen);
  if (retval) {
    printf("atchops_base64_decode (failed): %d\n", retval);
    goto ret;
  }
  printf("base64 decoded (%lu):", dstlen);
  for (int i = 0; i < dstlen; i++) {
    printf("%02x ", dst[i]);
  }
  printf("\n");

  retval = atchops_base64_encode(dst, dstlen, dst2, dst2size, &dst2len);
  if (retval) {
    printf("atchops_base64_encode (failed): %d\n", retval);
    goto ret;
  }
  printf("base64 encoded (%lu): %s\n", (dst2len), dst2);

  if ((retval = test_2_calculate_small_buffer()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_2_calculate_small_buffer failed: %d\n", retval);
    goto ret;
  }

  if ((retval = test_3_calculate_medium_buffer()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_3_calculate_medium_buffer failed: %d\n", retval);
    goto ret;
  }

  if ((retval = test_4_calculate_large_buffer()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_4_calculate_large_buffer failed: %d\n", retval);
    goto ret;
  }

  goto ret;

ret: { return retval; }
}

static int calculate_buffer_size_helper(const char *src, const size_t srclen) {
  int ret = 1;

  const size_t dstsize = atchops_base64_encoded_size(srclen);
  unsigned char dst[dstsize];
  memset(dst, 0, sizeof(unsigned char) * dstsize);
  size_t dstolen = 0;

  // log dstsize
  atlogger_log("calculate_buffer_size_helper", ATLOGGER_LOGGING_LEVEL_INFO, "dstsize: %lu\n", dstsize);

  size_t dst2size;
  unsigned char *dst2 = NULL;
  size_t dst2len = 0;

  // test if dstsize was a sufficient size
  ret = atchops_base64_encode((unsigned char *)src, srclen, dst, dstsize, &dstolen);
  if (ret != 0) {
    atlogger_log("test_2_calculate_small_buffer", ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode failed: %d\n",
                 ret);
    goto exit;
  }

  // if we reached this point, it means that dstsize was a sufficient buffer size

  dst2size = atchops_base64_decoded_size(dstolen);
  dst2 = (unsigned char *)malloc(dst2size);
  if (dst2 == NULL) {
    atlogger_log("test_2_calculate_small_buffer", ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    ret = 1;
    goto exit;
  }
  
  // log dst2size
  atlogger_log("calculate_buffer_size_helper", ATLOGGER_LOGGING_LEVEL_INFO, "dst2size: %lu\n", dst2size);

  ret = atchops_base64_decode(dst, dstolen, dst2, dst2size, &dst2len);
  if (ret != 0) {
    atlogger_log("test_2_calculate_small_buffer", ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode failed: %d\n",
                 ret);
    goto exit;
  }

  // if we reached this point, it means that dst2size was a sufficient buffer size

  ret = 0;
  goto exit;
exit: {
  free(dst2);
  return ret;
}
}

static int test_2_calculate_small_buffer() {
  int ret = 1;

  const char *src = SMALL_TEXT;
  const size_t srclen = strlen(src);

  if ((ret = calculate_buffer_size_helper(src, srclen)) != 0) {
    atlogger_log("test_2_calculate_small_buffer", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "calculate_buffer_size_helper failed: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int test_3_calculate_medium_buffer() {
  int ret = 1;

  const char *src = MEDIUM_TEXT;
  const size_t srclen = strlen(src);

  if ((ret = calculate_buffer_size_helper(src, srclen)) != 0) {
    atlogger_log("test_3_calculate_medium_buffer", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "calculate_buffer_size_helper failed: %d\n", ret);
    goto exit;
  }
  ret = 0;
  goto exit;

exit: { return ret; }
}

static int test_4_calculate_large_buffer() {
  int ret = 1;
  const char *src = LONG_TEXT;
  const size_t srclen = strlen(src);
  if ((ret = calculate_buffer_size_helper(src, srclen)) != 0) {
    atlogger_log("test_4_calculate_large_buffer", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "calculate_buffer_size_helper failed: %d\n", ret);
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}
