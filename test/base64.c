#include <stdio.h>
#include "at_client.h"
#include <string.h>

int main()
{
  const char *encoded = "1DPU9OP3CYvamnVBMwGgL7fm8yB1klAap0Uc5Z9R79g=";
  unsigned char *decoded;

  unsigned char *dst;
  unsigned long dlen;
  unsigned long *olen;

  // decode
  int retval = base64_decode(decoded, dlen, olen, (const unsigned char *)encoded, strlen(encoded));
  if (retval != 0)
  {
    printf("Decode failed\n");
    return retval;
  }

  const int dolen = *olen;

  // encode
  retval = base64_encode(dst, dlen, olen, (const unsigned char *)decoded, dolen);
  if (retval != 0)
  {
    printf("Encode failed\n");
    return retval;
  }

  // compare
  int res = strcmp((const char *)dst, encoded);
  return res;
}