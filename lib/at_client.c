#include <stdio.h>
#include "at_client.h"
#include "mbedtls/md5.h"

int do_something(int a)
{
  return a + 1;
}

int do_md5()
{
  // Used as a temporary test for ensuring that mbedtls is linked correctly
  const unsigned char *in = (unsigned char *)("Hello, World!");
  unsigned char out[500];
  int retval = mbedtls_md5(in, 13, out);
  return retval;
}