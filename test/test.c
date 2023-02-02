#include <stdio.h>
#include "at_client.h"

int main()
{
  printf("do_something:\t");
  printf(do_something(0) == 1 ? "PASS" : "FAIL");
  printf("\ndo_md5:\t");
  printf(do_md5() == 0 ? "PASS" : "FAIL");
  printf("\n");
  return 0;
}