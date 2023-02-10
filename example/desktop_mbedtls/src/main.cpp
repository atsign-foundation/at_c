#include "at_client.h"
#include <iostream>

int main()
{
  u_char key[32];
  at_client::make_aes_key(key);
  std::cout << "key: " << (u_char *)(key) << std::endl;
  return 0;
}