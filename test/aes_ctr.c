#include <stdio.h>
#include "at_client.h"
#include <string.h>
#include <stdlib.h>

int main()
{
  int retval;

  const char *aes_key = "1DPU9OP3CYvamnVBMwGgL7fm8yB1klAap0Uc5Z9R79g=";
  const char *plain_text = "i like to eat pizza";

  AtEncryptionKey key;
  InitialisationVector iv;

  key.size = strlen(aes_key);
  key.key = malloc(key.size);
  key.key = aes_key;

  iv.len = 16;
  iv.iv = malloc(iv.len);

  unsigned long dlen = 500;
  char cipher_text[dlen];
  unsigned long olen;

  retval = encrypt_string_aes_ctr(cipher_text, 500, &olen, plain_text, strlen(plain_text) + 1, &key, &iv);
  if (retval != 0)
  {
    printf("Encryption failed: %d\n", retval);
    return retval;
  }

  unsigned long dlen2 = 500;
  unsigned char decrypted[dlen2];
  unsigned long olen2;

  retval = decrypt_bytes_aes_ctr(decrypted, dlen2, &olen2, cipher_text, olen, &key, &iv);
  printf("Decrypted string: %s\n", (char *)decrypted);
  // if (retval != 0)
  // {
  //   printf("Decryption failed: %d\n", retval);
  //   return retval;
  // }

  int res = strcmp(decrypted, plain_text);
  printf("Result: %d\n", res);
  return 0;
}