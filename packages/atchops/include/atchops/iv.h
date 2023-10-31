
#ifndef ATCHOPS_IV_H
#define ATCHOPS_IV_H

int atchops_iv_generate(unsigned char *iv);
int atchops_iv_generate_base64(unsigned char *ivbase64, const unsigned long ivbase64len, unsigned long *ivbase64olen);

#endif