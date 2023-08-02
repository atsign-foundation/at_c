#include <stdio.h>
#include <stdlib.h>
#include "at_client.h"

int main()
{

    int ret = 1;

    // initialize buffer to use throughout program

    size_t recvlen = 10000;
    unsigned char *recv = malloc(sizeof(unsigned char) * recvlen);
    size_t *olen = malloc(sizeof(size_t));

    // initialize atkeys

    const char *keyspath = "/Users/jeremytubongbanua/.atsign/keys/@jeremy_0_key.atKeys";

    atclient_atkeysfile atkeysfile;
    atclient_atkeysfile_init(&atkeysfile);
    atclient_atkeysfile_read(keyspath, &atkeysfile);

    // connect to root and find secondary address

    atclient_connection_ctx root_connection;
    atclient_connection_init(&root_connection);
    atclient_connection_connect(&root_connection, HOST, PORT);

    unsigned char *src = "jeremy_0\r\n";
    size_t srclen = strlen(src);

    atclient_connection_send(&root_connection, recv, recvlen, olen, src, srclen);

    printf("\"%.*s\"\n", (int)*olen, recv);

    const size_t secondary_len = 100;
    char *secondary_host = malloc(sizeof(char) * secondary_len);
    char *secondary_port = malloc(sizeof(char) * secondary_len);

    int i = 0, c;
    while((c = recv[i]) != ':' && i < *olen)
    {
        secondary_host[i] = c;
        i++;
    }
    secondary_host[i] = '\0';
    i++;
    int j = 0;
    while((c = recv[i]) != '\0' && i < *olen)
    {
        secondary_port[j] = c;
        i++;
        j++;
    }

    printf("secondary_host: %s\n", secondary_host);
    printf("secondary_port: %s\n", secondary_port);

    // connect to secondary

    atclient_connection_ctx secondary_connection;
    atclient_connection_init(&secondary_connection);
    atclient_connection_connect(&secondary_connection, secondary_host, atoi(secondary_port));

    // send from request

    memset(recv, 0, recvlen);
    const unsigned char *from_command = "from:@jeremy_0\r\n";
    const size_t from_command_len = strlen(from_command);
    atclient_connection_send(&secondary_connection, recv, recvlen, olen, from_command, from_command_len);

    const size_t from_response_len = 1024;
    unsigned char *from_response = malloc(sizeof(unsigned char) * from_response_len);
    memset(from_response, 0, from_response_len);

    int in = 0;
    j = 0;
    for(int i = 0; i < *olen; i++)
    {
        char c = recv[i];
        if(in == 1)
        {
            from_response[j++] = c;
        }
        if(c == ':')
        {
            in = 1;
        }
    }

    printf("from_response: %s\n", from_response);

    // get pkam private key

    atchops_rsa_privatekey pkamprivatekeystruct;

    const size_t pkamprivatekeylen = 10000;
    unsigned char *pkamprivatekey = malloc(sizeof(unsigned char) * pkamprivatekeylen);

    printf("self encryption key: \"%s\"\n", atkeysfile.self_encryption_key->key);
    printf("pkam private key (encrypted): \"%s\"\n", atkeysfile.aes_pkam_private_key->key);
    printf("pkam private key (encrypted) len: %lu\n", atkeysfile.aes_pkam_private_key->len);

    atchops_aes_ctr_decrypt(atkeysfile.self_encryption_key->key, AES_256, atkeysfile.aes_pkam_private_key->key, atkeysfile.aes_pkam_private_key->len, olen, pkamprivatekey, pkamprivatekeylen);

    printf("pkam private key (decrypted): \"%s\"\n", pkamprivatekey);
    printf("pkam private key (decrypted) len: %lu\n", *olen);

    atchops_rsa_populate_privatekey(pkamprivatekey, *olen, &pkamprivatekeystruct);

    printf("n: %lu\n", pkamprivatekeystruct.n_param.len);
    printf("e: %lu\n", pkamprivatekeystruct.e_param.len);

    // sign from response

    const size_t signaturelen = 32768;
    unsigned char *signature = malloc(sizeof(unsigned char) * signaturelen);
    memset(signature, 0, signaturelen);
    atchops_rsa_sign(pkamprivatekeystruct, ATCHOPS_MD_SHA256, &signature, &signaturelen, from_response, strlen(from_response));

    printf("signature: \"%s\"\n", signature);

    // send pkam command

    size_t pkamcommandlen = 32768;
    unsigned char *pkamcommand = malloc(sizeof(unsigned char) * pkamcommandlen);
    memset(pkamcommand, 0, pkamcommandlen);

    strcat(pkamcommand, "pkam:");
    strncat(pkamcommand, signature, signaturelen);
    strcat(pkamcommand, "\r\n");

    printf("pkam command: \"%s\"\n", pkamcommand);

    atclient_connection_send(&secondary_connection, recv, recvlen, olen, pkamcommand, strlen(pkamcommand));

    printf("\"%.*s\"\n", (int)*olen, recv);

    goto exit;

exit: {
    return ret;
}
}