#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <atchops/aes_ctr.h>
#include <atchops/rsa.h>
#include <atclient/connection.h>
#include <atclient/atkeys_filereader.h>

#define ATSIGN "@jeremy_0"
#define ATKEYS_FILE_PATH "/Users/jeremytubongbanua/.atsign/keys/@jeremy_0_key.atKeys"
// #define ATKEYS_FILE_PATH "./@jeremy_0_key.atKeys"

static void *without_at_symbol(char *atsign, char *buf)
{
    int i = 0;
    while (atsign[i] != '\0')
    {
        buf[i] = atsign[i + 1];
        i++;
    }
    buf[i] = '\0';
    return buf;
}

int main()
{
    int ret = 1;

    // 1. initialize buffer to use throughout program

    size_t recvlen = 32768;
    unsigned char *recv = malloc(sizeof(unsigned char) * recvlen);
    size_t olen = 0;

    // 2. initialize atkeys, `atkeysfile` is now a struct that holds read atkeys


    const char *keyspath = ATKEYS_FILE_PATH;
    printf("Reading keys from \"%s\"...\n", keyspath);

    atclient_atkeysfile atkeysfile;
    atclient_atkeysfile_init(&atkeysfile);
    ret = atclient_atkeysfile_read(keyspath, &atkeysfile);
    if(ret != 0)
    {
        printf("Error reading keys from \"%s\"\n", keyspath);
        goto exit;
    }
    printf("Done reading...\n");

    // 3. connect to root and find secondary address

    // 3a. establish connection to root
    atclient_connection_ctx root_connection;
    atclient_connection_init(&root_connection);
    atclient_connection_connect(&root_connection, "root.atsign.org", 64);
    printf("Connected to root\n");

    // 3b. send atsign without @ symbol to root

    unsigned char *atsign_without_at = malloc(sizeof(unsigned char) * 100);
    memset(atsign_without_at, 0, 100);
    without_at_symbol(ATSIGN, atsign_without_at);
    strcat(atsign_without_at, "\r\n");
    size_t atsign_without_atlen = strlen(atsign_without_at);

    printf("Sending to root: \"%s\"\n", atsign_without_at);
    ret = atclient_connection_send(&root_connection, recv, recvlen, &olen, atsign_without_at, atsign_without_atlen);
    printf("Received from root: \"%.*s\"\n", (int) olen, recv);

    // 3c. parse secondary address

    const size_t secondary_len = 100;
    char *secondary_host = malloc(sizeof(char) * secondary_len);
    char *secondary_port = malloc(sizeof(char) * secondary_len);

    int i = 0, c;
    while ((c = recv[i]) != ':' && i < olen)
    {
        secondary_host[i] = c;
        i++;
    }
    secondary_host[i] = '\0';
    i++;
    int j = 0;
    while ((c = recv[i]) != '\0' && i < olen)
    {
        secondary_port[j] = c;
        i++;
        j++;
    }

    printf("secondary_host: %s\n", secondary_host);
    printf("secondary_port: %s\n", secondary_port);

    // 4. connect to secondary

    // 4a. establish secondary connection
    atclient_connection_ctx secondary_connection;
    atclient_connection_init(&secondary_connection);
    atclient_connection_connect(&secondary_connection, secondary_host, atoi(secondary_port));

    // 4b. send from request

    memset(recv, 0, recvlen);
    const unsigned char *from_command = malloc(sizeof(unsigned char) * 1024);
    memset(from_command, 0, 1024);
    strcat(from_command, "from:");
    strcat(from_command, ATSIGN);
    strcat(from_command, "\r\n");
    const size_t from_commandlen = strlen(from_command);
    atclient_connection_send(&secondary_connection, recv, recvlen, &olen, from_command, from_commandlen);
    printf("Sent: \"%.*s\" | Received: \"%.*s\"\n", (int) from_commandlen, from_command, (int) olen, recv);

    // 4c. parse from response, store data after the `data:` prefix
    const size_t from_responselen = 1024;
    unsigned char *from_response = malloc(sizeof(unsigned char) * from_responselen);
    memset(from_response, 0, from_responselen);

    int in = 0;
    j = 0;
    for (int i = 0; i < olen; i++)
    {
        char c = recv[i];
        if (in == 1)
        {
            from_response[j++] = c;
        }
        if (c == ':')
        {
            in = 1;
        }
    }

    printf("from_response: %.*s\n", (int) olen, (const char *) from_response);

    // get pkam private key

    atchops_rsa_privatekey pkamprivatekeystruct;

    const size_t pkamprivatekeylen = 10000;
    unsigned char *pkamprivatekey = malloc(sizeof(unsigned char) * pkamprivatekeylen);
    memset(pkamprivatekey, 0, pkamprivatekeylen);
    size_t pkamprivatekeyolen = 0;

    printf("self encryption key: \"%s\"\n", atkeysfile.self_encryption_key->key);
    printf("pkam private key (encrypted): \"%s\"\n", atkeysfile.aes_pkam_private_key->key);
    printf("pkam private key (encrypted) len: %lu\n", atkeysfile.aes_pkam_private_key->len);

    unsigned char *iv = malloc(sizeof(unsigned char) * 16);
    memset(iv, 0, 16);

    ret = atchops_aes_ctr_decrypt(atkeysfile.self_encryption_key->key, atkeysfile.self_encryption_key->len, 256, iv, 16, atkeysfile.aes_pkam_private_key->key, atkeysfile.aes_pkam_private_key->len, pkamprivatekey, pkamprivatekeylen, &pkamprivatekeyolen);
    printf("atchops_aes_ctr_decrypt: %d\n", ret);

    printf("pkam private key (decrypted): \"%s\"\n", pkamprivatekey);
    printf("pkam private key (decrypted) len: %lu\n", pkamprivatekeyolen);

    ret = atchops_rsakey_populate_privatekey(pkamprivatekey, pkamprivatekeyolen, &pkamprivatekeystruct);

    printf("n: %lu\n", pkamprivatekeystruct.n.len);
    printf("e: %lu\n", pkamprivatekeystruct.e.len);

    // sign from response

    const size_t signaturelen = 32768;
    unsigned char *signature = malloc(sizeof(unsigned char) * signaturelen);
    unsigned long signatureolen = 0;
    memset(signature, 0, signaturelen);
    atchops_rsa_sign(pkamprivatekeystruct, ATCHOPS_MD_SHA256, from_response, strlen(from_response), signature, signaturelen, &signatureolen);

    printf("signature: \"%.*s\"\n", (int) signatureolen, signature);

    // send pkam command

    size_t pkamcommandlen = 32768;
    unsigned char *pkamcommand = malloc(sizeof(unsigned char) * pkamcommandlen);
    memset(pkamcommand, 0, pkamcommandlen);

    strcat(pkamcommand, "pkam:");
    strcat(pkamcommand, signature);
    strcat(pkamcommand, "\r\n");

    printf("pkam command: \"%s\"\n", pkamcommand);

    ret = atclient_connection_send(&secondary_connection, recv, recvlen, &olen, pkamcommand, strlen(pkamcommand));

    printf("signature olen: %lu\n", signatureolen);
    printf("\"%.*s\"\n", (int) olen, recv);

    size_t commandlen = 32768;
    unsigned char *command = malloc(sizeof(unsigned char) * commandlen);
    memset(command, 0, commandlen);
    while (1)
    {
        fgets(command, commandlen, stdin);
        if (strcmp(command, "exit") == 0)
        {
            break;
        }
        atclient_connection_send(&secondary_connection, recv, recvlen, &olen, command, strlen(command));
        memset(command, 0, commandlen);
        printf("\nrecv: \"%.*s\"\n\n", olen, recv);
    }

    goto exit;

exit:
{
    return ret;
}
}