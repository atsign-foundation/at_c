
typedef struct atclient_atkeysfile_entry{
    size_t len;
    char* key;
} atclient_atkeysfile_entry;

typedef struct atclient_atkeysfile{
    atclient_atkeysfile_entry* aesPkamPublicKey;
    atclient_atkeysfile_entry* aesPkamPrivateKey;
    atclient_atkeysfile_entry* aesEncryptPublicKey;
    atclient_atkeysfile_entry* aesEncryptPrivateKey;
    atclient_atkeysfile_entry* selfEncryptionKey;
    atclient_atkeysfile_entry* atSign;
} atclient_atkeysfile;

void atclient_atkeysfile_init(atclient_atkeysfile** atkeysfile);
char* save(char* token, atclient_atkeysfile_entry* attribute);
void updateFileLine(char** line, char* type, atclient_atkeysfile_entry *attribute, int comma);
int atclient_atkeysfile_read(const char* path, const size_t pathlen, atclient_atkeysfile* atsign);
int atclient_atkeysfile_write(const char *path, const size_t len, atclient_atkeysfile *atsign);