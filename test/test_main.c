

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "at_chops/rsa2048.h"

int main()
{
    int ret = 0;

    // const unsigned char *privatekey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCAshHiDZwYHfXFxmquKyV+zAv9t+Pu0P9jPQdWO9Y1VW0P2B8K8TAcNcklwnkjx7h59LBtPjlOOK0OppTsoUN+jUhSJx9Y4TPWBD4jUxFVSVZprd0Hgho/1BwoNC7lQsvEPhMv9lsfVADBs2G5xtX6AahrjIU+FKMJwDBv3h3YqRFFyXi33nZm5gX7Zyi1XnWGEolIqNR/m3EKgeJyE+Hift3hFF/MFMe6TEGYODnLxAdbx3hLokLyDcNusmoCjzrtZiokbaChMcjTNGBaMY+LHzcSWTx7Alqg5fwCngzxQFvHWYusk9dEc7FLGkEXM5c9+gBDJ+ND6ovBpOl5ID/5AgMBAAECggEAVl6rj8lQfAMHYc8S44bDaEBqv8E9MJaE/0YC+YW48hw90Idb9gz+G8ChGT1V7YRpMzfbe8Vp0ixJQG7dvZ1Q3crVwYTODek9z6ETTsO9+z33x37Ouu4+zZ19tCGpY2WbuT1rxSGR8AmBZH4N1Q8zpdCdBmjNN2fEL5QTLdCkuTVqwxgZH0AEvOx1SMQN7234uYGGjQ6sEn6DOFlQv3N1GeJpdifJYDAlyG4GgZAp0B22Xr5BuKK0OoYbIERPhDgiDWoBJkP7rAwQfo7ZPk4IF22Eq5AC2gicBdcM54T1sMtSBLw2iTJDPcetZlERAplohl2Rf25vjow1ex19y/LX3QKBgQDpA+alDIaddwyXFG/B5EIR8jhgcQTj+Azm4c/1WUR5xIGpwkdYeoazD89O8nrVdoiF7/PFoY+62H24f1kwyiy0wWtw/eMafIc2oyZMYnyBYZ+4a6eCvU97hu7/lmzcCCzc+ar7Kktls+7CWjpN4eZKJKF/B914Pl9IhDGn0NpZ6wKBgQCNY+PKsTKbvcHw1JPkNxdY+0kdNDOO1SbAXY2VNDYpx0F/nqCz8mZJX1dz99hAQxlHUaqRay4fC6rXjkvPBf5dU588A/qG41hatCjIhbTpz5Mb6DX7FLYi7J4NJDM1o1jqrFRYot9sS/p1XSHRZLlxrQhkqLuOPztNKXgGH5aQqwKBgQCz5JMYMUdsIhDSQrDVHAf2Gu5zZk3EQiiTxxnp7PT0nUUNbjPulwmPDFGcPY+fZVeZL9sfZM+2DJVi7s5I4I0LL5hnL1s5g5JQGDzlE9PTfy70DgjQ4p6OW2oAYH3CkX0xTH84UTrMVdGqskX5AsHr08PqcoQE5QJi1cwQJymr6QKBgBdS4hHet0V/wQ10U80y1VQlZ8M8iEDIorLa++8gBMtRhlmCFmp40yzJYIjN2suHBhWAwE1qy9ntN8qFO7Yz++jzUXI6CcrUmA+mZo/llpl3V4IkBTudCAqs08nBLf1sK8/Si7tvasHXqsJPkbOUFQ9OhvLr7ryha6vn6lfAQDsvAoGAMF+pPaiZYEqWHmaIn5VBqJxIjJwWP0GlwY26gp9A1/QYmMxFdyWvlF2cMG1G9g+FEGDKMxUE+uMEj22nWcDNujKTSklXcHrzDaxi09exI38CmLSJwmDTDl+FJjTEqlUdu4+PQESF1TzwF6xACO0wXt+gmKLYOHApDUsMhYSMXJM=";

    // atchops_rsa2048_privatekey *privatekeystruct;
    // atchops_rsa2048_privatekey_init(&privatekeystruct);
    // atchops_rsa_populate_privatekey(privatekey, strlen(privatekey), privatekeystruct);

    // const size_t challengelen = 1000;
    // unsigned char *challenge = malloc(sizeof(unsigned char) * challengelen);

    // // get challenge from user input
    // scanf("%s", challenge);

    // printf("Challenge: \"%s\"\n", challenge);

    // size_t *signaturelen = malloc(sizeof(size_t));
    // unsigned char *signature = malloc(sizeof(unsigned char) * 5000);

    // ret = atchops_rsa_sign(privatekeystruct, ATCHOPS_MD_SHA256, &signature, signaturelen, challenge, strlen(challenge));
    // if(ret != 0) goto ret;

    // printf("Signature: %s\n", signature);

    goto ret;

    ret: {
        return ret;
    }
}