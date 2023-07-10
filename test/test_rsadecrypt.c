#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "at_chops/rsa.h"

#define PRIVATEKEYBASE64 "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCDc/uZ5+pmDYY1A+IQdiKeZNhRxttbYCv1aLksIP+5Fk1GJAnKlsBBum+Tp8CjXCHk22nWSM8YesiKRQFVEQi1OS6Whs449U1oLkVSDzqRAnZaT5nI9oIh+u2jsa/7KfYOIqqN1h17GOZopsw73RZJnvISYLaarxtFABIPQ+gbdFfWySEaRXUW89sfg4QO7MzEd8ZwK8KLf4E9xuCMshP90p7bMAdLn98T04rVvP78W60lMXwzospBjwT6HZxCNMSfdFEmVwynivCr/QY2abeY1jkSFRxqYqJJYgsb1rydjN4hRp9eYRIJmT4nXJW71ByZc/wOiS/7gou/vr9jVGypAgMBAAECggEAFTkjlQypfoKOeX6///Ji0nnrpwBZKB6V2lBnHSXSw7pDDaEB57CBJ9uG6ir6YiWc30tBgjRNI2GngRN1DJvscP3jdLAdGXsZXUmjLYWB6imgnCIf7R9HkV7nATfN9tomfM/CA5ZfOiGiCaFsdfnTAF3mLWtp7/13hKNnRwmqrsvUzJrqzNFqZty7YRtkm2pxxetsycq2WGKkOjwEyJdDZSI5XbQyAzuu878WEi+Th4EI2MV21jAuP7WEAZC/tBSLLFSZgiHnMaMnQ9ogWnxCbdIJfWPBiK54kcDRN2o/I7iXAVD5W3oadEYgEn6SBuG4ZQtqTM8cFSofxrGuVfyQgQKBgQDZnwC501pza1Jm4/H/lvB67kup9EFwQFbCTjJKuHd1NuV1O0LcHER5wfgLOac2My7kXva8gsheLHdi9ciPNtqhHrJVpl4QyXYd6h7m3FImGCfd1xwqrfWPPA0aMM8e8QZGANrX7Z20xzEzSgMu/0trg7WS4P7ChO2VHXviEn4mMQKBgQCaorqBjvajf9wkwh5V06HmpaI8Ji7JvRD44l1G0eGJgCrSYbvFUQr4KzfaQltfwaMJnqoNVrqey9yhPaFacjI2QbBM3zECjmasy9m20VS70QsV7XKq7tKco8M+YfUwzOFOKrpxUm/AG7SoTmTIwsg+VkZNTPWQB74kwKmRkkj3+QKBgGxnXi8y702rWmLSjYvqHmS+K4a/m5FVG2KzHS5HcYo8DFU3bfjDRAD69Jpy366KFIPCIlqJM1JmCBqNoJhmlMXJysALnbPzBxmjtDz/5xP+2G0TaH6CJV5yZXx0b9hT6/IXHuyM+xBAYWvRJIDWvzURaPN/jKhNGyQ6ial12M0hAoGAdFadbr+6O0QEwfrxi6zPD5HpvssTRF/kFvtnJdLdle9BSEqTVF4mnJMXUDPAPwiVurUORz7K5JGHih+t9zgXIs7E7vC0FLJB+RrczzgqQauCZZrhPEy1U3e5eoOETpS1pXNsFbnprWSqxD1GgexZbtzFw350+Ul5+nigmo6uKzECgYBuZVdUFt0XpIWZ8hugSMhCxHhNZMrOAIbQp0eXMs3U25zd8RpUx4qXK39Sp+X6Ifs8jCfSjThhI5Ip0L0/vz5IyBrTUwbaCJVmLZU69UHNm2g8I6FoMQx3w7/ILo2mlfhd9QwTEzyT9dsdXq23HJeMkWzoVLieTHySu20n+PxXbQ=="

#define CIPHERTEXTBASE64 "QVZmFo7iE0qr8QbF9pwBM9/AwPezOe+zzzSl2J/CKkyjwc8RsU4MCi5Mr/L09S+t8j3a092pax6OglKeS49xGlfmBWoFoCStb98T+ifwlYFnnKiSehDqUh3tvtMDgmmiUVxbCKR5CTsQYndGVeQaKhCLzl2Pv5OOutP9Uon2C42NQK3nOlEV7vMIlzY/HyiSWU+0sUkWLG01lChjI4m8cdfLjM/c+vxJe8qOFJKewtAuTdg63Q0tR0qZ/O7EHJ1JMKdc/fPFpKz8whZAevhx3UIIzilI7xBluMYKEi4jDH/p4UARTc1LALGE/7eQ5mVdPsdPU/h4Jd5jWbkXWOA1nA=="

int main()
{
    int ret = 1;
    atchops_rsa2048_privatekey privatekeystruct;

    const size_t privatekeylen = strlen(PRIVATEKEYBASE64);
    const char *privatekey = PRIVATEKEYBASE64;

    const size_t ciphertextlen = strlen(CIPHERTEXTBASE64);
    const char *ciphertext = CIPHERTEXTBASE64;

    ret = atchops_rsa_populate_privatekey(privatekey, privatekeylen, &privatekeystruct);
    if(ret != 0)
        goto ret;

    char *plaintext = malloc(sizeof(unsigned char) * 5000);
    size_t *plaintextlen = malloc(sizeof(size_t));
    plaintext[*plaintextlen] = '\0'; // add null terminator, not necessary but it's okay

    ret = atchops_rsa_decrypt(privatekeystruct, ciphertext, ciphertextlen, &plaintext, plaintextlen);
    if(ret != 0)
        goto ret;

    // printf("plaintext: %s\n", plaintext);

    goto ret;

    ret: {
        return ret;
    }
}