#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "at_chops/rsa2048.h"
#include "at_chops/base64.h"

int main()
{
    int ret;
    const unsigned char *privatekeybase64 = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCy64Pzy9ZDdm6e96z3DmjektD7sKUo40Ax+1VD12Ksm3pUPTGDkM3Nf4Sp2ATcy6ZbCRHSEWtx7dPfC/H1p7yS9KOVLtAmx8aT0SNiT+WGsclshI/n/XP+jCjxrpYwf4ntgX2i6p6hlo/ZiW8i3+Ayyhw8uYuVMUyMHv70EaoTN0+N5QF9l74LkLYL7cXyfZayDPTZJxbLF2WEoQz4ZWJhgFk40EeBw03jiLg/T0hw1gbS0z97HhZs/QPtTaDR9EJYq27eZagRFZ6em7esrjjTpmGaTJmtZjEomV6o/EOtdvImRe1tViI22DWGAKi87BBGXR5Zr3xoRXPSypHLqLsNAgMBAAECggEAatzd//QEMmD/KzVU+m6B1kYsSde0nZo1kmTCBXYUenGWe8/cze7j7NQ4AVWDefiskHz3Rteeq/pXbEXvK0EXEVLKjWTbb/4sLcdg8ew0c+GmI4l9hhtMd4FxRwB2tdrHH7MSvgaR3oNVwaEjXtoGR2+Ns/tCUkaSqLIupsoSIc0Mj07Teq7SZvAe++oMyNgkyArR509oSG0GQFQp706VgLaUVrvtlMEXvtGB0pcn/y1Axz/l9VvYpojYp7MqSwVU6R4GWxjrn4JXCVQrh48VmuJS83i2oqFgbAXD2KyNjjkoW3Z26uhfJ0qgN2PeQgMYH06gNhfEYOAGTI8HgtfChQKBgQDc7xIYG0IchAX/0lds4yUXRRF9wEjZmsvaf6LZPEs97/z11cAbTp41zlppCqpGL0md/lTwFVwsmGuZNob999sGKi7A6mM2sBj+QiBoHACvl2e167O72eFYqyXtJwDH5XOA5JMHbc6GJpSeVE29UnIgq1czgp3DtapQRX3BOPMRYwKBgQDPUVjZJERK5N9ccs59gjyKiu6e60m42AVjpvaCWbqPSZXTEhGM8X9OJNsdZufRoMi6tYctXGthiB4HOoV1E5ACvJxgWpOTmbqqbBDA5pQPrJ4eRdigHjGnrAWdsJ+3smMbhk/6Ai00gmqwz8rv7eyGSY+dwOem/vPoJOrlRFFkzwKBgH+IhbJiscQSNgBZpFvXtwZ6uUEU6Tir0bccbJ3n3ysuyKAENnPM6yj2KFxwaqA/FcjdEpzQR7f6eEomHsCl/cnOOdTkuEbOWm8TLu/KEl9KD/UEzWjHufxcN3VxSVMa0ZT63SCxs0DfLnVDBukdmYHgRmMWqAlcaacSpigOvskvAoGADVikSp5OEzA2vOHbLzNCKH0XLX3iKhcmCatG9U9Hdk/7aDIilRs64dH3lSX5yIH8SiDDigUIGKhFnpuC2e2feL2hp4ZNN9ROswfv8Csn3vZy22oNrwkikzO8zNEBBzdhr/Tukx6uwFGhAq7t1pJPhrmXmEVB5HtHQmuV/5ptTvsCgYA5d5L3hO3+1Na4C6xj8luQXFhkSLNe0rwoe16OLjcyzcnhlb2KKA8rORGP28s1JcCL4Htasf0YzCkOJ/jR28GzX/0qvWu0hBSilV2mCAqwQ1fvZx0L4quJznkAhJPMZ+oag8o1LlQiJGgnhsIMbDLZApKh3NuYlTmdqo20FfkZkg==";
    size_t privatekeybase64len = strlen(privatekeybase64);
    
    RSA2048_PrivateKey *privatekeystruct;
    ret = atchops_rsa2048_privatekey_init(&privatekeystruct);
    if (ret != 0) goto end;

    ret = atchops_populate_privatekey(privatekeybase64, privatekeybase64len, privatekeystruct);
    if (ret != 0) goto end;
    // printf("ret: %d\n", ret);

    // // print n e d p q lengths
    // printf("n len: %lu\n", privatekeystruct->n->len);
    // printf("e len: %lu\n", privatekeystruct->e->len);
    // printf("d len: %lu\n", privatekeystruct->d->len);
    // printf("p len: %lu\n", privatekeystruct->p->len);
    // printf("q len: %lu\n", privatekeystruct->q->len);

    // print n e d p q
    // printf("n: ");
    // printx(privatekeystruct->n->n, privatekeystruct->n->len);
    // printf("e: ");
    // printx(privatekeystruct->e->e, privatekeystruct->e->len);
    // printf("d: ");
    // printx(privatekeystruct->d->d, privatekeystruct->d->len);
    // printf("p: ");
    // printx(privatekeystruct->p->p, privatekeystruct->p->len);
    // printf("q: ");
    // printx(privatekeystruct->q->q, privatekeystruct->q->len);

    ret = atchops_rsa2048_privatekey_free(privatekeystruct);
    if (ret != 0) goto end;

    goto end;
        
    end: {
        return ret;
    }
}