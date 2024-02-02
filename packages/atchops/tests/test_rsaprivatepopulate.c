#include "atchops/rsa.h"
#include <stdio.h>
#include <string.h>
#include <stddef.h>

#define PRIVATE_KEY_BASE64 "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCy64Pzy9ZDdm6e96z3DmjektD7sKUo40Ax+1VD12Ksm3pUPTGDkM3Nf4Sp2ATcy6ZbCRHSEWtx7dPfC/H1p7yS9KOVLtAmx8aT0SNiT+WGsclshI/n/XP+jCjxrpYwf4ntgX2i6p6hlo/ZiW8i3+Ayyhw8uYuVMUyMHv70EaoTN0+N5QF9l74LkLYL7cXyfZayDPTZJxbLF2WEoQz4ZWJhgFk40EeBw03jiLg/T0hw1gbS0z97HhZs/QPtTaDR9EJYq27eZagRFZ6em7esrjjTpmGaTJmtZjEomV6o/EOtdvImRe1tViI22DWGAKi87BBGXR5Zr3xoRXPSypHLqLsNAgMBAAECggEAatzd//QEMmD/KzVU+m6B1kYsSde0nZo1kmTCBXYUenGWe8/cze7j7NQ4AVWDefiskHz3Rteeq/pXbEXvK0EXEVLKjWTbb/4sLcdg8ew0c+GmI4l9hhtMd4FxRwB2tdrHH7MSvgaR3oNVwaEjXtoGR2+Ns/tCUkaSqLIupsoSIc0Mj07Teq7SZvAe++oMyNgkyArR509oSG0GQFQp706VgLaUVrvtlMEXvtGB0pcn/y1Axz/l9VvYpojYp7MqSwVU6R4GWxjrn4JXCVQrh48VmuJS83i2oqFgbAXD2KyNjjkoW3Z26uhfJ0qgN2PeQgMYH06gNhfEYOAGTI8HgtfChQKBgQDc7xIYG0IchAX/0lds4yUXRRF9wEjZmsvaf6LZPEs97/z11cAbTp41zlppCqpGL0md/lTwFVwsmGuZNob999sGKi7A6mM2sBj+QiBoHACvl2e167O72eFYqyXtJwDH5XOA5JMHbc6GJpSeVE29UnIgq1czgp3DtapQRX3BOPMRYwKBgQDPUVjZJERK5N9ccs59gjyKiu6e60m42AVjpvaCWbqPSZXTEhGM8X9OJNsdZufRoMi6tYctXGthiB4HOoV1E5ACvJxgWpOTmbqqbBDA5pQPrJ4eRdigHjGnrAWdsJ+3smMbhk/6Ai00gmqwz8rv7eyGSY+dwOem/vPoJOrlRFFkzwKBgH+IhbJiscQSNgBZpFvXtwZ6uUEU6Tir0bccbJ3n3ysuyKAENnPM6yj2KFxwaqA/FcjdEpzQR7f6eEomHsCl/cnOOdTkuEbOWm8TLu/KEl9KD/UEzWjHufxcN3VxSVMa0ZT63SCxs0DfLnVDBukdmYHgRmMWqAlcaacSpigOvskvAoGADVikSp5OEzA2vOHbLzNCKH0XLX3iKhcmCatG9U9Hdk/7aDIilRs64dH3lSX5yIH8SiDDigUIGKhFnpuC2e2feL2hp4ZNN9ROswfv8Csn3vZy22oNrwkikzO8zNEBBzdhr/Tukx6uwFGhAq7t1pJPhrmXmEVB5HtHQmuV/5ptTvsCgYA5d5L3hO3+1Na4C6xj8luQXFhkSLNe0rwoe16OLjcyzcnhlb2KKA8rORGP28s1JcCL4Htasf0YzCkOJ/jR28GzX/0qvWu0hBSilV2mCAqwQ1fvZx0L4quJznkAhJPMZ+oag8o1LlQiJGgnhsIMbDLZApKh3NuYlTmdqo20FfkZkg=="

int main()
{
    int ret = 1;

    const char *privatekeybase64 = PRIVATE_KEY_BASE64;
    const unsigned long privatekeybase64len = strlen(PRIVATE_KEY_BASE64);

    atchops_rsakey_privatekey privatekey;
    atchops_rsakey_privatekey_init(&privatekey);

    ret = atchops_rsakey_populate_privatekey(&privatekey, privatekeybase64, privatekeybase64len);
    if (ret != 0)
    {
        printf("atchops_rsakey_populate_privatekey (failed): %d\n", ret);
        goto exit;
    }

    if (privatekey.n.len <= 0)
    {
        ret = 1;
        goto exit;
    }
    printf("n:\t");
    for (int i = 0; i < privatekey.n.len; i++)
    {
        printf("%02x ", privatekey.n.value[i]);
    }
    printf("\n");

    if (privatekey.e.len <= 0)
    {
        ret = 1;
        goto exit;
    }
    printf("e:\t");
    for (int i = 0; i < privatekey.e.len; i++)
    {
        printf("%02x ", privatekey.e.value[i]);
    }
    printf("\n");

    if (privatekey.d.len <= 0)
    {
        ret = 1;
        goto exit;
    }
    printf("d:\t");
    for (int i = 0; i < privatekey.d.len; i++)
    {
        printf("%02x ", privatekey.d.value[i]);
    }
    printf("\n");

    if (privatekey.p.len <= 0)
    {
        ret = 1;
        goto exit;
    }
    printf("p:\t");
    for (int i = 0; i < privatekey.p.len; i++)
    {
        printf("%02x ", privatekey.p.value[i]);
    }
    printf("\n");

    if (privatekey.q.len <= 0)
    {
        ret = 1;
        goto exit;
    }
    printf("q:\t");
    for (int i = 0; i < privatekey.q.len; i++)
    {
        printf("%02x ", privatekey.q.value[i]);
    }
    printf("\n");

    goto exit;
exit:
{
    return ret;
}
}