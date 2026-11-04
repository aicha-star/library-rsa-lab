#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

/* Affiche un grand nombre en hexadecimal (majuscules) */
static inline void printBN(const char *msg, const BIGNUM *a)
{
    char *s = BN_bn2hex(a);
    printf("%s %s\n", msg, s);
    OPENSSL_free(s);
}

/* Convertit un texte ASCII en BIGNUM (octets -> nombre) */
static inline BIGNUM *text2bn(const char *text)
{
    return BN_bin2bn((const unsigned char *)text, (int)strlen(text), NULL);
}

/* Affiche un BIGNUM sous forme de texte ASCII */
static inline void printBNText(const char *msg, const BIGNUM *a)
{
    unsigned char buf[512];
    int len = BN_bn2bin(a, buf);
    buf[len] = '\0';
    printf("%s %s\n", msg, buf);
}
