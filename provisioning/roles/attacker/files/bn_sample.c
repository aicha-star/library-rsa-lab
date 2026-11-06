/* bn_sample.c - exemple d'utilisation de la bibliotheque BIGNUM d'OpenSSL
   Compilation : gcc bn_sample.c -o bn_sample -lcrypto   (attention : -l minuscule L)  */
#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM *a)
{
    /* BN_bn2hex : chaine hexadecimale ; BN_bn2dec : chaine decimale */
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *res = BN_new();

    /* Initialisation de a, b, n */
    BN_generate_prime_ex(a, NBITS, 1, NULL, NULL, NULL);
    BN_dec2bn(&b, "273489463796838501848592769467194369268");
    BN_rand(n, NBITS, 0, 0);

    /* res = a * b */
    BN_mul(res, a, b, ctx);
    printBN("a * b = ", res);

    /* res = a^b mod n */
    BN_mod_exp(res, a, b, n, ctx);
    printBN("a^b mod n = ", res);

    return 0;
}
