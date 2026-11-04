#include "common.h"
static void sign(const char *msg, BIGNUM *d, BIGNUM *n, BN_CTX *ctx)
{
    BIGNUM *M = text2bn(msg), *S = BN_new();
    BN_mod_exp(S, M, d, n, ctx);   /* S = M^d mod n */
    printf("Message : %s\n", msg);
    printBN("S =", S);
}
int main(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new(), *d = BN_new();

    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    sign("I owe you $2000.", d, n, ctx);
    sign("I owe you $3000.", d, n, ctx);
    return 0;
}
