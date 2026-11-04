#include "common.h"
int main(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new(), *e = BN_new(), *C = BN_new();
    BIGNUM *M = text2bn("A top secret!");

    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e, "010001");

    BN_mod_exp(C, M, e, n, ctx);   /* C = M^e mod n */
    printBN("C =", C);
    return 0;
}
