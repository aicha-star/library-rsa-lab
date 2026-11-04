#include "common.h"
int main(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new(), *q = BN_new(), *e = BN_new();
    BIGNUM *p1 = BN_new(), *q1 = BN_new(), *phi = BN_new(), *d = BN_new();
    BIGNUM *one = BN_new();

    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");
    BN_dec2bn(&one, "1");

    BN_sub(p1, p, one);          /* p-1 */
    BN_sub(q1, q, one);          /* q-1 */
    BN_mul(phi, p1, q1, ctx);    /* phi(n) = (p-1)(q-1) */
    BN_mod_inverse(d, e, phi, ctx);

    printBN("d =", d);
    return 0;
}
