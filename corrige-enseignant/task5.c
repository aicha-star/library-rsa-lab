#include "common.h"
static void verify(const char *label, const char *S_hex, BIGNUM *e, BIGNUM *n, BN_CTX *ctx)
{
    BIGNUM *S = BN_new(), *M2 = BN_new();
    BIGNUM *M = text2bn("Launch a missile.");

    BN_hex2bn(&S, S_hex);
    BN_mod_exp(M2, S, e, n, ctx);  /* M' = S^e mod n */
    printf("--- %s ---\n", label);
    printBN("M' =", M2);
    if (BN_cmp(M, M2) == 0)
        printf("Resultat : valid\n");
    else
        printf("Resultat : invalid\n");
}
int main(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new(), *e = BN_new();

    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    BN_hex2bn(&e, "010001");

    verify("Signature d'origine (...2F)",
           "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F", e, n, ctx);
    verify("Signature modifiee (...3F)",
           "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F", e, n, ctx);
    return 0;
}
