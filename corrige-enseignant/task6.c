#define _GNU_SOURCE
/* Usage : ./task6 <modulus_hex> <signature_hex> <sha256_hex_du_corps>
   Verifie : S^e mod n se termine par le hash SHA-256 du corps du certificat. */
#include <strings.h>
#include "common.h"
int main(int argc, char **argv)
{
    if (argc != 4) { printf("Usage: %s n_hex sig_hex hash_hex\n", argv[0]); return 1; }
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new(), *e = BN_new(), *S = BN_new(), *M = BN_new();
    BN_hex2bn(&n, argv[1]);
    BN_hex2bn(&S, argv[2]);
    BN_hex2bn(&e, "010001");
    BN_mod_exp(M, S, e, n, ctx);          /* M = S^e mod n  (= 0001FF..FF00 || DigestInfo || hash) */
    char *m_hex = BN_bn2hex(M);
    printBN("S^e mod n =", M);
    /* Comparaison insensible a la casse sur les 64 derniers caracteres */
    size_t len = strlen(m_hex);
    if (len >= 64 && strcasecmp(m_hex + len - 64, argv[3]) == 0)
        printf("Resultat : valid (le hash correspond)\n");
    else
        printf("Resultat : invalid\n");
    OPENSSL_free(m_hex);
    return 0;
}
