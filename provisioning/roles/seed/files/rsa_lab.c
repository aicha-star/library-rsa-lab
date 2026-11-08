/* rsa_lab.c — RSA Lab Starter (SEED Labs)
 *
 * Compile : make rsa_lab
 * Run     : ./rsa_lab <task>   e.g.  ./rsa_lab 1
 *
 * Workflow for every task:
 *   1. Open ~/rsalab/params.txt  (cat ~/rsalab/params.txt)
 *   2. Copy YOUR unique hex values into the BN_hex2bn() calls below.
 *   3. Compile and run the task.
 *   4. Write the printed result to  ~/rsalab/answers/taskN.txt
 *   5. Run:  sudo rsa-verify <N>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>

/* ── Utility ──────────────────────────────────────────────────────────────── */

void printBN(char *msg, BIGNUM *a)
{
    char *s = BN_bn2hex(a);
    printf("%s %s\n", msg, s);
    OPENSSL_free(s);
}

/* ════════════════════════════════════════════════════════════════════════════
 * TASK 1 — Derive the Private Key
 *
 * Given p, q, e (from ~/rsalab/params.txt), compute d such that:
 *   e * d ≡ 1  (mod φ(n))    where  φ(n) = (p-1)(q-1)
 *
 * Write the printed d to ~/rsalab/answers/task1.txt
 * ════════════════════════════════════════════════════════════════════════════ */
void task1(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p   = BN_new();
    BIGNUM *q   = BN_new();
    BIGNUM *e   = BN_new();
    BIGNUM *p1  = BN_new();   /* p - 1 */
    BIGNUM *q1  = BN_new();   /* q - 1 */
    BIGNUM *phi = BN_new();   /* (p-1)(q-1) */
    BIGNUM *d   = BN_new();   /* private key — what we want */
    BIGNUM *one = BN_new();
    BN_one(one);

    /* ── TODO: replace with YOUR p and q from ~/rsalab/params.txt ── */
    BN_hex2bn(&p, "REPLACE_WITH_YOUR_P");
    BN_hex2bn(&q, "REPLACE_WITH_YOUR_Q");
    BN_hex2bn(&e, "010001");   /* e is always 65537 (0x10001) */
    /* ───────────────────────────────────────────────────────────── */

    /* Step 1: φ(n) = (p-1)(q-1) */
    BN_sub(p1, p, one);
    BN_sub(q1, q, one);
    BN_mul(phi, p1, q1, ctx);
    printBN("phi(n) = ", phi);

    /* Step 2: d = e^(-1) mod φ(n) */
    /* TODO: uncomment the line below */
    /* BN_mod_inverse(d, e, phi, ctx); */

    printBN("d = ", d);
    printf("\n→ Write the value of d to ~/rsalab/answers/task1.txt\n");
    printf("→ Then run: sudo rsa-verify 1\n");

    BN_free(p); BN_free(q); BN_free(e);
    BN_free(p1); BN_free(q1); BN_free(phi); BN_free(d); BN_free(one);
    BN_CTX_free(ctx);
}

/* ════════════════════════════════════════════════════════════════════════════
 * TASK 2 — Encrypt a Message
 *
 * Encrypt  M = "A top secret!"  using the public key (e, n).
 * M (hex) = 4120746f702073656372657421
 *
 *   C = M^e  mod n
 *
 * Write the printed C to ~/rsalab/answers/task2.txt
 * ════════════════════════════════════════════════════════════════════════════ */
void task2(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *M   = BN_new();
    BIGNUM *e   = BN_new();
    BIGNUM *n   = BN_new();
    BIGNUM *C   = BN_new();

    /* "A top secret!" as a hex string */
    BN_hex2bn(&M, "4120746f702073656372657421");
    BN_hex2bn(&e, "010001");

    /* ── TODO: replace with YOUR n from ~/rsalab/params.txt ── */
    BN_hex2bn(&n, "REPLACE_WITH_YOUR_N");
    /* ───────────────────────────────────────────────────────── */

    /* C = M^e mod n */
    /* TODO: uncomment the line below */
    /* BN_mod_exp(C, M, e, n, ctx); */

    printBN("C = ", C);
    printf("\n→ Write the value of C to ~/rsalab/answers/task2.txt\n");
    printf("→ Then run: sudo rsa-verify 2\n");

    BN_free(M); BN_free(e); BN_free(n); BN_free(C);
    BN_CTX_free(ctx);
}

/* ════════════════════════════════════════════════════════════════════════════
 * TASK 3 — Decrypt a Ciphertext
 *
 * Decrypt the ciphertext C (from ~/rsalab/params.txt) using (d, n).
 *
 *   M = C^d  mod n
 *
 * The decrypted plaintext M is YOUR flag for this task.
 * Write the printed M (hex) to ~/rsalab/answers/task3.txt
 * ════════════════════════════════════════════════════════════════════════════ */
void task3(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *C   = BN_new();
    BIGNUM *d   = BN_new();
    BIGNUM *n   = BN_new();
    BIGNUM *M   = BN_new();

    /* ── TODO: replace with YOUR C, d, n from ~/rsalab/params.txt ── */
    BN_hex2bn(&C, "REPLACE_WITH_YOUR_C");
    BN_hex2bn(&d, "REPLACE_WITH_YOUR_D");
    BN_hex2bn(&n, "REPLACE_WITH_YOUR_N");
    /* ───────────────────────────────────────────────────────────── */

    /* M = C^d mod n */
    /* TODO: uncomment the line below */
    /* BN_mod_exp(M, C, d, n, ctx); */

    printBN("M (hex) = ", M);

    /* Convert hex → ASCII to read the plaintext */
    char *hex_str = BN_bn2hex(M);
    printf("M (ASCII attempt) : ");
    for (int i = 0; hex_str[i] && hex_str[i+1]; i += 2) {
        char byte_str[3] = { hex_str[i], hex_str[i+1], '\0' };
        unsigned char byte = (unsigned char) strtol(byte_str, NULL, 16);
        if (byte >= 32 && byte < 127) putchar(byte);
        else printf("\\x%02X", byte);
    }
    printf("\n");
    OPENSSL_free(hex_str);

    printf("\n→ Write the hex value of M to ~/rsalab/answers/task3.txt\n");
    printf("→ Then run: sudo rsa-verify 3\n");

    BN_free(C); BN_free(d); BN_free(n); BN_free(M);
    BN_CTX_free(ctx);
}

/* ════════════════════════════════════════════════════════════════════════════
 * TASK 4 — Sign a Message
 *
 * Sign M = "I owe you $2000."  then also sign "I owe you $3000."
 * Compare the two signatures. (Sign the message directly, no hashing.)
 *
 *   S = M^d  mod n
 *
 * Write the signature for "$2000" to ~/rsalab/answers/task4.txt
 * ════════════════════════════════════════════════════════════════════════════ */
void task4(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *M   = BN_new();
    BIGNUM *Mb  = BN_new();
    BIGNUM *d   = BN_new();
    BIGNUM *n   = BN_new();
    BIGNUM *S   = BN_new();
    BIGNUM *Sb  = BN_new();

    /* Messages from ~/rsalab/params.txt */
    BN_hex2bn(&M,  "49206f776520796f75202432303030302e");  /* "I owe you $2000." */
    BN_hex2bn(&Mb, "49206f776520796f75202433303030302e");  /* "I owe you $3000." */

    /* ── TODO: replace with YOUR d and n from ~/rsalab/params.txt ── */
    BN_hex2bn(&d, "REPLACE_WITH_YOUR_D");
    BN_hex2bn(&n, "REPLACE_WITH_YOUR_N");
    /* ───────────────────────────────────────────────────────────── */

    /* S = M^d mod n */
    /* TODO: uncomment the two lines below */
    /* BN_mod_exp(S,  M,  d, n, ctx); */
    /* BN_mod_exp(Sb, Mb, d, n, ctx); */

    printBN("S  ($2000) = ", S);
    printBN("S' ($3000) = ", Sb);
    printf("\nObservation: even a 1-character difference produces a completely different signature.\n");

    printf("\n→ Write the value of S ($2000) to ~/rsalab/answers/task4.txt\n");
    printf("→ Then run: sudo rsa-verify 4\n");

    BN_free(M); BN_free(Mb); BN_free(d); BN_free(n); BN_free(S); BN_free(Sb);
    BN_CTX_free(ctx);
}

/* ════════════════════════════════════════════════════════════════════════════
 * TASK 5 — Verify a Signature (Alice's key — FIXED for all sandboxes)
 *
 * Verify that S is Alice's signature on M = "Launch a missile."
 *   Step 1: compute V = S^e mod n
 *   Step 2: compare V with M (hex of message)
 *   If V == M → VALID, else → INVALID
 *
 * Do it twice: once with the original S, once with the corrupted S' (last byte
 * changed from 0x2F to 0x3F).
 *
 * Write TWO lines to ~/rsalab/answers/task5.txt:
 *   Line 1: VALID  or  INVALID   (original S)
 *   Line 2: VALID  or  INVALID   (corrupted S')
 * ════════════════════════════════════════════════════════════════════════════ */
void task5(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *M   = BN_new();
    BIGNUM *e   = BN_new();
    BIGNUM *n   = BN_new();
    BIGNUM *S   = BN_new();
    BIGNUM *Sc  = BN_new();
    BIGNUM *V   = BN_new();

    /* "Launch a missile." */
    BN_hex2bn(&M, "4c61756e63682061206d697373696c652e");

    /* Alice's public key (fixed, from the SEED lab PDF) */
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");

    /* Signatures from ~/rsalab/params.txt */
    BN_hex2bn(&S,  "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
    BN_hex2bn(&Sc, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");

    /* ── Original signature ── */
    /* TODO: uncomment */
    /* BN_mod_exp(V, S, e, n, ctx); */
    printBN("V  (original S ) = ", V);
    printBN("M                = ", M);
    printf("Result (original) : %s\n\n",
           BN_cmp(V, M) == 0 ? "VALID — V == M ✓" : "INVALID — V != M");

    /* ── Corrupted signature ── */
    /* TODO: uncomment */
    /* BN_mod_exp(V, Sc, e, n, ctx); */
    printBN("V  (corrupted S') = ", V);
    printf("Result (corrupted): %s\n",
           BN_cmp(V, M) == 0 ? "VALID — V == M" : "INVALID — V != M ✗");

    printf("\n→ Write TWO lines (VALID/INVALID for original, then corrupted)"
           " to ~/rsalab/answers/task5.txt\n");
    printf("→ Then run: sudo rsa-verify 5\n");

    BN_free(M); BN_free(e); BN_free(n); BN_free(S); BN_free(Sc); BN_free(V);
    BN_CTX_free(ctx);
}

/* ════════════════════════════════════════════════════════════════════════════
 * TASK 6 — Manually Verify an X.509 Certificate
 *
 * Most of Task 6 uses openssl command-line tools (see ~/rsalab/params.txt
 * for the step-by-step commands). This C function performs the final RSA
 * verification step: decrypt the cert signature with the CA's public key
 * and compare it with the SHA-256 hash of the cert body.
 *
 * Steps (do BEFORE running this function):
 *   openssl x509 -in ~/rsalab/task6/c1.pem -noout -modulus   → extract n_CA
 *   openssl x509 -in ~/rsalab/task6/c1.pem -text -noout      → find e_CA
 *   openssl x509 -in ~/rsalab/task6/c0.pem -text -noout      → find signature S
 *   openssl asn1parse -i -in ~/rsalab/task6/c0.pem \
 *       -strparse 4 -out /tmp/c0_body.bin -noout              → cert body
 *   sha256sum /tmp/c0_body.bin                                → expected hash H
 *
 * Write the sha256sum output (the hash hex string) to ~/rsalab/answers/task6.txt
 * ════════════════════════════════════════════════════════════════════════════ */
void task6(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *S   = BN_new();   /* signature extracted from c0.pem  */
    BIGNUM *e   = BN_new();   /* CA public exponent               */
    BIGNUM *n   = BN_new();   /* CA modulus                       */
    BIGNUM *V   = BN_new();   /* decrypted value = S^e mod n      */

    printf("Task 6 — Before running this, extract S, e, n from the certificates.\n");
    printf("See ~/rsalab/params.txt → Task 6 section for the commands.\n\n");

    /* ── TODO: paste the values extracted from the certs ── */
    BN_hex2bn(&S, "REPLACE_WITH_SIGNATURE_FROM_C0");
    BN_hex2bn(&e, "010001");   /* most CA certs use e=65537 */
    BN_hex2bn(&n, "REPLACE_WITH_MODULUS_FROM_C1");
    /* ───────────────────────────────────────────────────── */

    /* V = S^e mod n  — decrypts the signature */
    /* TODO: uncomment */
    /* BN_mod_exp(V, S, e, n, ctx); */

    printBN("V (decrypted signature) = ", V);

    printf("\nCompare the last 64 hex chars of V with the sha256sum of /tmp/c0_body.bin.\n");
    printf("If they match → the certificate is VALID (the CA's signature is genuine).\n");
    printf("\n→ Write the sha256sum output to ~/rsalab/answers/task6.txt\n");
    printf("→ Then run: sudo rsa-verify 6\n");

    BN_free(S); BN_free(e); BN_free(n); BN_free(V);
    BN_CTX_free(ctx);
}

/* ── Entry point ──────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: ./rsa_lab <task>  (1-6)\n");
        printf("  1 — Derive private key\n");
        printf("  2 — Encrypt\n");
        printf("  3 — Decrypt\n");
        printf("  4 — Sign\n");
        printf("  5 — Verify signature\n");
        printf("  6 — X.509 certificate\n");
        printf("\nParameters: cat ~/rsalab/params.txt\n");
        return 1;
    }
    switch (atoi(argv[1])) {
        case 1: task1(); break;
        case 2: task2(); break;
        case 3: task3(); break;
        case 4: task4(); break;
        case 5: task5(); break;
        case 6: task6(); break;
        default:
            fprintf(stderr, "Unknown task: %s\n", argv[1]);
            return 1;
    }
    return 0;
}
