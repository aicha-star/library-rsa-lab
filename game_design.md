# RSA Public-Key Encryption & Signature Lab (game design)

Based on the SEED Labs *RSA Public-Key Encryption and Signature Lab* (CC BY-NC-SA 4.0).
See `ATTRIBUTION.txt`.

**Audience :** étudiants en sécurité système / cryptographie (~30 par session).
**Durée :** ~120 minutes.
**Score :** 200 points plateforme = 20/20 (×10). Pénalités indice : 5-20 points = −0,5 à −2/20.

## Objectifs pédagogiques
* Calculer la clé privée RSA avec `BN_mod_inverse` (C + OpenSSL BigNum).
* Chiffrer et déchiffrer des messages avec `BN_mod_exp`.
* Générer et vérifier une signature numérique RSA.
* Vérifier manuellement un certificat X.509.

## Niveaux
| Niveau | Score | Flag variant | Indices | Questions |
|---|---|---|---|---|
| Task 0 — Setup | 10 | Oui (`flag_t0_setup`) | 5, 10 | Q0 |
| Task 1 — Clé privée (d) | 30 | Oui (`flag_t1_privkey`) | 5, 10, 15 | Q1, Q2 |
| Task 2 — Chiffrement | 20 | Oui (`flag_t2_encrypt`) | 5, 10 | Q3 |
| Task 3 — Déchiffrement | 30 | Oui (`flag_t3_decrypt`) | 5, 10 | Q4, Q5 |
| Task 4 — Signature | 30 | Oui (`flag_t4_sign`) | 5, 10 | Q6, Q7 |
| Task 5 — Vérification | 30 | Oui (`flag_t5_verify`) | 5, 10 | Q8, Q9 |
| Task 6 — X.509 | 20 | Oui (`flag_t6_cert`) | 5, 10, 20 | Q10, Q11 |
| Quiz (6 × 5) | 30 | Non | — | — |

## Mécanisme anti-triche

### Paramètres uniques par sandbox (Tasks 1-4)
`gen_params.py` génère aléatoirement p et q (128 bits, Miller-Rabin 20 tours) pour chaque sandbox.
Ainsi n, d, C2, S4 sont tous différents. L'étudiant doit résoudre le problème avec **ses propres** paramètres.

### flag_t3_decrypt : le message déchiffré EST le flag
La valeur APG `flag_t3_decrypt` est utilisée comme plaintext M3. Le provisioning calcule C3 = M3^e mod n
et stocke C3 dans `params.txt`. Le déchiffrement C3^d mod n redonne M3 = le flag. Le student
soumet directement le texte déchiffré comme réponse à la plateforme.

### Certificat X.509 unique (Task 6)
Le provisioning génère une paire CA + serveur avec `openssl genrsa / req / x509` à chaque déploiement.
Le hash SHA-256 du corps du certificat (calculé par `store_cert_hash.py`) est stocké dans
`secrets.json`. Chaque sandbox a un certificat différent, donc un hash différent.

### Verifier (rsa-verify)
- Lit les réponses dans `~/rsalab/answers/taskN.txt`.
- Normalise les hex (majuscules, sans espaces, sans 0x, sans zéros de tête).
- Compare avec `secrets.json` (root-only, 0o600).
- Imprime le flag uniquement si la réponse est correcte.

## Solutions de référence (voir aussi champ `solution` dans training.json)
```c
// Task 1
BN_sub(p1, p, one); BN_sub(q1, q, one); BN_mul(phi, p1, q1, ctx);
BN_mod_inverse(d, e, phi, ctx);

// Task 2
BN_mod_exp(C, M, e, n, ctx);

// Task 3
BN_mod_exp(M, C, d, n, ctx);

// Task 4
BN_mod_exp(S, M, d, n, ctx);

// Task 5
BN_mod_exp(V, S, e, n, ctx);  // VALID si BN_cmp(V, M) == 0

// Task 6 (après extraction des valeurs avec openssl)
BN_mod_exp(V, S_cert, e_ca, n_ca, ctx);  // comparer avec sha256(cert_body)
```
