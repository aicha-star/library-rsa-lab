# Cybersecurity game "RSA Public-Key Encryption & Signature Lab"

Scénario linéaire avec **paramètres RSA et flags uniques par étudiant** pour la [plateforme CyberRangeCZ](https://docs.platform.cyberrange.cz/), basé sur le [SEED Labs RSA Lab](https://github.com/seed-labs/seed-labs/tree/master/category-crypto/Crypto_RSA) (CC BY-NC-SA 4.0, voir `ATTRIBUTION.txt`).

L'étudiant implémente chaque étape de l'algorithme RSA en **C + OpenSSL BigNum** : dérivation de la clé privée, chiffrement, déchiffrement, signature numérique, vérification de signature, et vérification manuelle d'un certificat X.509. Noté **sur 20** (plateforme ×10 = 200 points). Conçu pour ~30 étudiants simultanés.

## Résumé des niveaux
| # | Niveau | Type | Pts (×10) | /20 | Flag obtenu par |
|---|---|---|---|---|---|
| 0 | Bienvenue | info | — | — | — |
| 1 | Accès | access | — | — | passkey `start` |
| 2 | Task 0 — Mise en place | training | 10 | 1 | `sudo rsa-verify 0` (**unique**) |
| 3 | Task 1 — Clé privée d | training | 30 | 3 | `sudo rsa-verify 1` (**unique**) |
| 4 | Task 2 — Chiffrement | training | 20 | 2 | `sudo rsa-verify 2` (**unique**) |
| 5 | Task 3 — Déchiffrement | training | 30 | 3 | Texte déchiffré = flag (**unique**) |
| 6 | Task 4 — Signature | training | 30 | 3 | `sudo rsa-verify 4` (**unique**) |
| 7 | Task 5 — Vérification | training | 30 | 3 | `sudo rsa-verify 5` (**unique**) |
| 8 | Task 6 — X.509 | training | 20 | 2 | `sudo rsa-verify 6` (**unique**) |
| 9 | Quiz final (6 × 5 pts) | assessment | 30 | 3 | — |
| 10 | Débriefing | info | — | — | — |
| | **Total** | | **200** | **20** | |

Pénalités : 5-20 pts plateforme = **−0,5 à −2 / 20**.

## Topologie
| Machine | Image | Flavor | Rôle |
|---|---|---|---|
| `seed` | `seed-ubuntu-20.04` **(à adapter)** | `m1.medium` | poste de l'étudiant (tout le lab s'y déroule) |
| `router` | `debian-12-x86_64` | `m1.small` | accès WAN (non requis pour les tasks 0-5) |

Réseau : `seed-switch` 10.1.33.0/24. La machine `seed` n'a pas besoin d'accès réseau externe (tous les certs de Task 6 sont générés localement lors du provisioning).

### Ce que vous DEVEZ adapter dans `topology.yml`
1. `image:` de `seed` → nom de votre image SEED dans OpenStack/Glance.
2. `mgmt_user:` → compte SSH de gestion de cette image (clé + passwordless sudo).
3. `flavor:` si `m1.medium` / `m1.small` n'existent pas dans votre cloud.

### Pré-requis pour l'image SEED Ubuntu 20.04
* `gcc`, `make`, `libssl-dev`, `openssl` disponibles (ou Internet pour les installer).
* Python3 disponible (pour `gen_params.py` et `store_cert_hash.py`).
* Environnement graphique avec terminal (pour l'Open GUI du portail étudiant).

## Mécanisme anti-triche détaillé

### 1. Paramètres RSA uniques (Tasks 1-4)
`gen_params.py` (pur Python, aucune dépendance externe) génère deux nombres premiers 128 bits `p` et `q` avec un test de Miller-Rabin (20 tours). Chaque sandbox a son propre `(p, q, n, d)`. Les réponses (d, C2, S4) sont donc **différentes pour chaque étudiant**. Les params sont dans `~/rsalab/params.txt` (lisibles) et les bonnes réponses dans `/opt/rsalab/secrets.json` (root-only, 0o600).

### 2. Task 3 : le flag EST le message déchiffré
La valeur APG `flag_t3_decrypt` (générée par la plateforme, 12 chars) est le plaintext M3. Le provisioning calcule `C3 = M3^e mod n` et écrit `C3` dans `params.txt`. L'étudiant déchiffre `C3^d mod n` = M3 et soumet M3 directement à la plateforme. Pas besoin de passer par `rsa-verify 3` (mais c'est disponible pour confirmer).

### 3. Task 6 : certificat unique par sandbox
`openssl genrsa / req / x509` génère une paire CA + serveur différente à chaque provisioning. `store_cert_hash.py` calcule le SHA-256 du corps du certificat et l'enregistre dans `secrets.json`. Chaque sandbox a un hash différent → flag unique.

### 4. Verifier `rsa-verify`
L'étudiant écrit sa réponse (hex string) dans `~/rsalab/answers/taskN.txt`, puis lance `sudo rsa-verify N`. Le verifier normalise les valeurs hex (minuscules/majuscules, espaces, 0x) et compare. Si correct, imprime le flag plateforme.

## Import dans CyberRangeCZ et lancement pour 30 étudiants
1. **Pousser ce repo sur GitHub** (voir ci-dessous).
2. *Sandbox definitions* → **Create** → URL Git (branche `main`).
3. *Training definitions* → **Upload** `training.json` → passer en `RELEASED` quand prêt.
4. *Pools* → taille **30 (+ 2-3 de réserve)**, allouer.
5. *Training instances* → créer une instance (training + pool), distribuer le lien.
6. Scoreboard : diviser par 10 pour la note sur 20.

## Structure du repo
```
topology.yml
variables.yml
training.json
game_design.md
README.md / ATTRIBUTION.txt / LICENSE
provisioning/
  playbook.yml
  requirements.yml
  host_vars/seed.yml
  roles/seed/
    defaults/main.yml
    tasks/main.yml
    files/
      bn_sample.c         # exemple OpenSSL BigNum (verbatim du PDF SEED)
      rsa_lab.c           # programme starter avec TODOs pour toutes les tâches
      Makefile
      gen_params.py       # générateur Python de paramètres RSA uniques
      store_cert_hash.py  # calcule le SHA-256 du corps du cert (Task 6)
      rsa-verify          # script Python de vérification + affichage des flags
```

## Pousser sur GitHub
```bash
cd library-rsa-lab
git remote add origin https://github.com/<votre-compte>/library-rsa-lab.git
git push -u origin main
```

## Dépannage
* **`make` échoue avec `openssl/bn.h not found`** : `sudo apt install libssl-dev` sur la VM SEED.
* **`gen_params.py` timeout** : la génération de premiers 128 bits est rapide (~1 s) ; vérifiez que Python3 est disponible sur l'image SEED.
* **`rsa-verify N` : FAIL sur la valeur hex** : l'étudiant a peut-être inclus des espaces, le préfixe `0x`, ou des guillemets dans `taskN.txt`. Le verifier normalise mais ne peut pas corriger une valeur numériquement fausse.
* **Task 6 : hash non stocké (TBD)** : la tâche Ansible `Compute SHA-256 of the Task 6 cert body` a échoué (openssl asn1parse absent ou erreur). Vérifier les logs de provisioning.
* **Licence** : ce scénario est basé sur le SEED Labs RSA Lab (CC BY-NC-SA 4.0) — usage pédagogique non-commercial uniquement.
