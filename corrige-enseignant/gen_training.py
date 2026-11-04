import json

def tl(order, title, minutes, answer, content, solution, hints, score):
    return {
        "title": title,
        "level_type": "TRAINING_LEVEL",
        "order": order,
        "estimated_duration": minutes,
        "minimal_possible_solve_time": None,
        "answer": answer,
        "answer_variable_name": None,
        "content": content,
        "solution": solution,
        "solution_penalized": True,
        "hints": [
            {"title": t, "content": c, "hint_penalty": p, "order": i}
            for i, (t, c, p) in enumerate(hints)
        ],
        "incorrect_answer_limit": 10,
        "attachments": [],
        "max_score": score,
        "variant_answers": False,
        "reference_solution": [],
        "mitre_techniques": [],
        "expected_commands": [],
        "commands_required": False,
    }

COMPILE = "Compilez avec `gcc tacheX.c -o tacheX -lcrypto` (le caractère après `-` est la lettre **L** minuscule). Les fichiers du TP sont dans `~/tp` (`cd ~/tp`)."

levels = []

levels.append({
    "title": "Introduction",
    "level_type": "INFO_LEVEL",
    "order": 0,
    "estimated_duration": 0,
    "minimal_possible_solve_time": None,
    "content": (
        "# Informations générales : à lire attentivement\n\n"
        "* Les niveaux se suivent : terminez chacun avant de passer au suivant.\n"
        "* **Les indices (hints) coûtent des points** : chaque indice débloqué diminue le score du niveau. Afficher la solution fait perdre tous les points du niveau.\n"
        "* Vous avez 10 tentatives par niveau.\n"
        "* Vous pouvez utiliser la documentation d'OpenSSL : https://linux.die.net/man/3/bn\n"
        "* Ce TP est à but pédagogique uniquement.\n\n"
        "# Le TP\n\n"
        "RSA est l'un des premiers systèmes de cryptographie à clé publique. Dans ce TP, vous allez le programmer vous-même "
        "en langage C avec la bibliothèque **BIGNUM d'OpenSSL** : calcul de la clé privée, chiffrement, déchiffrement, "
        "signature, vérification de signature, puis vérification manuelle d'un certificat X.509.\n\n"
        "Vous devrez aussi rédiger un **rapport** (étapes, code, captures d'écran, explications) à remettre à l'enseignant.\n\n"
        "Basé sur le TP « RSA Public-Key Encryption and Signature Lab » de SEED Labs (Wenliang Du)."
    ),
})

levels.append({
    "title": "Get Access",
    "level_type": "ACCESS_LEVEL",
    "order": 1,
    "estimated_duration": 0,
    "minimal_possible_solve_time": None,
    "passkey": "start",
    "cloud_content": (
        "Votre première tâche est d'accéder à la sandbox, où vous ferez tous les niveaux suivants. "
        "Une fois connecté, soumettez la réponse **`start`**.\n\n"
        "### Accès à la sandbox\n"
        "1. Dans la topologie à droite, faites un clic droit sur **`attacker`** puis cliquez sur **`Open GUI`** : une nouvelle fenêtre s'ouvre.\n"
        "2. Connectez-vous avec l'utilisateur **`user`** et le mot de passe **`Password123`**.\n"
        "3. Ouvrez un terminal et tapez `cd ~/tp && ls`. Vous devez voir : `bn_sample.c  valeurs.txt  c0.pem  c1.pem`.\n\n"
        "Vous pouvez aussi utiliser SSH. Voir la [documentation](https://docs.platform.cyberrange.cz/user-guide-advanced/sandboxes/sandbox-access/#user-access)."
    ),
    "local_content": "This sandbox has not been tested for use with local sandbox.",
})

levels.append(tl(2, "T1 - Calculer la clé privée", 10,
    "3587A24598E5F2A21DB007D89D18CC50ABA5075BA19A33890FE7C28A9B496AEB",
    "**Objectif** : calculer la clé privée `d` à partir de `p`, `q` et `e` (fichier `~/tp/valeurs.txt`, section *Tâche 1*). Copiez-collez les valeurs, ne les retapez pas.\n\n"
    "1. Écrivez `tache1.c` en vous inspirant de `bn_sample.c`.\n"
    "2. Convertissez p, q, e avec `BN_hex2bn`.\n"
    "3. Calculez n = p × q, puis φ(n) = (p-1) × (q-1).\n"
    "4. Calculez d tel que e × d ≡ 1 (mod φ(n)).\n"
    "5. " + COMPILE.replace("tacheX", "tache1") + "\n\n"
    "Le flag est la valeur de **d en hexadécimal, en majuscules, sans espace** (ce que `BN_bn2hex` affiche).",
    "```c\nBN_sub(p1,p,one); BN_sub(q1,q,one);\nBN_mul(phi,p1,q1,ctx);\nBN_mod_inverse(d,e,phi,ctx);\nprintBN(\"d =\", d);\n```\nd = 3587A245...96AEB",
    [("Quelle valeur faut-il calculer avant d ?", "Calculez φ(n) = (p-1)(q-1). Utilisez `BN_sub` et `BN_mul`.", 2),
     ("Quelle fonction OpenSSL pour d ?", "`BN_mod_inverse(d, e, phi, ctx)` calcule l'inverse de e modulo φ(n).", 4)],
    20))

levels.append(tl(3, "T2 - Chiffrer un message", 10,
    "6FB078DA550B2650832661E14F4F8D2CFAEF475A0DF3A75CACDC5DE5CFC5FADC",
    "**Objectif** : chiffrer le message `A top secret!` avec la clé publique (e, n) de `valeurs.txt` (section *Tâches 2, 3 et 4*).\n\n"
    "1. Convertissez le texte en hexadécimal :\n"
    "   `python3 -c 'print(\"A top secret!\".encode().hex())'`\n"
    "2. Dans `tache2.c`, convertissez ce nombre hexadécimal avec `BN_hex2bn`.\n"
    "3. Calculez C = M^e mod n.\n"
    "4. " + COMPILE.replace("tacheX", "tache2") + "\n\n"
    "Le flag est **C en hexadécimal, majuscules, sans espace**.",
    "```c\nBN_hex2bn(&M, \"4120746f702073656372657421\");\nBN_mod_exp(C, M, e, n, ctx);\nprintBN(\"C =\", C);\n```",
    [("Comment convertir le texte ?", "Convertissez d'abord le texte ASCII en hexadécimal (commande Python indiquée), puis utilisez `BN_hex2bn`.", 2),
     ("Quelle fonction pour le chiffrement ?", "C = M^e mod n correspond à `BN_mod_exp(C, M, e, n, ctx)`.", 4)],
    15))

levels.append(tl(4, "T3 - Déchiffrer un message", 10,
    "Password is dees",
    "**Objectif** : déchiffrer le chiffré `C` (section *Tâche 3* de `valeurs.txt`) avec la clé privée `d`, et retrouver le texte.\n\n"
    "1. Dans `tache3.c`, calculez M = C^d mod n.\n"
    "2. Affichez M en hexadécimal.\n"
    "3. Reconvertissez l'hexadécimal en texte :\n"
    "   `python3 -c 'print(bytes.fromhex(\"VOTRE_HEX\").decode())'`\n"
    "4. " + COMPILE.replace("tacheX", "tache3") + "\n\n"
    "Le flag est **le texte clair obtenu, exactement** (majuscule initiale comprise).",
    "```c\nBN_mod_exp(M, C, d, n, ctx);\nprintBN(\"M =\", M);\n```\nM = 50617373776F72642069732064656573 donc `Password is dees`.",
    [("Quelle formule ?", "M = C^d mod n.", 2),
     ("Comment lire le résultat ?", "Le résultat est un nombre hexadécimal : convertissez-le en ASCII avec la commande Python indiquée.", 4)],
    15))

levels.append(tl(5, "T4 - Signer un message", 10,
    "55A4E7F17F04CCFE2766E1EB32ADDBA890BBE92A6FBE2D785ED6E73CCB35E4CB",
    "**Objectif** : signer le message `I owe you $2000.` avec la clé privée (signez directement le message, pas son hash).\n\n"
    "1. Convertissez le message en hexadécimal (`python3 -c 'print(\"I owe you $2000.\".encode().hex())'`).\n"
    "2. Dans `tache4.c`, calculez S = M^d mod n.\n"
    "3. Recommencez avec `I owe you $3000.` et comparez les deux signatures (**pour votre rapport** : que remarquez-vous ?).\n"
    "4. " + COMPILE.replace("tacheX", "tache4") + "\n\n"
    "Le flag est la **signature du message `I owe you $2000.`**, en hexadécimal, majuscules, sans espace.",
    "```c\nBN_mod_exp(S, M, d, n, ctx);\nprintBN(\"S =\", S);\n```\nS($3000) = BCC20FB7...05822 : une toute petite modification du message change complètement la signature.",
    [("Quelle opération réalise la signature ?", "Signer revient à chiffrer avec la clé privée : S = M^d mod n.", 2),
     ("Quelle fonction OpenSSL ?", "`BN_mod_exp(S, M, d, n, ctx)`.", 4)],
    15))

levels.append(tl(6, "T5 - Vérifier une signature", 5,
    "valid",
    "**Objectif** : Bob reçoit le message `Launch a missile.` d'Alice avec une signature S. Vérifiez si la signature est bien celle d'Alice (section *Tâche 5* de `valeurs.txt`).\n\n"
    "1. Dans `tache5.c`, calculez M' = S^e mod n.\n"
    "2. Convertissez M' en texte, ou comparez-le avec le message converti en hexadécimal : `python3 -c 'print(\"Launch a missile.\".encode().hex())'`.\n"
    "3. " + COMPILE.replace("tacheX", "tache5") + "\n\n"
    "Le flag est `valid` si la signature est correcte, `invalid` sinon.",
    "```c\nBN_mod_exp(M2, S, e, n, ctx);\n```\nM' = 4C61756E63682061206D697373696C652E = `Launch a missile.` donc `valid`.",
    [("Quelle formule pour vérifier ?", "Calculez M' = S^e mod n avec la clé publique (e, n).", 2),
     ("Que comparer ?", "Comparez M' avec le message `Launch a missile.` converti en hexadécimal.", 3)],
    10))

levels.append(tl(7, "T5 - Signature corrompue", 5,
    "invalid",
    "Le dernier octet de la signature passe de `2F` à `3F` (un seul bit change) :\n\n"
    "`S = 643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F`\n\n"
    "Refaites la vérification de la tâche précédente avec cette nouvelle signature. **Pour votre rapport** : décrivez ce qui se passe.\n\n"
    "Le flag est `valid` ou `invalid`.",
    "S^e mod n donne un nombre aléatoire illisible, différent de `Launch a missile.` donc `invalid`.",
    [("Que faire ?", "Recommencez exactement la vérification, mais avec la signature modifiée.", 2)],
    10))

levels.append(tl(8, "T6 - Vérifier un certificat X.509", 20,
    "caeeae50fcb4393fe6a5acfaf127da80df9634cd20fd5da059577e113cbd6ff7",
    "**Objectif** : vérifier à la main la signature du certificat serveur `c0.pem` avec la clé publique de son émetteur `c1.pem` (dans `~/tp`). N'utilisez pas `openssl verify` : vous devez programmer la vérification.\n\n"
    "1. **Clé publique de l'émetteur** : le modulus n avec `openssl x509 -in c1.pem -noout -modulus`, et l'exposant e avec `openssl x509 -in c1.pem -noout -text | grep Exponent`.\n"
    "2. **Signature du certificat** :\n"
    "   `openssl x509 -in c0.pem -noout -text | sed -n '/Signature Value/,$p' | tail -n +2 | tr -d '[:space:]:'`\n"
    "3. **Corps du certificat** (la partie signée) :\n"
    "   `openssl asn1parse -i -in c0.pem` (repérez les deux blocs SEQUENCE), puis\n"
    "   `openssl asn1parse -i -in c0.pem -strparse 4 -out c0_body.bin -noout`\n"
    "4. **Hash du corps** : `sha256sum c0_body.bin`\n"
    "5. Dans votre programme C, calculez S^e mod n : le résultat se termine par le hash SHA-256 du corps. Comparez-les.\n\n"
    "Le flag est le **hash SHA-256 (64 caractères hexadécimaux, minuscules)** de `c0_body.bin`.",
    "```\nopenssl asn1parse -i -in c0.pem -strparse 4 -out c0_body.bin -noout\nsha256sum c0_body.bin\n```\nS^e mod n se termine par ce hash : le certificat est valide.",
    [("Quelle partie du certificat est hachée ?", "Le corps du certificat, sans le bloc de signature.", 3),
     ("Quelle commande extrait le corps ?", "`openssl asn1parse -i -in c0.pem -strparse 4 -out c0_body.bin -noout`", 4)],
    15))

total = sum(l.get("estimated_duration", 0) for l in levels)
doc = {
    "title": "RSA Public-Key Encryption and Signature Lab",
    "description": "Hands-on RSA lab with OpenSSL BIGNUM",
    "prerequisites": [],
    "outcomes": ["You will implement RSA key derivation, encryption, decryption, signature and verification in C, and manually verify an X.509 certificate."],
    "state": "UNRELEASED",
    "show_stepper_bar": True,
    "levels": levels,
    "estimated_duration": total,
    "variant_sandboxes": False,
}
out = "../library-rsa-lab/training.json"
with open(out, "w", encoding="utf-8") as f:
    json.dump(doc, f, ensure_ascii=False, indent=2)
    f.write("\n")
print("écrit", out, "durée", total, "score total", sum(l.get("max_score", 0) for l in levels))
