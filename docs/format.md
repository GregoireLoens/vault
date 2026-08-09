# Format de vault — version 1

**Statut** : normatif. **Version de format** : 1. **Dernière révision** : 2026-08-08.

Ce document décrit intégralement le format d'un vault sur disque. Le principe IV de la
constitution du projet en fixe l'objectif : **un vault doit rester déchiffrable dans dix ans, à
partir de cette seule spécification et d'outils cryptographiques standard, sans exécuter vault.**

Il n'existe aucun paramètre implicite. Tout ce qui est nécessaire au déchiffrement figure dans le
fichier `header`, en clair — les identifiants d'algorithmes, le sel et les coûts de dérivation
inclus. Une implémentation qui coderait ces valeurs en dur serait fausse : un vault produit avec
d'autres paramètres doit rester lisible.

> **Le format 1 est figé.** Depuis `v1.0.0`, cette disposition est tenue pour stable : les
> versions suivantes de vault sauront la lire, et un changement qui casserait cette lecture serait
> une version majeure, accompagnée d'un chemin de migration documenté.
>
> Un vault de référence produit par `v0.3.0` est conservé dans
> `crates/vault-core/tests/fixtures/v1/` et relu par chaque exécution de la suite. Il ne sera
> jamais régénéré : c'est ce qui fait de l'engagement ci-dessus une vérification plutôt qu'une
> déclaration.

---

## 1. Disposition sur disque

Un vault est un **répertoire** :

```text
mon-vault/
├── header              # EN CLAIR — paramètres publics uniquement
├── index               # CHIFFRÉ — arborescence, noms, tailles, dates
├── objects/
│   ├── 7f3a9c1e…       # CHIFFRÉ — un blob par fichier, nom = identifiant aléatoire
│   └── b204e88d…
└── .lock               # vide — support du verrou d'accès exclusif entre instances
```

Trois règles gouvernent l'ensemble :

1. `header` est le **seul** élément lisible, et ne contient que ce qui est nécessaire au
   déchiffrement.
2. Aucun nom de blob n'a de rapport avec le nom réel du fichier. La correspondance n'existe que
   dans `index`, chiffré.
3. `index` est le **point d'engagement**. Un blob présent dans `objects/` mais non référencé par
   l'index n'existe pas du point de vue du vault : c'est un déchet inerte, jamais une corruption.

### Conventions d'écriture

Les entiers multi-octets de cette spécification sont en **gros-boutiste** lorsqu'ils apparaissent
dans des données associées ; les entiers des structures CBOR suivent la RFC 8949.

Tout remplacement de fichier suit la séquence : écriture dans un temporaire du **même
répertoire**, `fsync` du fichier, `rename`, `fsync` du répertoire parent. `rename` est atomique
sur un même système de fichiers ; les deux synchronisations garantissent que l'ordre survit à une
coupure d'alimentation.

---

## 2. Algorithmes

| Rôle | Algorithme | Identifiant dans l'en-tête |
|---|---|---|
| Dérivation depuis la passphrase | Argon2id, version 0x13 | `argon2id` |
| Chiffrement authentifié | XChaCha20-Poly1305 | `xchacha20poly1305` |
| Chiffrement du contenu | STREAM (BE32) sur XChaCha20-Poly1305 | — |
| Dérivation des clés par blob | BLAKE3 en mode `derive_key` | — |

Toutes les clés font 256 bits. Tous les tags Poly1305 font 16 octets. Un nonce
XChaCha20-Poly1305 fait 24 octets.

---

## 3. Le fichier `header`

Encodé en **CBOR** (RFC 8949), en clair, de l'ordre de 200 octets. C'est une carte à neuf clés
textuelles :

| Clé | Type CBOR | Description |
|---|---|---|
| `magic` | chaîne d'octets, 8 o | Constante `56 41 55 4C 54 46 4D 54`, soit `VAULTFMT` en ASCII |
| `format_version` | entier non signé | Version du format. Vaut `1` |
| `kdf_algorithm` | texte | `"argon2id"` |
| `kdf_salt` | chaîne d'octets, 16 o | Sel de dérivation, tiré aléatoirement |
| `kdf_memory_kib` | entier non signé | Coût mémoire Argon2id, en kibioctets |
| `kdf_iterations` | entier non signé | Nombre de passes |
| `kdf_parallelism` | entier non signé | Degré de parallélisme |
| `aead_algorithm` | texte | `"xchacha20poly1305"` |
| `wrapped_master_key` | chaîne d'octets, 72 o | Clé maîtresse enveloppée : nonce (24 o) ‖ chiffré (32 o) ‖ tag (16 o) |

Valeurs par défaut à la création — **indicatives**, jamais présumées à la lecture :
`kdf_memory_kib` = 131072 (128 MiB), `kdf_iterations` = 3, `kdf_parallelism` = 4.

### Règles de lecture

- `magic` et `format_version` sont lus **avant toute autre chose**. Une constante différente
  signifie que le fichier n'est pas un en-tête de vault ; une version inconnue provoque un refus
  explicite d'ouverture, jamais une tentative de lecture approximative.
- L'en-tête ne contient **aucune** information sur le contenu : ni nombre d'entrées, ni taille
  totale, ni date.
- L'en-tête n'est réécrit qu'au changement de passphrase. Les ajouts, suppressions et
  modifications ne le touchent pas.

### Intégrité de l'en-tête

Les champs publics de l'en-tête servent de données associées à l'enveloppement de la clé
maîtresse (§4). **Altérer le sel, un coût de dérivation ou un identifiant d'algorithme fait donc
échouer le désenveloppement**, exactement comme une passphrase erronée. Aucune empreinte de
vérification n'est stockée : elle offrirait une prise à une attaque hors ligne sans rien apporter.

---

## 4. Chaîne de dérivation des clés

```text
passphrase ──Argon2id(kdf_salt, m, t, p)──▶ clé d'enveloppe (256 bits)
                                                  │
                             déchiffre wrapped_master_key
                                                  ▼
                                         clé maîtresse (256 bits)
                                            │            │
                         chiffre l'index ◀──┘            └──▶ clé de blob (256 bits)
```

La clé maîtresse est **tirée du générateur aléatoire du système** à la création du vault. Elle
n'est jamais dérivée de la passphrase. Cette indirection est ce qui rend le changement de
passphrase indépendant de la taille du vault : seul l'en-tête est réécrit, le contenu n'est ni
déchiffré ni rechiffré.

### 4.1 Clé d'enveloppe

```text
clé_enveloppe = Argon2id(
    mot_de_passe = passphrase encodée en UTF-8,
    sel          = kdf_salt,
    m            = kdf_memory_kib,
    t            = kdf_iterations,
    p            = kdf_parallelism,
    version      = 0x13,
    longueur     = 32 octets)
```

### 4.2 Désenveloppement de la clé maîtresse

```text
contexte_public = magic                                   (8 o)
                ‖ format_version en gros-boutiste sur 4 o
                ‖ "argon2id"                              (8 o, ASCII)
                ‖ kdf_salt                                (16 o)
                ‖ kdf_memory_kib en gros-boutiste sur 4 o
                ‖ kdf_iterations en gros-boutiste sur 4 o
                ‖ kdf_parallelism en gros-boutiste sur 4 o
                ‖ "xchacha20poly1305"                     (17 o, ASCII)

données_associées = "vault master key v1" ‖ contexte_public

nonce   = wrapped_master_key[0..24]
chiffré = wrapped_master_key[24..]

clé_maîtresse = XChaCha20-Poly1305-Ouvrir(
    clé = clé_enveloppe, nonce = nonce,
    données_associées = données_associées, chiffré = chiffré)
```

Le contexte public emploie un encodage à champs de largeur fixe, et non le CBOR de l'en-tête :
deux encodeurs CBOR peuvent légitimement produire des octets différents pour la même structure,
et l'authentification cesserait d'être reproductible.

### 4.3 Clé d'un blob

```text
clé_blob = BLAKE3-derive_key(
    contexte = "vault 2026 blob key v1",
    matière  = clé_maîtresse ‖ blob_id)
```

Concrètement : initialiser BLAKE3 en mode dérivation avec la chaîne de contexte, absorber les 32
octets de la clé maîtresse puis les 32 octets de l'identifiant, et prendre les 32 premiers octets
de la sortie.

Une clé par blob cantonne toute réutilisation accidentelle de nonce à un seul fichier, et permet
de livrer un jour un élément isolé sans livrer la clé maîtresse.

---

## 5. Le fichier `index`

```text
┌──────────────┬────────────────────────────────┬──────────┐
│ nonce (24 o) │ CBOR de l'index, chiffré       │ tag 16 o │
└──────────────┴────────────────────────────────┴──────────┘
```

- **Clé** : la clé maîtresse.
- **Données associées** : la chaîne ASCII `vault index v1`.
- **Nonce** : tiré aléatoirement à **chaque** écriture, et stocké en tête du fichier. Deux
  réécritures successives d'un index inchangé produisent donc deux fichiers différents.

Placer le nonce dans le fichier qu'il protège, plutôt que dans l'en-tête, ramène toute
modification du vault à **un seul** remplacement atomique. Avec le nonce dans l'en-tête, une
interruption entre les deux remplacements laisserait un en-tête pointant un nonce qui n'est plus
celui de l'index — un vault ouvrable mais dont l'index serait indéchiffrable.

### Contenu déchiffré

Une carte CBOR à deux clés :

| Clé | Type | Description |
|---|---|---|
| `index_version` | entier non signé | Numéro de révision, incrémenté à chaque modification |
| `entries` | tableau | Les entrées, **triées par chemin** et sans doublon |

Chaque entrée est une carte CBOR :

| Clé | Type | Description |
|---|---|---|
| `path` | tableau de chaînes d'octets | Chemin relatif, composant par composant |
| `kind` | texte | `"File"` ou `"Directory"` |
| `size` | entier ou `null` | Taille **réelle** du contenu, avant remplissage. `null` pour un dossier |
| `modified` | entier signé | Date de modification d'origine, en secondes Unix |
| `blob_id` | chaîne d'octets 32 o ou `null` | Identifiant du blob. `null` pour un dossier |
| `blob_padded_size` | entier ou `null` | Taille du blob sur disque, remplissage compris. `null` pour un dossier |

### Invariants

Une implémentation lisant l'index **doit** les vérifier, y compris après une authentification
réussie : un vault forgé puis remis à sa victime ne doit pas pouvoir faire écrire l'extraction
hors de sa destination.

- Les entrées sont strictement ordonnées par `path` : ni désordre, ni doublon.
- Une entrée `File` porte `size`, `blob_id` et `blob_padded_size` ; une entrée `Directory` n'en
  porte aucun.
- Aucun composant de `path` n'est vide, ne vaut `.` ou `..`, et ne contient `/`, `\` ni l'octet
  nul.
- Tout `blob_id` référencé doit exister dans `objects/`. L'inverse n'est pas vrai : un blob non
  référencé est un **déchet**, et non une corruption. L'index est le point d'engagement du vault ;
  un blob écrit puis abandonné par une opération interrompue n'existe pas de son point de vue.

  Une implémentation **peut** le supprimer, et vault le fait silencieusement à chaque
  déverrouillage — sans le signaler, puisque rien d'anormal ne s'est produit, et sans faire échouer
  l'ouverture si la suppression est impossible. Un fichier de `objects/` dont le nom n'est pas
  64 chiffres hexadécimaux n'est pas un blob : il est laissé en place.

### Noms de fichiers

Les composants de `path` sont stockés **en octets bruts**, tels que le système de fichiers les a
fournis, sans conversion ni normalisation Unicode. C'est le seul moyen de restituer un nom à
l'identique entre des systèmes dont les conventions diffèrent.

Deux conséquences, assumées :

- **Deux noms qui ne diffèrent que par leur normalisation Unicode sont deux entrées distinctes.**
  `café` en forme composée et `café` en forme décomposée cohabitent dans le même dossier.
- **Tous les hôtes n'acceptent pas toutes les suites d'octets.** Un vault se transporte d'une
  plateforme à l'autre, et une entrée parfaitement valide dans le format peut être inextractible
  ailleurs :

  | Plateforme | Ce qu'elle accepte comme nom de fichier |
  |---|---|
  | Linux, et la plupart des systèmes POSIX | tout octet, sauf `/` et l'octet nul |
  | macOS — APFS et HFS+ | UTF-8 valide obligatoire ; le noyau refuse le reste |
  | Windows — NTFS | UTF-8 valide, sans `< > : " \| ? *` ni caractère de contrôle, sans point ni espace final, et hors noms de périphériques réservés (`CON`, `PRN`, `AUX`, `NUL`, `COM0` à `COM9`, `LPT0` à `LPT9`, extension comprise) |

  L'entrée reste **listable et intacte** dans le vault : c'est son écriture à destination qui est
  impossible, et une implémentation doit la refuser explicitement **avant** d'écrire quoi que ce
  soit, plutôt que de laisser le système rendre une erreur opaque au milieu d'une arborescence à
  moitié extraite. Le vault s'extraira sur un hôte dont les règles acceptent ce nom.

---

## 6. Les blobs

Un fichier par entrée de type `File`, dans `objects/`, nommé par les **64 chiffres hexadécimaux
minuscules** de son `blob_id`.

```text
┌────────────────┬─────────────────────────────────┬──────────────┐
│ nonce (19 o)   │ morceaux STREAM chiffrés        │ remplissage  │
└────────────────┴─────────────────────────────────┴──────────────┘
```

### 6.1 Identifiant

`blob_id` fait 32 octets tirés du générateur aléatoire du système. Il n'a **aucun** lien avec le
contenu ni avec le nom du fichier, et ce n'est **pas** une empreinte : deux fichiers identiques
donnent deux blobs distincts, sans quoi le vault révélerait ses doublons.

### 6.2 Chiffrement du contenu

Le contenu est chiffré par la construction **STREAM** (Hoang, Reyhanitabar, Rogaway, Vizár), dans
sa variante **BE32**, sur XChaCha20-Poly1305, par morceaux de **65536 octets** de clair.

- **Clé** : la clé du blob (§4.3).
- **Données associées**, identiques pour tous les morceaux :
  `"vault blob v1" ‖ blob_id`.
- **Nonce STREAM** : 19 octets, tirés aléatoirement, stockés en tête du blob. STREAM BE32 prélève
  les 5 octets restants du nonce de 24 octets de XChaCha20-Poly1305 pour y loger un compteur de
  morceau sur 32 bits et un drapeau de dernier morceau. Le nonce complet du morceau *n* est donc
  `nonce_stream ‖ n en gros-boutiste sur 4 o ‖ drapeau`, où le drapeau vaut `0x01` pour le dernier
  morceau et `0x00` pour les autres.
- Chaque morceau chiffré occupe la taille de son clair plus 16 octets de tag.
- **Un contenu vide occupe un morceau**, vide et marqué comme dernier. Sans lui, un blob vide ne
  porterait aucune marque de fin et sa troncature serait indétectable.

Nombre de morceaux et longueur du chiffré, pour un contenu de `taille` octets :

```text
morceaux     = max(1, plafond(taille / 65536))
chiffré      = taille + 16 × morceaux
```

La longueur du clair vient de l'index, donc d'une source authentifiée. Elle détermine combien
d'octets lire : **le reste du blob est du remplissage, jamais déchiffré ni interprété.**

Ce que STREAM apporte par rapport à un simple découpage : chaque morceau est authentifié à sa
position, donc réordonner deux morceaux est détecté ; le dernier morceau porte une marque de fin,
donc tronquer un blob est détecté ; supprimer un morceau intermédiaire décale tous les suivants,
donc échoue.

### 6.3 Remplissage

La taille du blob est portée au palier supérieur d'une suite géométrique de raison 1,1, avec un
plancher à 4096 octets. En arithmétique entière, à partir de la longueur réelle `l = 19 + chiffré` :

```text
palier ← 4096
tant que palier < l : palier ← plafond(palier × 11 / 10)
```

Le calcul est entier et non flottant : deux plateformes doivent produire exactement les mêmes
paliers. Les octets de remplissage sont tirés aléatoirement.

Le surcoût de stockage reste sous 10 %, tandis qu'un observateur du vault verrouillé n'apprend
qu'une **fourchette** de taille, et non la taille exacte.

### 6.4 Dates sur le système de fichiers hôte

La date de modification que l'hôte pose sur un fichier de blob est ramenée à **l'époque Unix**,
au moment de l'écriture et avant que le blob n'apparaisse dans `objects/`.

Le remplissage cache la taille, l'identifiant aléatoire cache le nom — mais la date, laissée à
l'hôte, trahirait **l'ordre et le rythme des ajouts**. Trier `objects/` par date reconstituerait
la chronologie du vault : ce qui est arrivé en premier, ce qui a suivi des mois plus tard,
lesquels sont arrivés ensemble. Rien de cela n'est du contenu, et tout cela en dit long.

L'époque Unix est choisie parce qu'elle est manifestement conventionnelle : une date plausible
laisserait croire à une information, alors que celle-ci se lit pour ce qu'elle est — une absence
de date. La date d'**accès** n'est pas normalisée : le système la remet à jour à chaque lecture,
si bien que la fixer ne tiendrait pas.

Une implémentation tierce qui se contenterait de lire un vault n'a rien à faire de cette règle.
Une implémentation qui **écrit** doit l'appliquer.

### 6.5 Bornes

La taille maximale du contenu d'un fichier est de **4 000 000 000 octets**. Au-delà, l'ajout est
refusé explicitement, avant toute écriture.

Ce n'est pas 4 GiB : 4 294 967 296 octets dépassent la limite et sont refusés.

---

## 7. Le fichier `.lock`

Fichier vide, support d'un verrou consultatif exclusif — `flock` sous Unix, `LockFileEx` sous
Windows — tenu pendant toute la durée d'une session déverrouillée. Le noyau le libère à la
fermeture du descripteur, y compris lorsque le processus est tué sans ménagement : contrairement à
un fichier témoin, il ne laisse jamais un vault définitivement « occupé » par un processus mort.

Ce fichier ne participe pas au format : une implémentation tierce qui se contente de lire un vault
peut l'ignorer.

---

## 7 bis. Vecteurs de test

Les valeurs ci-dessous sont celles du **vault de référence** conservé dans
`crates/vault-core/tests/fixtures/v1/`. Elles permettent à une implémentation tierce de situer
l'étape exacte où elle diverge, **sans exécuter vault** : il suffit de comparer, étape par étape,
ce qu'elle obtient à ce qui suit.

> ⚠ **Ces valeurs appartiennent à un vault dont la passphrase est publique et qui ne protège
> rien.** Ce n'est pas un exemple à imiter : ses paramètres de dérivation sont volontairement
> minimaux pour que la suite de tests reste rapide, et un vault réel emploie ceux de la §3.

Passphrase : `vault fixture v1 passphrase de reference`, soit en UTF-8 :

```text
7661756c7420666978747572652076312070617373706872617365206465207265666572656e6365   (40 o)
```

### Champs publics de l'en-tête

| Champ | Valeur |
|---|---|
| `format_version` | `1` |
| `kdf_salt` | `bdfaa6979ddb4e6f23ce5c8615aaedcd` (16 o) |
| `kdf_memory_kib` | `64` |
| `kdf_iterations` | `1` |
| `kdf_parallelism` | `1` |

### Chaîne de dérivation

Clé d'enveloppe, par Argon2id (§4.1) :

```text
7bb28f039c531ddc0ee414e4fa5f1648e81060cb2a6da3a894a58f6582b5e15e   (32 o)
```

Contexte public (§4.2), 65 octets — c'est ici qu'une description approximative se paie le plus
cher, d'où sa publication in extenso :

```text
5641554c54464d54 00000001 6172676f6e326964 bdfaa6979ddb4e6f23ce5c8615aaedcd
00000040 00000001 00000001 786368616368613230706f6c7931333035
```

Données associées du désenveloppement, soit `"vault master key v1" ‖ contexte_public`, 84 octets :

```text
7661756c74206d6173746572206b6579207631
5641554c54464d54000000016172676f6e326964bdfaa6979ddb4e6f23ce5c8615aaedcd
000000400000000100000001786368616368613230706f6c7931333035
```

Clé maîtresse obtenue :

```text
3b2930a56bd1030f685292e07ddcc985fa2aace1961583da49260db2d5905b41   (32 o)
```

### Une entrée témoin

Pour l'entrée `lisez-moi.txt`, de `size` 67 :

| Élément | Valeur |
|---|---|
| `blob_id` | `64a8f329ed76ed598354b07483b2dca8a2bd700eb09e08df17b3fac6d7b81d80` |
| Clé du blob (§4.3) | `24bd88c76e17e3bb676e183c8ce5369410168e186bb998e131d5e2bb7a0875f7` |
| Données associées (§6.2) | `7661756c7420626c6f622076 31` ‖ `blob_id`, soit 45 o |
| Nonce STREAM, en tête du blob | `5174be637c527dbea15f84a55487b1b3afc790` (19 o) |
| Nonce complet du morceau 0 | `5174be637c527dbea15f84a55487b1b3afc790` ‖ `00000000` ‖ `01` (24 o) |
| `blob_padded_size` | `4096` |

Le contenu tenant en un seul morceau, celui-ci est **le dernier** : son drapeau vaut `01`.

### Ce que ces vecteurs garantissent

Ils sont vérifiés automatiquement contre le logiciel à chaque exécution de la suite de tests. Une
divergence entre ce document et le code fait échouer la chaîne d'intégration — c'est ce qui
empêche cette section de vieillir en silence.

Ils sont par ailleurs calculés par une **implémentation indépendante**, écrite depuis ce seul
document (`verification/dechiffreur/`), et non par le logiciel : des vecteurs produits par le code
qu'ils servent à vérifier ne vérifieraient rien.

**Limite de cette vérification, énoncée franchement** : un déchiffreur écrit par l'auteur du
logiciel valide la **suffisance de ce document** — il établit qu'un tiers peut s'en servir pour
déchiffrer. Il ne valide **pas** la conception cryptographique elle-même, qui reste à relire par
quelqu'un d'autre.

---

## 8. Procédure de déchiffrement complète

Pour extraire un fichier d'un vault sans exécuter vault :

1. Lire `header`, le décoder en CBOR. Vérifier `magic` et `format_version`.
2. Dériver la clé d'enveloppe par Argon2id, avec le sel et les coûts **lus dans l'en-tête** (§4.1).
3. Désenveloppper la clé maîtresse (§4.2). Un échec signifie passphrase erronée **ou** en-tête
   altéré, sans qu'il soit possible — ni souhaitable — de distinguer les deux.
4. Lire `index`. Ses 24 premiers octets sont le nonce ; le reste est le chiffré. Ouvrir avec la
   clé maîtresse et les données associées `vault index v1`, puis décoder le CBOR (§5).
5. Trouver l'entrée voulue. En retenir `size` et `blob_id`.
6. Dériver la clé du blob (§4.3).
7. Lire `objects/<blob_id en hexadécimal>`. Ses 19 premiers octets sont le nonce STREAM.
8. Déchiffrer `size + 16 × morceaux` octets à partir du 19e, morceau par morceau, en marquant le
   dernier comme tel (§6.2). **Authentifier chaque morceau avant d'en écrire le clair.** Ignorer
   le remplissage qui suit.
9. Écrire le clair sous le nom donné par `path`, avec la date `modified`.

---

## 9. Fuites résiduelles

Elles sont documentées ici plutôt que passées sous silence. Un observateur qui accède au
répertoire d'un vault **verrouillé**, sans la passphrase, apprend :

| Ce qu'il apprend | Précision | Atténuation |
|---|---|---|
| Le nombre de blobs | Le nombre approximatif de fichiers stockés | Aucune dans cette version |
| La taille de chaque blob | Une fourchette large de 10 %, pas la taille exacte | Remplissage par paliers (§6.3) |
| La date de dernière modification du vault | Quand il a servi pour la dernière fois, par `index` et `header` | Aucune : réécrire l'index est ce qui rend le vault utilisable |
| Les paramètres de dérivation | Le coût d'une attaque par force brute | Publics par conception |

Les dates des **blobs**, elles, n'apprennent rien : elles sont toutes ramenées à l'époque Unix
(§6.4), si bien que `objects/` ne trahit ni l'ordre ni le rythme des ajouts.

Il n'apprend **ni** les noms de fichiers, **ni** l'arborescence, **ni** les tailles exactes, **ni**
le contenu, **ni** si deux fichiers du vault sont identiques.

Hors du périmètre de ce format, et rappelés ici pour être honnête : un poste déjà compromis au
moment de l'utilisation, la contrainte physique ou légale exercée sur le porteur de la
passphrase, les canaux auxiliaires matériels, et l'écriture de la mémoire du processus dans le
fichier d'échange ou l'image d'hibernation par le système d'exploitation.

---

## 10. Compatibilité et évolution

- Toute version de vault sait lire tous les formats antérieurs. Un changement cassant la lecture
  d'un format antérieur est un changement majeur, et s'accompagne d'un chemin de migration
  documenté.
- Cette spécification est versionnée dans le dépôt et mise à jour **dans le même commit** que
  toute modification du format.
- Les coûts de dérivation sont révisables à la hausse sans casser les vaults existants : ils
  appartiennent au vault, et un changement de passphrase permet de les relever au passage.
- **La perte de la passphrase est définitive.** Il n'existe aucune backdoor, aucune clé de secours,
  aucun mécanisme d'escrow, aucune réinitialisation.
