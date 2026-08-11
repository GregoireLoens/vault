# Format du conteneur d'export — version 1

Document **normatif**. Le principe IV en fixe l'exigence : *un conteneur doit rester lisible dans
dix ans à partir de cette seule spécification et d'outils cryptographiques standard, sans exécuter
vault.*

Cette suffisance n'est pas une déclaration : elle est **éprouvée à chaque exécution de la suite**
par `verification/dechiffreur/conteneur.py`, écrit depuis ce document et sans consulter le code
Rust. Un écart y désigne une partie du document qui est fausse ou incomplète.

**Version de format de conteneur** : 1. **Indépendante** de la version du format de vault, décrite
par [`format.md`](./format.md). Un conteneur de version 2 pourra transporter un vault de format 1,
et réciproquement.

---

## 1. Ce que ce format est, et n'est pas

Un conteneur d'export **cadre** un vault ; il ne le chiffre pas. Tous les octets de contenu qu'il
transporte sont ceux que le vault a écrits, recopiés sans être ouverts.

Le déchiffrement d'un conteneur est donc **exactement** celui d'un vault, décrit par
[`format.md`](./format.md) : ce document-ci n'ajoute aucune chaîne de dérivation, aucune donnée
associée, aucune primitive cryptographique.

Il en découle une propriété qu'une implémentation tierce vérifie en une ligne : **dépaqueter un
conteneur produit un répertoire de vault, et rien d'autre.**

---

## 2. Disposition

```text
┌─────────────────────────────────────────────────────────┐
│ EN-TÊTE          carte CBOR, en clair                   │
├─────────────────────────────────────────────────────────┤
│ CADRE 1          carte CBOR, en clair                   │
│ CHARGE 1         length octets, opaques                 │
│ CADRE 2                                                 │
│ CHARGE 2                                                │
│ …                                                       │
├─────────────────────────────────────────────────────────┤
│ SCEAU            carte CBOR, en clair                   │
└─────────────────────────────────────────────────────────┘
```

Aucun octet de remplissage entre les éléments. Le flux se lit d'un bout à l'autre, **sans jamais
revenir en arrière** : c'est ce qui le rend utilisable dans un tube.

Tout le CBOR de ce format suit la RFC 8949. Les cartes emploient des clés textuelles et un encodage
de longueur **définie**.

---

## 3. En-tête

Carte CBOR à cinq clés textuelles.

| Clé | Type CBOR | Description |
|---|---|---|
| `magic` | chaîne d'octets, 8 o | Constante `56 41 55 4C 54 58 46 52`, soit `VAULTXFR` en ASCII |
| `container_version` | entier non signé | Version de **ce** format. Vaut `1` |
| `vault_format_version` | entier non signé | Version du format du vault transporté. Vaut `1` |
| `member_count` | entier non signé | Nombre de membres qui suivent. **Au moins 2** |
| `payload_bytes` | entier non signé | Somme des `length` de tous les membres |

### Règles de lecture

- `magic` et `container_version` sont lus **avant toute autre chose**. Une constante différente
  signifie que ce n'est pas un conteneur ; une version inconnue provoque un refus explicite, jamais
  une lecture approximative.
- `vault_format_version` est vérifiée **avant** d'écrire le moindre octet à destination.
- `member_count` inférieur à 2 est un refus : le membre `header` et le membre `index` sont
  obligatoires.
- `payload_bytes` permet de contrôler l'espace disponible avant d'écrire. Ce n'est **pas** une
  autorité : la lecture s'arrête sur le sceau, pas sur ce compte.
- L'en-tête ne contient **aucune** information sur le contenu du vault : ni nombre d'entrées, ni
  nom, ni date, ni rien qui vienne de la machine qui a produit le conteneur.

---

## 4. Membres

Chaque membre est une carte CBOR à trois clés, **immédiatement** suivie de sa charge.

| Clé | Type CBOR | Description |
|---|---|---|
| `kind` | texte | `"header"`, `"index"` ou `"blob"` |
| `id` | chaîne d'octets 32 o, ou `null` | `null` pour `header` et `index` ; l'identifiant du blob sinon |
| `length` | entier non signé | Nombre d'octets de la charge qui suit |

La charge est **opaque** : ce sont les octets du fichier correspondant du vault, tels quels.

| `kind` | Charge | Décrite par |
|---|---|---|
| `header` | le fichier `header` du vault | [`format.md`](./format.md) §3 |
| `index` | le fichier `index` du vault | [`format.md`](./format.md) §5 |
| `blob` | le fichier `objects/<id en hexadécimal minuscule>` | [`format.md`](./format.md) §6 |

### Ordre, normatif

1. Exactement un membre `header`, **en premier**.
2. Exactement un membre `index`, **en deuxième**.
3. Zéro ou plusieurs membres `blob`, **triés par `id` strictement croissant**, comparés comme des
   suites d'octets non signés. Aucun doublon.

Un lecteur **doit** vérifier cet ordre. Ce n'est pas une préférence esthétique : c'est ce qui rend
deux exports d'un vault inchangé identiques octet pour octet, et donc ce qui permet de comparer deux
conteneurs sans les ouvrir.

Le tri strict exclut les doublons du même coup : deux membres de même `id` violent la croissance.

### Bornes, normatives

Un lecteur **doit** refuser une `length` hors bornes **avant toute allocation**.

| `kind` | Borne supérieure, en octets |
|---|---|
| `header` | 65 536 |
| `index` | 268 435 456 |
| `blob` | 4 400 000 000 |

Une `length` qui dépasse ces valeurs, ou qui déborde l'entier, est un refus explicite. Ces bornes
sont ce qui empêche un conteneur forgé de faire réserver de la mémoire à celui qui le lit.

Une charge plus courte que la `length` annoncée — un flux qui s'arrête au milieu — est un refus.

---

## 5. Sceau

Carte CBOR à trois clés, terminant le flux.

| Clé | Type CBOR | Description |
|---|---|---|
| `end` | chaîne d'octets, 8 o | Constante `56 41 55 4C 54 45 4E 44`, soit `VAULTEND` en ASCII |
| `member_count` | entier non signé | Doit valoir celui de l'en-tête |
| `digest` | chaîne d'octets, 32 o | BLAKE3 de **tous les octets du conteneur qui précèdent le sceau** |

```text
digest = BLAKE3(en-tête ‖ cadre₁ ‖ charge₁ ‖ … ‖ cadreₙ ‖ chargeₙ)
```

BLAKE3 en mode **hachage simple** : sans clé, sans contexte de dérivation, sortie de 32 octets.

Aucun octet ne suit le sceau. Un lecteur **doit** refuser un flux qui en contient — sans quoi un
conteneur valide suivi de n'importe quoi passerait pour intact.

### Ce que le sceau établit

Il détecte une **troncature** et une **corruption accidentelle** — disque, câble, mémoire —, ainsi
qu'un membre manquant, dupliqué ou réordonné.

Il **ne détecte pas une falsification** : il n'est pas authentifié par une clé, et quiconque réécrit
un conteneur peut le recalculer.

L'authenticité du contenu est celle du format de vault — les tags AEAD de
[`format.md`](./format.md) —, et elle ne s'établit qu'au **déverrouillage**, avec la passphrase. Un
dépaquetage n'en dispose pas.

Ce paragraphe est normatif au même titre que les autres : une implémentation qui présenterait un
sceau vert comme une garantie d'intégrité au sens fort tromperait son utilisateur.

Trois portées distinctes, et il faut les trois pour couvrir le trajet d'un vault :

| Portée | Établie par | À quel moment |
|---|---|---|
| Complétude de ce qui est arrivé | le sceau | au dépaquetage, sans passphrase |
| Intégrité du canal | le transport employé | pendant le transfert |
| Authenticité du contenu | les tags AEAD du vault | au premier déverrouillage |

---

## 6. Procédure de lecture, pas à pas

Ce que fait une implémentation tierce qui ne dispose que de ce document.

```text
 1. Lire l'en-tête. Vérifier magic et container_version.
 2. Vérifier vault_format_version contre ce qu'on sait lire.
 3. Vérifier member_count ≥ 2.
 4. Initialiser un BLAKE3 et y absorber les octets de l'en-tête.
 5. Répéter member_count fois :
      a. Lire un cadre. L'absorber dans le BLAKE3.
      b. Vérifier kind, la présence ou l'absence de id, et les bornes de length.
      c. Vérifier l'ordre : header, puis index, puis blob par id strictement croissant.
      d. Lire length octets. Les absorber dans le BLAKE3.
      e. Les écrire au bon endroit :
           header → <sortie>/header
           index  → <sortie>/index
           blob   → <sortie>/objects/<id en hexadécimal minuscule>
 6. Lire le sceau. Vérifier end, member_count, et digest contre le BLAKE3 calculé.
 7. Vérifier qu'aucun octet ne suit.
 8. Le répertoire produit est un vault. Le lire selon format.md.
```

L'étape 8 est le contrat tout entier : **il n'y a rien de plus à savoir.**

Une implémentation qui **écrit** un vault applique en outre la §6.4 de [`format.md`](./format.md) :
la date de modification des blobs est ramenée à l'époque Unix. Le fichier support du verrou
(`.lock`) n'appartient pas au format et n'est ni transporté ni recréé.

---

## 7. Vecteurs de test

Le conteneur de référence est conservé dans
`crates/vault-core/tests/fixtures/container-v1/container.vaultx`. Il a été produit depuis le vault
de référence de format 1, lui-même figé dans `crates/vault-core/tests/fixtures/v1/`.

**Il ne sera jamais régénéré**, y compris lorsqu'un écart est constaté. Un écart signale soit une
erreur de ce document, soit une erreur du logiciel, et il faut établir laquelle avant de poursuivre.
C'est ce qui fait de la compatibilité ascendante une vérification plutôt qu'une déclaration.

| Grandeur | Valeur |
|---|---|
| Taille du conteneur | 85 132 octets |
| `container_version` | 1 |
| `vault_format_version` | 1 | 
| `member_count` | 6 — un `header`, un `index`, quatre `blob` |
| `payload_bytes` | 84 686 |
| BLAKE3 du **conteneur entier** | `72125c7136c7e21f205287bc1ed27864a96f9b7fd1edbd133c88d03e47c366c4` |
| Décalage du sceau | 85 063 |
| Longueur du sceau | 69 octets |

Le sceau, en toutes lettres :

```text
a3 63 65 6e 64 48 5641554c54454e44 6c 6d656d6265725f636f756e74 06
66 646967657374 5820
e0e786ffc08430169660432e78ee12071115873e85d44af3a72dac86e13715ef
```

soit, champ par champ :

| Octets | Signification |
|---|---|
| `a3` | carte de 3 paires |
| `63 656e64` | clé `end` |
| `48 5641554c54454e44` | chaîne de 8 octets, `VAULTEND` |
| `6c 6d656d6265725f636f756e74` | clé `member_count` |
| `06` | entier 6 |
| `66 646967657374` | clé `digest` |
| `5820 e0e7…15ef` | chaîne de 32 octets, le BLAKE3 du corps |

Et l'on doit vérifier :

```text
BLAKE3(container.vaultx[0 .. 85063]) = e0e786ffc08430169660432e78ee12071115873e85d44af3a72dac86e13715ef
```

Un vault produit par dépaquetage de ce conteneur est **identique octet pour octet** au vault de
référence de `tests/fixtures/v1/`, `.lock` excepté — qui n'appartient pas au format. Sa passphrase
est celle du vault de référence, publiée par [`format.md`](./format.md) §7 bis :
`vault fixture v1 passphrase de reference`.

---

## 8. Évolution

- Toute version future de vault **doit** lire tous les `container_version` antérieurs.
- Un changement de disposition incrémente `container_version` et **doit** être accompagné, dans le
  **même commit**, de la mise à jour de ce document.
- `container_version` et `vault_format_version` évoluent **indépendamment**.
- Chaque version de format de conteneur publiée conserve son conteneur de référence dans le dépôt,
  et tous sont relus à chaque exécution de la suite.

---

## 9. Ce que ce format ne contient pas

Énoncé ici pour que l'absence soit lisible, et non découverte.

- **Le fichier `.lock`** — il décrit l'état d'exécution d'un poste, pas le contenu d'un vault.
- **Rien qui vienne de l'extérieur du vault** : ni nom de machine, ni chemin d'origine, ni
  horodatage de production, ni version du logiciel qui l'a produit. Trois raisons, dans cet ordre :
  ce sont des métadonnées sur l'utilisateur ; elles casseraient le déterminisme ; et aucune n'est
  nécessaire à la lecture, ce que le principe IV interdit d'ajouter.
- **Aucune marque d'origine dans le vault reconstitué.** Un vault produit par dépaquetage est
  **indiscernable** d'un vault créé sur place. C'est une propriété, pas un oubli.
