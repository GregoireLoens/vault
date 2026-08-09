# Déchiffreur indépendant

Une implémentation de **lecture** du format de vault, écrite depuis le seul
[`docs/format.md`](../../docs/format.md).

Elle n'est pas un produit. Elle ne chiffre rien, ne modifie jamais un vault, et ne couvre que ce
qu'il faut pour lire. Son unique raison d'être est d'**éprouver le document**.

## Pourquoi

Le principe IV de la constitution du projet exige qu'un vault reste « déchiffrable à partir de sa
seule spécification et d'outils cryptographiques standard, sans exécuter vault ».

Rien ne le vérifiait. La suite de compatibilité, `crates/vault-core/tests/compat.rs`, déchiffre le
vault de référence **avec le code qui l'a écrit** : elle prouve la non-régression, pas la
suffisance du document. Un logiciel qui lit et écrit avec le même code ne peut détecter aucune
erreur de *description* — si `docs/format.md` décrit mal la construction du nonce, tous ses tests
passent quand même.

D'où ce programme, écrit en Python avec des primitives génériques — libsodium pour l'AEAD, la
bibliothèque de référence Argon2, celle de BLAKE3. Il ne partage rien avec le logiciel hormis les
mathématiques.

## La règle

> **Ce programme s'écrit sans consulter le code Rust. Sa seule source est `docs/format.md`.**

Cette règle ne se vérifie pas mécaniquement. Elle tient à la discipline de qui écrit, et la
trahir viderait l'exercice de tout son sens **sans que rien ne le signale** : un déchiffreur écrit
en regardant le code passerait, et le document pourrait rester faux.

Corollaire, tout aussi important :

> **Un échec est un défaut du document, jamais un défaut du déchiffreur.**

La correction se fait dans `docs/format.md`. Ni ce programme ni le vault de référence ne sont
ajustés pour faire disparaître un écart — ce serait supprimer le témoin plutôt que le défaut. Le
vault de référence n'est **jamais** régénéré.

Si un écart révèle une divergence entre le document et le **comportement réel** du logiciel — et
non une imprécision de rédaction — c'est alors le code qui peut être en cause, et cela s'instruit
séparément.

## Ce qu'un échec désigne

| Étape en défaut | Ce qui est mal décrit |
|---|---|
| Lecture de l'en-tête | La disposition CBOR, les noms ou les types de champs |
| Dérivation de la clé d'enveloppe | Les paramètres Argon2id, la version, la longueur de sortie |
| Désenveloppement de la clé maîtresse | Le contexte public, les données associées, ou leur ordre |
| Déchiffrement de l'index | La place du nonce, les données associées, l'encodage |
| Dérivation d'une clé de blob | Le contexte de dérivation ou la matière absorbée |
| Authentification d'un morceau | **La construction du nonce STREAM** — le cas le plus probable |
| Contenu différent d'un octet | Le remplissage, la longueur, ou le découpage en morceaux |
| Nom ou arborescence différents | L'encodage des chemins |

## Usage

```bash
./scripts/dev.sh verifier-format
```

Ou directement, dans le conteneur :

```bash
echo "<passphrase>" | /opt/verification/bin/python verification/dechiffreur/dechiffrer.py \
    crates/vault-core/tests/fixtures/v1 /tmp/restitue
/opt/verification/bin/python verification/dechiffreur/verifier.py \
    verification/dechiffreur/attendu.json /tmp/restitue
```

## Ce que cet exercice ne prouve pas

- **Pas la conception cryptographique.** Un déchiffreur qui restitue le contenu établit que le
  document décrit fidèlement ce que le code fait. Il ne dit rien de la question de savoir si ce
  que le code fait est une bonne idée.
- **Pas une vérification par un tiers.** Écrit par l'auteur du logiciel, il n'est pas indépendant
  au sens fort. Il valide la **suffisance du document**, ce qui est déjà ce qu'aucun test du
  logiciel ne peut faire — et il réduit d'autant le périmètre d'une relecture externe.
