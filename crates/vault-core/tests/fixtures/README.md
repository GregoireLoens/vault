# Vaults de référence

Un vault figé par version de format publiée. Ils servent SC-008 : **100 % des vaults créés par une
version donnée restent ouvrables par les versions ultérieures.** `compat.rs` les ouvre, en vérifie
le contenu octet pour octet, et échouera le jour où une évolution du format cesserait de savoir
les lire.

## La règle

**Un vault de référence n'est jamais régénéré.** Jamais. C'est toute sa valeur : il a été produit
par une version du logiciel qui n'existe plus, avec un code que personne ne peut plus modifier
rétroactivement. Le régénérer avec le logiciel d'aujourd'hui ne prouverait plus qu'une chose —
qu'il sait lire ce qu'il vient d'écrire.

Si un test de compatibilité échoue, c'est **le logiciel** qu'il faut corriger, pas la référence.
Le principe IV l'exige : toute version future doit savoir lire tous les formats antérieurs.

Une nouvelle version de format s'accompagne d'un **nouveau** répertoire — `v2/`, `v3/` — ajouté à
côté des précédents, jamais à leur place.

## `v1/`

Produit le 2026-08-08 par le logiciel en `v0.3.0`, format sur disque **1**.

| | |
|---|---|
| Passphrase | `vault fixture v1 passphrase de reference` |
| Argon2id | 64 Kio, 1 passe, 1 fil |
| Entrées | 5 — trois fichiers, un dossier, un sous-fichier |

Les paramètres de dérivation sont **délibérément minimaux**, et cela ne dit rien de ceux qu'un
vault réel devrait employer : la référence est ouverte par chaque exécution de la suite, et des
paramètres réalistes y ajouteraient une seconde à chaque fois pour ne rien prouver de plus. La
passphrase est publique pour la même raison — ce vault ne protège rien.

Contenu, **défini exactement** — c'est cette définition, et non le logiciel, qui fait autorité :

| Chemin | Taille | Contenu |
|---|---|---|
| `lisez-moi.txt` | 67 o | `Vault de référence, format 1.\nCe fichier ne doit jamais changer.\n`, encodé en UTF-8 |
| `vide.bin` | 0 o | vide |
| `photos/` | — | dossier |
| `photos/été.jpg` | 256 o | les octets de `0x00` à `0xff`, dans l'ordre |
| `photos/grand.bin` | 70 000 o | l'octet d'indice `i` vaut `i modulo 251` — au-delà d'un morceau STREAM |

Le nom `photos/été.jpg` s'écrit en UTF-8, forme **composée** : `été` y fait sept octets.

> **Pourquoi cette table est précise à l'octet près.** Elle décrivait naguère « un texte accentué,
> deux lignes », ce qui suffit à un lecteur mais **pas à reconstituer le contenu**. Or c'est
> exactement ce qu'exige un tiers qui veut vérifier par lui-même, et ce dont
> `verification/dechiffreur/attendu.json` est dérivé. Un contenu attendu qu'on ne pourrait
> obtenir qu'en exécutant le logiciel ne prouverait plus rien : il faudrait croire le logiciel sur
> parole pour vérifier le logiciel.

Le fichier `.lock` n'y figure pas : il ne fait pas partie du format, et il est recréé à
l'ouverture. `compat.rs` copie d'ailleurs la référence dans un répertoire temporaire avant de
l'ouvrir, pour qu'aucune exécution de la suite ne puisse modifier ce qui est versionné.
