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

Contenu, tel que `compat.rs` le vérifie :

| Chemin | Contenu |
|---|---|
| `lisez-moi.txt` | texte accentué, 2 lignes |
| `vide.bin` | 0 octet |
| `photos/` | dossier |
| `photos/été.jpg` | les 256 octets de `0x00` à `0xff` |
| `photos/grand.bin` | 70 000 octets, `index % 251` — au-delà d'un morceau STREAM |

Le fichier `.lock` n'y figure pas : il ne fait pas partie du format, et il est recréé à
l'ouverture. `compat.rs` copie d'ailleurs la référence dans un répertoire temporaire avant de
l'ouvrir, pour qu'aucune exécution de la suite ne puisse modifier ce qui est versionné.
