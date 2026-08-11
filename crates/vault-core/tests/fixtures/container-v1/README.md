# Conteneur de référence — format de conteneur 1

`container.vaultx` est le conteneur d'export de référence pour la **version 1 du format de
conteneur**, spécifié par [`docs/conteneur.md`](../../../../../docs/conteneur.md).

## Il ne sera jamais régénéré

C'est la règle qui donne sa valeur à ce fichier, et elle ne souffre aucune exception — **y compris
lorsqu'un écart est constaté.**

Un conteneur que le logiciel d'aujourd'hui régénérerait ne prouverait rien : seulement qu'il sait
relire ce qu'il vient d'écrire, ce que `tests/container.rs` établit déjà. La preuve de
compatibilité ascendante demande un fichier que le logiciel d'aujourd'hui **n'a pas produit**, et
qu'il ne peut pas corriger rétroactivement.

Quand `compat.rs` ou la porte 7 échouent sur ce fichier, l'écart signale **soit une erreur du
document, soit une erreur du logiciel**. Il faut établir laquelle avant de poursuivre. Ce qu'il ne
faut pas faire, c'est régénérer le conteneur : cela ferait disparaître la question au lieu d'y
répondre.

## D'où il vient

Produit une fois, le 2026-08-11, par un export en mode par défaut du vault de référence figé dans
[`../v1/`](../v1) — dont le contenu est défini à l'octet près par [`../README.md`](../README.md).

L'export en mode par défaut recopie l'enveloppe du vault source telle quelle et trie les blobs par
identifiant : il est **déterministe**. Ce fichier est donc reproductible à l'octet près tant que le
format ne change pas — ce qui est exactement ce que la porte de compatibilité vérifie.

Sa passphrase est celle du vault de référence, publique parce que ce vault ne protège rien :
`vault fixture v1 passphrase de reference`.

## Ce qui le vérifie

| Vérification | Où |
|---|---|
| Les vecteurs publiés dans `docs/conteneur.md` §7 sont ceux du fichier | `tests/compat.rs` |
| Le dépaquetage redonne le vault de référence octet pour octet | `tests/compat.rs` |
| Un dépaqueteur écrit depuis le **seul document** le lit | porte 7, `verification/dechiffreur/conteneur.py` |

La dernière est la plus exigeante : elle n'exécute aucune ligne de Rust, et un document inexact ou
incomplet la fait échouer.
