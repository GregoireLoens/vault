# Politique de sécurité

vault chiffre des données que leur propriétaire ne peut pas récupérer autrement. Une faille y a des
conséquences qu'aucun correctif ultérieur ne répare : des données lues par qui ne devait pas les
lire, ou perdues. Ce document dit comment nous prévenir, sous quels délais nous répondons, et ce
qui relève ou non de cette politique.

## Signaler une faille

**N'ouvrez pas d'issue publique.** Une faille décrite publiquement avant d'être corrigée met en
danger tous ceux qui utilisent le logiciel entre-temps.

Passez par les **avis de sécurité privés** du dépôt :

> Onglet **Security** → **Report a vulnerability**

Le canal est chiffré de bout en bout, ne demande aucun outil supplémentaire, et se trouve là où le
code vit.

## Ce à quoi nous nous engageons

| | |
|---|---|
| Accusé de réception | **7 jours** |
| Divulgation coordonnée | **90 jours** à compter du signalement |

Le délai de quatre-vingt-dix jours peut être raccourci d'un commun accord si un correctif est
disponible plus tôt.

**Ces délais engagent le mainteneur, et lui seul.** Vous restez libre de publier quand vous
l'entendez : une politique de divulgation n'est pas un contrat qu'on impose à qui rend service.

Ce qui vous sera dit : si le signalement est retenu, ce qui en est compris, et quand un correctif
est prévu. Le projet n'a **aucun programme de récompense** — il n'a aucun revenu.

## Versions concernées

La dernière version publiée. Le projet n'a qu'un mainteneur ; il ne maintient pas de branches de
support parallèles.

Le **format sur disque** est stable depuis `v1.0.0` : un correctif de sécurité ne rendra pas vos
vaults illisibles.

## Ce qui n'est pas une faille au sens de ce projet

Ce n'est pas une manière de se dérober. C'est ce que le modèle de menace place hors périmètre
depuis le premier commit, et le dire d'avance vous évite d'y passer du temps.

- **Un poste déjà compromis** au moment de l'utilisation : enregistreur de frappe, extraction
  mémoire, logiciel malveillant disposant de vos privilèges. Aucun logiciel de chiffrement ne
  protège une machine dont l'attaquant est déjà maître.
- **La contrainte** physique ou légale exercée sur le porteur de la passphrase.
- **Les canaux auxiliaires matériels** et l'analyse de consommation.
- **L'écriture de la mémoire du processus dans le fichier d'échange** ou l'image d'hibernation par
  le système d'exploitation.
- **Un ordinateur quantique** cryptographiquement pertinent.
- **Les fuites résiduelles déjà documentées** : le nombre de blobs, une fourchette de taille à
  10 %, la date de dernière modification du vault, les paramètres de dérivation. Elles sont
  décrites dans le [README](README.md) et dans [`docs/format.md`](docs/format.md).
- **La perte de la passphrase.** Elle est définitive **par conception**. Il n'existe ni question
  de secours, ni réinitialisation, ni clé de secours, et il n'en existera pas.

En revanche, tout ce qui suit **est** une faille, et nous intéresse au premier chef : un
déchiffrement possible sans la passphrase, une altération non détectée, une fuite de contenu ou de
nom hors du vault, un refus qui ne serait pas explicite, une divergence entre
[`docs/format.md`](docs/format.md) et le comportement réel.

## Ce que ce projet a déjà vérifié — et ce qu'il n'a pas vérifié

Avant de chercher, vous voudrez peut-être savoir ce qui est déjà couvert :
[`docs/verifications.md`](docs/verifications.md) recense les vérifications menées, leur étendue, et
**ce qu'elles n'établissent pas**.

Le point le plus important y figure aussi ici : **vault n'a fait l'objet d'aucun audit externe.**
La conception cryptographique n'a été relue par personne d'autre que son auteur. C'est la
principale limite de ce projet, et signaler quelque chose de ce côté-là serait particulièrement
utile.
