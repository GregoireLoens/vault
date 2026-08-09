<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/vault-lockup.svg">
  <img src="docs/assets/vault-lockup-noir.svg" alt="Noyau Vault" width="380">
</picture>

**Un coffre-fort de fichiers, local et chiffré de bout en bout.**

</div>

Vous déposez des fichiers dans un vault, vous les ressortez identiques. Entre les deux, rien n'est
lisible sans la passphrase : ni le contenu, ni les noms de fichiers, ni l'arborescence, ni les
tailles exactes.

vault ne parle à aucun serveur. Pas de compte, pas d'activation, pas de télémétrie. Si tous les
serveurs du monde disparaissaient demain, il fonctionnerait exactement pareil.

## Avant de lui confier quoi que ce soit

Deux choses à savoir, et autant les dire tout de suite.

**Personne n'a audité cette cryptographie.** Ne mettez pas dans un vault des données dont vous
n'avez pas de copie ailleurs. La version 1.0.0 signifie que ce qui était annoncé est livré et que
le format sur disque ne bougera plus : vos vaults resteront lisibles par les versions suivantes.
Elle ne signifie pas qu'un tiers est passé derrière moi. Ce sont deux garanties différentes, et la
seconde manque encore.

**Si vous perdez la passphrase, c'est terminé.** Pas de question de secours, pas de
réinitialisation, pas de clé de secours, et aucun moyen pour moi de vous dépanner. Ce n'est pas un
oubli, c'est la contrepartie directe de la garantie.

### Ce qui marche aujourd'hui

| Commande | |
|---|---|
| `vault create` | Créer un vault |
| `vault add` | Y déposer fichiers et dossiers |
| `vault ls` | Lister le contenu |
| `vault extract` | Ressortir le contenu, octet pour octet |
| `vault rm` | Retirer une entrée, définitivement |
| `vault passwd` | Changer la passphrase, sans réécrire le contenu |
| `vault info` | Lire les paramètres publics, sans déverrouiller |

Reste à faire : l'export et le transfert entre postes. Prévus, pas encore commencés.

## Ce qui est protégé, et ce qui ne l'est pas

Des garanties dont on ne dit pas où elles s'arrêtent ne valent pas grand-chose. Voici où celles-ci
s'arrêtent.

### Protégé

- Le vol ou la perte du support : disque, poste, clé USB, sauvegarde.
- L'accès en lecture au système de fichiers par un autre utilisateur, ou par un processus tiers qui
  n'a pas la passphrase.
- L'altération : modifier un seul octet est détecté et provoque un échec explicite. Jamais un
  déchiffrement partiel présenté comme valide.

### Ce qui fuit quand même

Quelqu'un qui accède au répertoire d'un vault verrouillé, sans la passphrase, apprend ceci :

| Ce qu'il apprend | Précision | Atténuation |
|---|---|---|
| Le nombre de blobs | Le nombre approximatif de fichiers | Aucune à ce jour |
| La taille de chaque blob | Une fourchette large de 10 % | Remplissage par paliers géométriques |
| La date de dernière modification du vault | Quand il a servi pour la dernière fois | Aucune : réécrire l'index est ce qui rend le vault utilisable |
| Les paramètres de dérivation | Le coût d'une attaque par force brute | Publics par conception |

Il n'apprend ni les noms de fichiers, ni l'arborescence, ni les tailles exactes, ni le contenu, ni
si deux fichiers du vault sont identiques, ni dans quel ordre ils ont été déposés. Les dates des
blobs sont toutes ramenées à la même valeur, sans quoi trier le répertoire par date suffirait à
reconstituer la chronologie du vault.

### Hors de portée

- Un poste déjà compromis au moment où vous vous en servez : enregistreur de frappe, extraction
  mémoire, logiciel malveillant qui tourne avec vos privilèges.
- La contrainte physique ou légale exercée sur celui qui connaît la passphrase.
- Les canaux auxiliaires matériels et l'analyse de consommation.
- La mémoire du processus écrite dans le fichier d'échange ou l'image d'hibernation par le système.
- Un ordinateur quantique cryptographiquement pertinent.

## La cryptographie

Je n'ai écrit aucune primitive. vault assemble celles de bibliothèques maintenues et largement
déployées.

| Rôle | Algorithme |
|---|---|
| Dérivation depuis la passphrase | Argon2id — 128 MiB, 3 passes, parallélisme 4 par défaut |
| Chiffrement authentifié | XChaCha20-Poly1305 |
| Chiffrement du contenu | Construction STREAM (BE32), morceaux de 64 KiB |
| Dérivation des clés par blob | BLAKE3 en mode `derive_key` |
| Aléa | CSPRNG du système d'exploitation, exclusivement |

La passphrase ne chiffre jamais le contenu directement. Elle dérive une clé d'enveloppe, qui ne
protège qu'une clé maîtresse tirée au hasard. C'est cette indirection qui rend le changement de
passphrase instantané, quelle que soit la taille du vault.

[`docs/format.md`](docs/format.md) décrit le format en entier, avec la procédure de déchiffrement
pas à pas. C'est une exigence que je me suis fixée : un vault doit rester déchiffrable dans dix
ans à partir de cette seule spécification et d'outils cryptographiques standard, sans exécuter
vault.

## Construire

Rien ne s'installe sur votre machine. La chaîne d'outils Rust vit dans un conteneur Docker
construit depuis le `Dockerfile` du dépôt, à version figée.

```bash
./scripts/dev.sh build          # construit l'image, une fois
./scripts/dev.sh fetch          # récupère les dépendances — seule commande avec réseau
./scripts/dev.sh cargo build --release
```

Toutes les autres commandes tournent sans accès réseau, et pas seulement parce que c'est écrit
quelque part : le conteneur n'a matériellement pas d'interface.

Les sept portes de qualité, toutes bloquantes :

```bash
./scripts/dev.sh cargo fmt --all --check
./scripts/dev.sh cargo clippy --workspace --all-targets --all-features
./scripts/dev.sh env RUSTFLAGS=-Dwarnings cargo build --workspace --all-targets
./scripts/dev.sh cargo test --workspace --all-targets
./scripts/dev.sh coverage         # couverture de lignes, seuil bloquant à 100 %
./scripts/dev.sh deny             # aucune dépendance réseau, même transitive
./scripts/dev.sh verifier-format  # le déchiffreur indépendant sur le vault de référence
```

S'y ajoute une porte de livraison, de portée plus étroite : elle ne bloque que les pull requests
`release/vX.Y.Z` et vérifie que les numéros de version suivent la livraison préparée.

```bash
./scripts/verifier-version.sh 1.1.0   # bash seul, aucune chaîne d'outils
```

## S'en servir

```console
$ vault create ~/mon-vault
Passphrase :
Confirmez la passphrase :
Robustesse : bonne

  ⚠  Si vous perdez cette passphrase, vos données seront définitivement
     perdues. Il n'existe aucun moyen de les récupérer : ni question de
     secours, ni réinitialisation, ni assistance possible.

Tapez OUI pour confirmer que vous avez compris : OUI
Vault créé : /home/vous/mon-vault
```

```console
$ vault add ~/documents/impots-2025.pdf --vault ~/mon-vault
Passphrase :
  ⚠  L'original a été supprimé, mais des traces peuvent subsister sur ce
     support : ni un disque à mémoire flash, ni un système de fichiers à copie
     sur écriture ne garantissent qu'une réécriture atteigne l'emplacement
     d'origine.
1 fichier(s) ajouté(s), 2.4 Mo.
```

`--move` est le comportement par défaut : l'original est retiré une fois l'ajout vérifié. `--copy`
le conserve, en clair, et vault vous le rappelle.

```console
$ vault ls --vault ~/mon-vault
impots-2025.pdf  2.4 Mo
0 dossier(s), 1 fichier(s), 2.4 Mo

$ vault extract impots-2025.pdf --to ~/sortie --vault ~/mon-vault
1 entrée(s) extraite(s) vers /home/vous/sortie.

$ vault rm impots-2025.pdf --vault ~/mon-vault
Passphrase :
La suppression est définitive : il n'existe ni corbeille, ni annulation, ni récupération.
Supprimer 1 entrée(s) ? [o/N] : o
1 entrée(s) supprimée(s).
```

`--recursive` est obligatoire pour un dossier non vide : un dossier ne part pas par mégarde. La
suppression réécrit l'index d'abord et ne délie les blobs qu'ensuite, de sorte qu'une interruption
laisse des déchets inertes plutôt qu'un index désignant un contenu absent.

```console
$ vault passwd --vault ~/mon-vault
Passphrase :
Passphrase :
Confirmez la passphrase :
Robustesse : bonne
Passphrase changée.
L'opération est immédiate et ne réécrit pas le contenu : seule la clé qui protège le vault a
été réenveloppée. Vos fichiers n'ont pas été touchés.
```

Cette rapidité est normale, et vault le dit pour qu'elle n'inquiète pas. La clé qui chiffre votre
contenu est tirée au hasard à la création et n'est jamais dérivée de la passphrase ; celle-ci ne
sert qu'à l'envelopper. Changer de passphrase réenveloppe trente-deux octets, donc un vault de
quatre cents gigaoctets s'y prête aussi vite qu'un vault vide, sans relire ni réécrire le contenu.
Si l'opération est interrompue, le vault s'ouvre avec l'ancienne passphrase ou avec la nouvelle,
jamais avec aucune.

`vault info` est la seule commande qui ne demande rien : tout ce qu'elle affiche vient de
l'en-tête, qui est en clair par conception. Elle ne dit donc ni ce que le vault contient, ni
combien il en contient, puisque le savoir exigerait de le déverrouiller.

```console
$ vault info --vault ~/mon-vault
Version du format   : 1
Dérivation de clé   : argon2id
  mémoire           : 131072 Kio (128 Mio)
  passes            : 3
  parallélisme      : 4
Chiffrement         : xchacha20poly1305
```

La passphrase se saisit toujours en masqué sur le terminal, et n'est jamais acceptée en argument :
elle finirait dans l'historique du shell et dans la table des processus.

`--json` produit une sortie lisible par une machine. `--quiet` supprime la progression, sans
jamais faire taire les avertissements.

### Codes de retour

| Code | Signification |
|---|---|
| 0 | Succès |
| 1 | Erreur générique |
| 2 | Usage invalide, ou saisie nécessaire sur un terminal non interactif |
| 3 | Échec d'authentification — passphrase erronée **ou** vault altéré, indifféremment |
| 4 | Vault déjà ouvert par une autre instance |
| 5 | Vault ou entrée introuvable |
| 6 | Espace disque insuffisant |
| 7 | Version de format non gérée |

Le code 3 et son message sont identiques que la passphrase soit fausse ou que le vault ait été
altéré. C'est voulu : distinguer les deux renseignerait un attaquant sur ce qu'il a déjà réussi.

## Les deux numéros de version

Il y en a deux, et ils ne disent pas la même chose.

**La version du logiciel** suit le versionnement sémantique, et chaque livraison est marquée par
un tag `vX.Y.Z` sur `main`.

- `0.x.y` — développement. Incomplet, non audité.
- Mineure (`0.1.0` → `0.2.0`) — une user story livrée, un ajout de fonctionnalité, ou de nouvelles
  garanties. Ça ne veut pas toujours dire du code visible à l'usage : `v1.1.0` n'ajoute aucune
  commande, seulement de quoi vérifier les promesses des versions précédentes.
- Correctif (`0.1.0` → `0.1.1`) — corrections, sans nouvelle fonctionnalité.
- `1.0.0` — le périmètre de la première feature est complet, le format est tenu pour stable.

**La version du format sur disque** est indépendante et vit dans l'en-tête de chaque vault. Elle
vaut 1 aujourd'hui. Elle ne change que si la disposition sur disque change, et je m'engage à ce
que toute version future de vault sache lire tous les formats antérieurs. Un changement qui
casserait cette lecture serait un changement majeur, avec un chemin de migration documenté.

Autrement dit : passer de `v0.3.0` à `v0.4.0` ne rendra jamais vos vaults illisibles.

Le numéro qu'annonce `vault --version` est vérifié contre celui de la livraison, par une porte
d'intégration et par [`scripts/verifier-version.sh`](scripts/verifier-version.sh). Ce n'est pas
une précaution abstraite : les tags `v0.1.0` à `v0.4.0` ont été posés sur un binaire qui
s'annonçait en `0.1.0`. Savoir quelle version on exécute est le préalable de toute vérification.

| Tag | Contenu |
|---|---|
| `v0.1.0` | Format, cryptographie, et user story 1 — créer, ajouter, lister, extraire |
| `v0.2.0` | Fermer un vault et le rouvrir — détection d'altération, `vault info` |
| `v0.3.0` | Retirer des fichiers — `vault rm` |
| `v0.4.0` | Changer la passphrase — `vault passwd` |
| `v1.0.0` | Périmètre complet, format 1 tenu pour stable |
| `v1.1.0` | Vérifiabilité externe — aucune fonctionnalité nouvelle, des garanties contrôlables par un tiers. Première livraison signée |

## Ce que vous pouvez vérifier vous-même

Je préfère que vous n'ayez pas à me croire sur parole. Voici ce qui se contrôle sans moi.

**Le format se suffit à lui-même.** Un déchiffreur écrit depuis le seul
[`docs/format.md`](docs/format.md), dans un autre langage et avec des bibliothèques
cryptographiques courantes, restitue le contenu d'un vault octet pour octet. Il vit dans
[`verification/dechiffreur/`](verification/dechiffreur/) et tourne à chaque intégration. La
spécification publie aussi des vecteurs de test, c'est-à-dire les valeurs intermédiaires de la
chaîne de dérivation : de quoi situer l'étape exacte où votre propre implémentation divergerait,
sans exécuter vault.

**Le logiciel refuse ce qu'il ne comprend pas.** Chaque intégration rejoue un corpus permanent
d'entrées hostiles sur les quatre surfaces de décodage et vérifie qu'aucune altération ne passe.
L'exploration engendrée et les campagnes guidées qui complétaient ce corpus ont été retirées le
2026-08-09 : ce qui reste rejoue ce qui a déjà compté, et ne découvre plus rien de neuf. L'étendue
exacte de ce qui a été exploré, et ce que cela n'établit pas, est consignée dans
[`docs/verifications.md`](docs/verifications.md).

**Le binaire correspond au code, et la livraison vient bien de moi.**
[`docs/reconstruction.md`](docs/reconstruction.md) donne les deux marches à suivre : reconstruire
et comparer, avec le critère qui distingue une divergence attendue d'une divergence suspecte,
sans quoi constater un écart ne permettrait de conclure ni dans un sens ni dans l'autre ; puis
vérifier la signature du tag en dehors de la forge. Les livraisons sont signées à partir de
`v1.1.0`. Les précédentes ne le sont pas, et le document explique pourquoi.

**Une faille se signale en privé.** Voir [`SECURITY.md`](SECURITY.md) : canal non public, accusé
de réception sous 7 jours, divulgation coordonnée à 90 jours, et la liste de ce qui n'est pas une
faille au sens de ce projet.

### Ce que tout cela ne remplace pas

Aucun tiers n'a relu la conception cryptographique. Ce qui précède établit que le format est
fidèlement décrit et que le logiciel refuse proprement ce qu'il ne comprend pas. Ça ne dit rien de
la question de savoir si les choix de conception sont les bons : le coût Argon2id retenu,
l'absence d'engagement de clé, la construction du nonce. Ça demande d'autres yeux que les miens,
et ça manque.

## Comment le projet est tenu

vault suit une constitution de huit principes non négociables. Trois se voient de l'extérieur.

**Aucune cryptographie maison.** Les primitives viennent de bibliothèques auditées ; le projet les
assemble et n'en écrit aucune.

**Le format est auto-descriptif.** Tout ce qui est nécessaire au déchiffrement figure en clair
dans l'en-tête. Aucun paramètre n'est codé en dur dans le logiciel.

**Aucune régression non détectée.** Sept portes bloquent chaque fusion : formatage, analyse
statique sans le moindre avertissement, compilation sans avertissement, tests, couverture de
lignes à 100 %, absence de dépendance réseau y compris transitive et vérifiée mécaniquement, et le
déchiffreur indépendant, qui échoue si la spécification du format ne suffit plus à lire un vault.

Les tests portent les garanties de sécurité plutôt que de les affirmer : une suite vérifie
qu'aucun octet reconnaissable des données d'entrée n'apparaît sur le disque après une session
représentative, une autre qu'une altération est toujours détectée, une troisième qu'une
interruption à n'importe quel point d'écriture laisse le vault ouvrable et son contenu antérieur
intact.

## Licence

[Apache-2.0](LICENSE).
