# vault

Un coffre-fort de fichiers **local** et **chiffré de bout en bout**. Vous y déposez des fichiers,
ils en ressortent identiques, et rien de ce qu'ils contiennent — ni leur contenu, ni leur nom, ni
l'arborescence, ni leur taille exacte — n'est lisible sans la passphrase.

vault ne parle à aucun serveur. Il n'a ni compte, ni activation, ni télémétrie. Il reste
pleinement fonctionnel si tous les serveurs du monde disparaissent.

---

## ⚠ État du projet — à lire avant de confier quoi que ce soit

**vault n'a fait l'objet d'aucun audit externe. Ne lui confiez pas de données dont vous n'avez pas
de copie ailleurs.**

La version `1.0.0` dit que le périmètre annoncé est complet et que **le format sur disque est tenu
pour stable** — vos vaults resteront lisibles par les versions suivantes. Elle ne dit rien de
plus, et surtout pas qu'un tiers a relu cette cryptographie. Ce sont deux garanties différentes,
et la seconde manque encore.

Ce n'est pas une formule de prudence : la perte de la passphrase est **définitive et par
conception**. Il n'existe ni question de secours, ni réinitialisation, ni clé de secours, ni
moyen pour l'auteur de vous aider. C'est le prix de la garantie, et il est annoncé franchement
plutôt que contourné.

Ce qui fonctionne aujourd'hui :

| | |
|---|---|
| ✅ `vault create` | Créer un vault |
| ✅ `vault add` | Y déposer fichiers et dossiers |
| ✅ `vault ls` | Lister le contenu |
| ✅ `vault extract` | Ressortir le contenu, octet pour octet |
| ✅ `vault rm` | Retirer une entrée, définitivement |
| ✅ `vault passwd` | Changer la passphrase, sans réécrire le contenu |
| ✅ `vault info` | Paramètres publics du vault, sans le déverrouiller |
| ✅ `vault export` | Sortir le vault en un fichier unique, portable |
| ✅ `vault import` | Le remettre, octet pour octet |
| ✅ `vault send` | L'envoyer vers un autre poste, par ssh |
| ✅ `vault fetch` | Le rapatrier depuis un autre poste |

---

## Ce que vault protège, et ce qu'il ne protège pas

Un logiciel de chiffrement qui ne dit pas où s'arrêtent ses garanties est un logiciel qui ment.

### Protégé

- Le **vol ou la perte** du support : disque, poste, clé USB, sauvegarde.
- L'**accès en lecture** au système de fichiers par un autre utilisateur ou un processus tiers qui
  n'a pas la passphrase.
- L'**altération** du vault : toute modification d'un octet est détectée et provoque un échec
  explicite, jamais un déchiffrement partiel présenté comme valide.

### Fuites résiduelles, assumées et documentées

Un observateur qui accède au répertoire d'un vault **verrouillé** — ou à un **conteneur
d'export**, qui n'en révèle ni plus ni moins —, sans la passphrase, apprend :

| Ce qu'il apprend | Précision | Atténuation |
|---|---|---|
| Le nombre de blobs | Le nombre approximatif de fichiers | Aucune à ce jour |
| La taille de chaque blob | Une fourchette large de 10 % | Remplissage par paliers géométriques |
| La date de dernière modification du vault | Quand il a servi pour la dernière fois | Aucune : réécrire l'index est ce qui rend le vault utilisable |
| Les paramètres de dérivation | Le coût d'une attaque par force brute | Publics par conception |

Il n'apprend **ni** les noms de fichiers, **ni** l'arborescence, **ni** les tailles exactes,
**ni** le contenu, **ni** si deux fichiers du vault sont identiques, **ni** dans quel ordre ils
ont été déposés — les dates des blobs sont toutes ramenées à la même valeur, faute de quoi trier
le répertoire par date reconstituerait la chronologie du vault.

### Un export n'est pas un partage

**Un conteneur d'export porte la clé maîtresse du vault dont il provient.** Qui l'ouvre peut donc
ouvrir le vault d'origine. C'est une sauvegarde ou un déplacement — jamais un moyen de confier un
contenu à quelqu'un sans lui confier tout le coffre.

Choisir une passphrase distincte pour le conteneur n'y change **rien** : la clé maîtresse
transportée est la même. C'est pourquoi vault le rappelle à chaque export, et pourquoi `--quiet`
ne supprime pas cet avertissement.

Un vrai partage demanderait une clé neuve et un rechiffrement intégral du contenu — un coût
proportionnel au volume, et une fonctionnalité en soi. Elle n'existe pas.

### Ce qu'un transfert protège, et ce qu'il ne protège pas

| | |
|---|---|
| ✅ Le contenu est chiffré **avant** d'entrer dans le canal | ssh est une couche supplémentaire, jamais la seule |
| ✅ Aucun secret ne traverse le canal | Ni passphrase, ni clé maîtresse : un export par défaut n'ouvre pas le vault |
| ✅ L'authentification des deux bouts est celle d'OpenSSH | Vos clés, votre fichier des hôtes connus, vos habitudes |
| ✅ Une interruption ne laisse jamais de vault à moitié écrit | Réception à côté, vérification, puis bascule |
| ❌ vault ne peut pas corriger une configuration ssh affaiblie | Un `StrictHostKeyChecking no` dans votre `~/.ssh/config` désarme la vérification d'hôte sans que vault le sache |
| ❌ Un sceau vert ne signifie pas « authentique » | Il signifie **complet et non corrompu**. L'authenticité vient du déchiffrement, avec la passphrase |

### Hors périmètre

- Un poste **déjà compromis** au moment de l'utilisation : enregistreur de frappe, extraction
  mémoire, logiciel malveillant disposant de vos privilèges.
- La **contrainte** physique ou légale exercée sur le porteur de la passphrase.
- Les **canaux auxiliaires** matériels et l'analyse de consommation.
- L'écriture de la mémoire du processus dans le **fichier d'échange** ou l'image d'hibernation par
  le système d'exploitation.
- Un attaquant disposant d'un **ordinateur quantique** cryptographiquement pertinent.

---

## Cryptographie

vault n'invente aucune primitive. Il assemble celles de bibliothèques maintenues et largement
déployées.

| Rôle | Algorithme |
|---|---|
| Dérivation depuis la passphrase | Argon2id — 128 MiB, 3 passes, parallélisme 4 par défaut |
| Chiffrement authentifié | XChaCha20-Poly1305 |
| Chiffrement du contenu | Construction STREAM (BE32), morceaux de 64 KiB |
| Dérivation des clés par blob | BLAKE3 en mode `derive_key` |
| Aléa | CSPRNG du système d'exploitation, exclusivement |

La passphrase ne chiffre jamais le contenu directement : elle dérive une **clé d'enveloppe** qui
ne protège qu'une clé maîtresse tirée aléatoirement. C'est cette indirection qui rendra le
changement de passphrase instantané, quelle que soit la taille du vault.

**[`docs/format.md`](docs/format.md) décrit le format intégralement**, avec la procédure de
déchiffrement pas à pas. C'est une exigence du projet : un vault doit rester déchiffrable dans dix
ans, à partir de cette seule spécification et d'outils cryptographiques standard, sans exécuter
vault.

**[`docs/conteneur.md`](docs/conteneur.md) fait de même pour le conteneur d'export**, et il est
court : un conteneur **cadre** un vault, il ne le chiffre pas. Aucune primitive, aucune chaîne de
dérivation, aucune donnée associée n'y est ajoutée — dépaqueter un conteneur produit un répertoire
de vault, et rien d'autre.

---

## Construire

**Rien ne s'installe sur votre machine.** La chaîne d'outils Rust vit dans un conteneur Docker
construit depuis le `Dockerfile` du dépôt, à version figée.

```bash
./scripts/dev.sh build          # construit l'image, une fois
./scripts/dev.sh fetch          # récupère les dépendances — seule commande avec réseau
./scripts/dev.sh cargo build --release
```

Toutes les autres commandes s'exécutent **sans accès réseau** : l'interdiction du réseau n'est pas
déclarative, le conteneur n'a matériellement pas d'interface.

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

S'y ajoute la porte de livraison, de portée plus étroite : elle ne bloque que les pull requests
`release/vX.Y.Z`, et vérifie que les numéros de version suivent la livraison préparée.

```bash
./scripts/verifier-version.sh 1.1.0   # bash seul, aucune chaîne d'outils
```

---

## Utiliser

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

`--move` est le **défaut** : l'original est retiré une fois l'ajout vérifié. `--copy` le conserve,
en clair, et vault vous le rappelle.

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

`--recursive` est requis pour un dossier non vide : un dossier ne part pas par mégarde. La
suppression réécrit l'index **d'abord** et ne délie les blobs qu'ensuite — une interruption
laisse ainsi des déchets inertes, jamais un index désignant un contenu absent.

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

La rapidité est normale, et c'est pour cela qu'elle est annoncée. La clé qui chiffre votre
contenu est tirée au hasard à la création et **n'est jamais dérivée de la passphrase** : celle-ci
ne sert qu'à envelopper cette clé. Changer de passphrase réenveloppe trente-deux octets — un vault
de quatre cents gigaoctets s'y prête aussi vite qu'un vault vide, et le contenu n'est ni relu ni
réécrit. Si l'opération est interrompue, le vault s'ouvre avec l'ancienne **ou** avec la nouvelle,
jamais avec aucune.

`vault info` est la seule commande qui ne demande **rien** : tout ce qu'elle affiche vient de
l'en-tête, qui est en clair par conception. Elle ne dit donc ni ce que le vault contient, ni
combien il en contient — le savoir exigerait de le déverrouiller.

```console
$ vault info --vault ~/mon-vault
Version du format   : 1
Dérivation de clé   : argon2id
  mémoire           : 131072 Kio (128 Mio)
  passes            : 3
  parallélisme      : 4
Chiffrement         : xchacha20poly1305
```

La passphrase est **toujours** saisie de manière masquée sur le terminal. Elle n'est jamais
acceptée en argument : elle apparaîtrait dans l'historique du shell et dans la table des
processus.

`--json` produit une sortie lisible par une machine ; `--quiet` supprime la progression sans
jamais faire taire les avertissements.

**Tout le dialogue passe par l'erreur standard** — progression, invites, avertissements, erreurs.
La sortie standard ne porte que ce qu'une machine lit : le rendu `--json`, un listage, et le
conteneur d'export. Sans cette séparation, un tube produirait un conteneur corrompu par la
première ligne de progression.

### Sauvegarder : `export` et `import`

Un **conteneur d'export** est un fichier unique qui porte le vault entier. On le copie comme
n'importe quel fichier — sur un disque externe, sur une sauvegarde hors-ligne, sur une clé USB.

```console
$ vault export --to sauvegarde.vaultx --vault ~/mon-vault

  ⚠  Ce conteneur porte la clé maîtresse de votre vault : qui l'ouvre peut
     aussi ouvrir le vault d'origine. C'est une sauvegarde ou un déplacement,
     pas un moyen de partager avec quelqu'un.

1 vault exporté, 2.4 Mo, 143 blob(s).
```

**Aucune passphrase ne vous est demandée**, et ce n'est pas un raccourci : l'enveloppe du vault
source est recopiée telle quelle, sans jamais être ouverte. La clé maîtresse n'existe donc à aucun
moment en mémoire, et le conteneur s'ouvre avec la passphrase du vault d'origine.

Deux conséquences utiles :

- **Un export est déterministe.** Deux exports d'un vault inchangé donnent des octets identiques :
  vous pouvez comparer une sauvegarde à une autre sans en ouvrir aucune.
- **Un export coûte le prix d'une recopie.** Rien n'est déchiffré ni rechiffré. Un vault de quatre
  cents gigaoctets produit un conteneur de quatre cents gigaoctets, au débit du support.

```console
$ vault import sauvegarde.vaultx --to ~/vault-restaure
Vault reconstitué : /home/vous/vault-restaure — 143 blob(s), sceau vérifié.
```

L'import ne demande rien non plus : il transpose le conteneur sans l'ouvrir. Ce qu'il vérifie —
que **tout** est arrivé et que rien n'a été corrompu — se contrôle sans la passphrase.
`--verify-content` va plus loin et contrôle l'authenticité de chaque fichier ; il demande alors la
passphrase.

Par défaut, une destination déjà occupée par un vault est **refusée**. `--replace` restaure
par-dessus, et **ne supprime jamais** le vault remplacé : il est déplacé à côté, sous un nom qui
dit ce qu'il est, et vault vous annonce où.

Les deux commandes fonctionnent en tube, ce qui permet de monter un transfert à la main :

```console
$ vault export --to - --vault ~/mon-vault | ssh poste-b 'vault import - --to ~/coffres/v'
```

Cette forme donne **exactement** les mêmes vérifications que `vault send` : le sceau vit dans le
conteneur, pas dans la commande. La suite de tests l'établit plutôt que cette phrase ne l'affirme.

### Déplacer d'un poste à l'autre : `send` et `fetch`

Prérequis : un accès ssh qui fonctionne déjà entre les deux postes, et `vault` installé des deux
côtés. **vault n'implémente aucun protocole réseau et n'ouvre aucune socket** : il lance votre
client ssh et lui parle par des tubes.

```console
$ vault send ~/mon-vault poste-b:~/coffres/mon-vault

  ⚠  Ce conteneur porte la clé maîtresse de votre vault : […]

Vérification du poste distant…
2.4 Mo transférés. Vault reçu : poste-b:~/coffres/mon-vault
```

```console
$ vault fetch serveur:~/coffres/mon-vault ~/mon-vault
Vérification du poste distant…
Vault rapatrié : /home/vous/mon-vault — 143 blob(s), sceau vérifié.
```

**Aucune passphrase n'est demandée, dans un sens comme dans l'autre.** Le sens du rapatriement
compte autant que l'autre : c'est celui où votre vault dort sur un serveur que rien ne permet de
joindre en retour.

| Option | Effet |
|---|---|
| `--replace` | Remplace un vault existant à la destination. La confirmation est demandée **avant** que le moindre octet ne parte |
| `--ssh-option <OPT>` | Passée telle quelle à ssh — `-p2222`, `-oControlMaster=auto`, `-J rebond`. Répétable |
| `--remote-command <CMD>` | Commande vault à invoquer à distance. `vault` par défaut |

Trois choses à savoir :

- **Rien ne part avant un sondage.** vault ouvre d'abord une session ssh qui ne fait que
  demander : la destination est-elle libre, et sait-elle lire ce format ? Une destination occupée
  ou un vault distant trop ancien font échouer **avant** le premier octet.
- **Deux authentifications ssh, donc.** Si le prix vous paraît élevé, `ControlMaster` d'OpenSSH le
  ramène à une.
- **Un transfert interrompu recommence depuis le début.** La reprise n'existe pas : elle
  supposerait un dialogue entre les deux vault, que ce projet a refusé d'inventer. Un transfert
  interrompu ne laisse jamais de vault à moitié écrit à la destination — seulement un répertoire
  d'attente, nommé comme tel, dont la suppression est sans conséquence.

Les questions de votre client ssh — confirmation d'empreinte, passphrase de clé, second facteur —
vous parviennent normalement : vault n'intercepte pas sa sortie d'erreur. Un changement d'empreinte
interrompt le transfert, comme il doit.

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
| 7 | Version de format non gérée — de vault ou de conteneur |
| 8 | Destination déjà occupée par un vault |
| 9 | Échec du transport — ssh absent, commande distante introuvable, canal rompu |

Lorsqu'un poste distant refuse pour une autre raison, **son** code de retour est celui qui remonte,
tel quel : vault ne réinterprète pas un verdict qu'il n'a pas rendu, et la cause que la destination
a nommée vous est déjà parvenue par l'erreur standard.

Le code 3 et son message sont **identiques** que la passphrase soit fausse ou que le vault ait été
altéré. C'est délibéré : distinguer les deux renseignerait un attaquant sur ce qu'il a déjà
réussi.

---

## Versions

Deux numéros de version cohabitent, et ils ne disent pas la même chose.

**La version du logiciel** suit le versionnement sémantique, et les livraisons sont marquées par
un tag `vX.Y.Z` sur `main`.

- **`0.x.y`** — développement. Le logiciel est incomplet et n'a pas été audité.
- **Mineure** (`0.1.0` → `0.2.0`) — une user story livrée, un ajout de fonctionnalité, ou un
  ensemble de garanties nouvelles. Une mineure ne suppose pas toujours du code visible à
  l'usage : `v1.1.0` n'ajoute aucune commande, seulement de quoi vérifier les promesses des
  versions précédentes.
- **Correctif** (`0.1.0` → `0.1.1`) — corrections, sans nouvelle fonctionnalité.
- **`1.0.0`** — le périmètre de la première feature est complet et le format est tenu pour stable.

**La version du format sur disque** est indépendante et vit dans l'en-tête de chaque vault. Elle
vaut **1** aujourd'hui. Elle ne change que si la disposition sur disque change, et le projet
s'engage à ce que **toute version future de vault sache lire tous les formats antérieurs**. Un
changement qui casserait cette lecture serait un changement majeur, accompagné d'un chemin de
migration documenté.

Autrement dit : passer de `v0.3.0` à `v0.4.0` ne rend jamais vos vaults illisibles.

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
| `v1.1.0` | Vérifiabilité externe — aucune fonctionnalité nouvelle, des garanties contrôlables par un tiers. **Première livraison signée** |

---

## Vérifiabilité — ce que vous pouvez contrôler vous-même

Un logiciel de chiffrement qui demande qu'on le croie sur parole ne vaut pas mieux qu'une promesse.
Voici ce qui se vérifie sans nous faire confiance.

**Le format se suffit à lui-même.** Un déchiffreur écrit depuis le seul
[`docs/format.md`](docs/format.md), dans un autre langage et avec des bibliothèques
cryptographiques courantes, restitue le contenu d'un vault octet pour octet. Il vit dans
[`verification/dechiffreur/`](verification/dechiffreur/) et tourne à chaque intégration. La
spécification publie en outre des **vecteurs de test** — valeurs intermédiaires de la chaîne de
dérivation — qui vous permettent de situer l'étape exacte où votre propre implémentation
divergerait, sans exécuter vault.

**Le format d'export aussi.** Un conteneur de référence, produit une fois et **jamais régénéré**,
est dépaqueté à chaque intégration par un second programme écrit depuis le seul
[`docs/conteneur.md`](docs/conteneur.md) — puis le vault qui en sort est déchiffré par le premier.
Aucune ligne du logiciel n'intervient dans cette chaîne : un document inexact ou incomplet la fait
échouer.

**Le logiciel refuse ce qu'il ne comprend pas.** Chaque intégration rejoue un corpus permanent
d'entrées hostiles sur les **cinq** surfaces de décodage — l'en-tête, l'index, les chemins, les
blobs, et désormais le conteneur d'export —, et vérifie qu'aucune altération ne passe.
L'exploration engendrée et les campagnes guidées qui complétaient ce corpus **ont été retirées le
2026-08-09** : ce qui subsiste rejoue ce qui a déjà compté, et ne découvre rien de neuf. L'étendue
exacte de ce qui a été exploré — et ce que cela n'établit pas — est consignée dans
[`docs/verifications.md`](docs/verifications.md).

**Le binaire correspond au code, et la livraison vient de son auteur.**
[`docs/reconstruction.md`](docs/reconstruction.md) donne les deux marches à suivre : reconstruire
et comparer — avec le critère qui distingue une divergence attendue d'une divergence suspecte,
sans quoi constater un écart ne permettrait de conclure ni dans un sens ni dans l'autre — puis
vérifier la signature du tag hors de la forge. Les livraisons sont signées **à partir de
`v1.1.0`** ; les précédentes ne le sont pas, et le document dit pourquoi.

**Une faille se signale en privé.** Voir [`SECURITY.md`](SECURITY.md) : canal non public, accusé de
réception sous 7 jours, divulgation coordonnée à 90 jours, et la liste de ce qui **n'est pas** une
faille au sens de ce projet.

### Ce que rien de tout cela ne remplace

**Aucun tiers n'a relu la conception cryptographique.** Les vérifications ci-dessus établissent que
le format est fidèlement décrit et que le logiciel refuse proprement ce qu'il ne comprend pas.
Elles ne disent rien de la question de savoir si les choix de conception sont les bons — le coût
Argon2id retenu, l'absence d'engagement de clé, la construction du nonce. Cela demande d'autres
yeux que les nôtres, et cela manque.

---

## Comment le projet est tenu

vault est développé sous une **constitution** de huit principes non négociables. Trois d'entre eux
se voient de l'extérieur :

- **Aucune cryptographie maison.** Les primitives viennent de bibliothèques auditées ; le projet
  les assemble et n'en écrit aucune.
- **Le format est auto-descriptif.** Tout ce qui est nécessaire au déchiffrement figure en clair
  dans l'en-tête. Aucun paramètre n'est codé en dur dans le logiciel.
- **Aucune régression non détectée.** Sept portes bloquent chaque fusion : formatage, analyse
  statique sans le moindre avertissement, compilation sans avertissement, tests, **couverture de
  lignes à 100 %**, absence de dépendance réseau — y compris transitive, vérifiée mécaniquement —
  et le déchiffreur indépendant, qui échoue si la spécification du format ne suffit plus à lire un
  vault.

Les tests portent les garanties de sécurité plutôt que de les affirmer : une suite vérifie
qu'aucun octet reconnaissable des données d'entrée n'apparaît sur le disque après une session
représentative, une autre qu'une altération est toujours détectée, une troisième qu'une
interruption à n'importe quel point d'écriture laisse le vault ouvrable et son contenu antérieur
intact.

---

## Licence

[Apache-2.0](LICENSE).
