# Vérifications manuelles

Ce que la suite automatisée ne couvre pas seule, et ce qui a été constaté en le déroulant à la
main. Dernier passage le **2026-08-08**, logiciel en `v0.3.0` + phase 7.

Les neuf scénarios de `specs/001-vault-core/quickstart.md` y sont repris un par un, avec pour
chacun ce qui a servi de preuve et les écarts relevés entre le texte du scénario et le logiciel
tel qu'il est. **Les écarts sont dans le quickstart, pas dans le logiciel** — sauf mention
contraire.

---

## Ce que ces vérifications établissent, et ce qu'elles n'établissent pas

À lire avant tout le reste, parce que la confusion est facile et coûteuse.

**Ce qu'elles établissent :**

- que le format se **décrit** fidèlement — une implémentation écrite depuis le seul
  `docs/format.md` restitue le contenu d'un vault de référence octet pour octet ;
- que le logiciel **refuse explicitement** ce qu'il ne comprend pas, y compris des octets que
  personne n'a choisis ;
- qu'une livraison peut être **rattachée à son auteur** et reconstruite par un tiers.

**Ce qu'elles n'établissent pas** — et aucune accumulation de tests verts n'y changera rien :

- **Pas la conception cryptographique.** Un déchiffreur indépendant qui restitue le contenu prouve
  que le document décrit fidèlement ce que le code fait. Il ne dit rien de la question de savoir
  si ce que le code fait est une bonne idée. Les paramètres de dérivation, l'absence d'engagement
  de clé, la construction du nonce : tout cela reste à relire par quelqu'un d'autre.
- **Pas l'absence de défaut.** Une exploration qui ne trouve rien n'établit pas qu'il n'y a rien à
  trouver. L'étendue de l'effort consenti est consignée plus bas pour que le lecteur en juge
  lui-même, plutôt que de conclure du silence à la sûreté.
- **Pas une relecture par un tiers.** Ces vérifications sont écrites par l'auteur du logiciel.
  Elles réduisent le périmètre et le coût d'un audit externe ; elles ne s'y substituent pas.

Ce paragraphe est écrit **avant** les vérifications qu'il encadre, et non après. Rédigé une fois
les tests au vert, il se serait transformé en excuse ; écrit d'avance, il fixe ce qu'on a le droit
de conclure.

---

## Suffisance de la spécification de format — SC-001 à SC-003

Un déchiffreur écrit depuis le seul `docs/format.md`, en Python et avec des primitives génériques,
restitue le contenu du vault de référence **octet pour octet**. Il tourne à chaque exécution de la
chaîne d'intégration (`./scripts/dev.sh verifier-format`).

**Le document a tenu.** Aucune erreur ni omission n'a été trouvée dans `docs/format.md` : la
chaîne complète — en-tête CBOR, Argon2id, contexte public à champs de largeur fixe,
désenveloppement, index, dérivation BLAKE3, et surtout la **reconstruction de STREAM BE32 à partir
de la primitive** — s'est écrite directement depuis le texte.

Deux constats tout de même, et le second compte :

- **Le défaut trouvé était dans le déchiffreur, pas dans le document.** `pathlib` refuse les
  chemins en octets, alors que le format impose de les conserver bruts ; il a fallu passer par
  `os.path`. C'est un défaut de l'outil de vérification, et il est consigné ici pour que personne
  ne le compte comme une victoire du document.
- **`crates/vault-core/tests/fixtures/README.md` était trop vague pour être exploitable.** Il
  décrivait « un texte accentué, deux lignes », ce qui se lit bien mais **ne permet pas de
  reconstituer le contenu**. Or c'est précisément ce dont un tiers a besoin. La table est
  désormais définie à l'octet près, et le contenu attendu en est dérivé — et non de la sortie du
  logiciel, ce qui reviendrait à croire le logiciel sur parole pour le vérifier.

### La limite, qui doit être lue avec le résultat

Le déchiffreur a été écrit par l'auteur du logiciel, au cours d'une session où le code Rust avait
déjà été lu. **L'indépendance n'est donc pas celle d'un tiers** : là où le document aurait été
muet, la connaissance préalable a pu combler le silence sans que rien ne le signale.

Ce que ce résultat établit malgré tout, et qu'aucun test du logiciel ne pouvait établir : le
document décrit une chaîne **complète et exacte**, reproductible avec d'autres bibliothèques, dans
un autre langage. Ce qu'il n'établit pas : qu'un lecteur n'ayant jamais vu le code y parviendrait
sans buter. Cela reste à faire faire par quelqu'un d'autre.

---

## Refus de l'entrée hostile — SC-004, SC-005

**L'exploration hostile a été retirée du dépôt le 2026-08-09**, sur décision de l'auteur :
`crates/vault-core/tests/hostile.rs`, le crate `fuzz/`, le module `vault-core::fuzzing` et la porte
« Harnais d'exploration » n'existent plus. Les portes d'intégration continue passent de huit à
sept. Ce paragraphe reste pour qu'un lecteur qui trouve le dispositif mentionné ailleurs — dans
`v1.1.0`, dans les spécifications de la feature 002 — sache qu'il a existé et où il est parti.

### Ce qui subsiste

- `crates/vault-core/tests/regressions.rs` — le corpus permanent d'entrées hostiles (T022,
  FR-011), rejoué à chaque exécution. Aucune campagne n'ayant révélé de défaut, il est amorcé avec
  les cas limites rencontrés au développement — dont le nom de blob multi-octets, qui fait paniquer
  un découpage naïf de chaîne hexadécimale ;
- `crates/vault-core/tests/tamper.rs` — la détection d'altération sur les quatre surfaces, sept
  suites, inchangée ;
- l'exploration `proptest` de `roundtrip.rs` sur les noms hostiles, les tailles et les profondeurs.

Ces trois-là relèvent de la porte « Suite de tests complète au vert » et restent bloquants.

**Deux propriétés avaient été reformulées après un premier échec du dispositif retiré, et l'erreur
était dans l'énoncé, pas dans le logiciel.** Elles sont conservées ici parce qu'elles décrivent le
comportement du logiciel, qui n'a pas changé :

- exiger que `Vault::open` échoue sur tout en-tête altéré était **faux**. L'ouverture ne fait que
  décoder les champs publics et n'authentifie rien — c'est documenté, et c'est ce qui permet à
  `vault info` de travailler sans passphrase. La propriété juste est plus forte : *si* une entrée
  hostile mène jusqu'à une session ouverte, le contenu de cette session doit être **le bon** ;
- exiger que toute altération de blob fasse échouer l'extraction était **faux** aussi. Le
  remplissage n'est ni déchiffré ni interprété (VR-B3) : l'altérer laisse légitimement
  l'extraction aboutir. La propriété juste : ou bien l'extraction échoue **sans rien écrire**, ou
  bien elle aboutit et restitue le contenu d'origine octet pour octet. Le troisième cas — aboutir
  sur des données altérées — est le seul interdit.

### Les campagnes menées, et qui ne sont plus rejouables

Le tableau ci-dessous est un **constat historique**. Il a été obtenu hors ligne avec `cargo-afl`
sur chaîne stable, le 2026-08-08, **60 secondes par surface**, sur du code que `v1.1.0` contient et
que la présente version ne contient plus. **Le harnais ayant été supprimé, ces mesures ne peuvent
plus être reproduites depuis ce dépôt** — il faudrait le reconstruire, ou repartir de `v1.1.0`.

| Surface | Exécutions | Vitesse | Chemins découverts | Plantages | Blocages |
|---|---|---|---|---|---|
| En-tête | 1 555 129 | 25 917/s | 1 237 | **0** | **0** |
| Index authentifié | 2 016 634 | 33 608/s | 986 | **0** | **0** |
| Chemins | 2 490 482 | 41 507/s | 71 | **0** | **0** |

Soit environ **six millions d'exécutions**, sans un seul plantage ni blocage.

**Ce que cela n'établissait pas déjà.** Soixante secondes par surface est une campagne **courte** :
elle écarte les défauts qui se trouvent vite, pas ceux qui demandent des heures. Les 1 237 chemins
découverts sur l'en-tête montrent que l'exploration était encore en train de progresser quand elle
s'est arrêtée. L'absence de découverte n'était donc pas une preuve d'absence de défaut. Ce tableau
reste publié pour que le lecteur en juge lui-même, et non pour conclure du silence à la sûreté.

**Ce que le retrait coûte, à ne pas taire** : il n'existe plus, dans ce dépôt, de moyen de chercher
un défaut que personne n'a imaginé sur les surfaces de décodage. Le corpus permanent rejoue ce qui
a déjà compté ; il ne découvre rien. C'est un des points que la relecture externe devra désormais
couvrir — la dernière section en tient compte.

---

## SC-010 — 4 Go sous 2 Go de mémoire

Exécuté sous limite mémoire imposée par le noyau, `./scripts/dev.sh --mem 2g`, en profil
`release` : un fichier de **4 000 000 000 octets** ajouté puis extrait, taille vérifiée à la
sortie. **75 secondes, sans élimination du processus.** Un chargement intégral en mémoire aurait
provoqué un arrêt franc bien avant.

La vérification est passée par la bibliothèque et non par la ligne de commande, celle-ci exigeant
une saisie masquée que le conteneur non interactif ne peut pas fournir (CLI-001). Le chemin
mesuré — découpage en morceaux de 64 Kio, écriture en flux, extraction en flux — est exactement
le même.

Ce contrôle n'est pas dans la suite : douze gigaoctets d'écriture et une minute et quart par
exécution en feraient payer le prix à chaque poussée, sur trois plateformes, pour une garantie
qui ne bouge pas d'une version à l'autre. Il se relance à la demande.

---

## Les neuf scénarios

### 1 — Aller-retour complet · SC-002

**Preuve** : `roundtrip.rs`, vert. Cas nommés — contenu vide, frontières de morceau, noms
accentués, arborescence profonde — et exploration `proptest` des noms hostiles et des tailles.

**Écart** : le `diff` final du scénario compare les mauvais chemins. `add /tmp/source` dépose
l'arborescence sous le nom `source`, et `extract source --to /tmp/sortie` la restitue dans
`/tmp/sortie/source`. La comparaison juste est `diff -r /tmp/source /tmp/sortie/source`.

### 2 — Aucune fuite en clair · SC-003

**Preuve** : `no_plaintext.rs`, vert. Il balaie l'intégralité du répertoire du vault, les
temporaires et la sortie du processus, à la recherche de motifs témoins **en octets bruts**.

**Deux écarts**, dont un de fond :

- `xxd` n'est pas installé dans l'image de développement, et la commande du scénario échoue ;
- surtout, chercher `head -c 32 fichier | xxd -p` dans le vault revient à chercher la
  **représentation hexadécimale en texte** d'octets qui, eux, sont binaires. Le motif ne pourrait
  pas s'y trouver même si le contenu était stocké en clair : le contrôle serait vert quoi qu'il
  arrive. C'est un faux témoin, à remplacer par une recherche d'octets bruts — ce que fait
  `no_plaintext.rs`.

### 3 — Détection d'altération · SC-004

**Preuve** : `tamper.rs`, vert, et plus exigeant que le scénario. Là où celui-ci retourne un
octet, la suite balaie **toutes** les positions de l'en-tête, de l'index et de la zone chiffrée
des blobs, un bit à la fois, et vérifie à chaque échec que la destination est restée vide.

**Aucun écart.**

### 4 — Passphrase incorrecte · SC-006

**Preuve** : `errors.rs` compare octet pour octet le rendu d'une passphrase erronée et celui de
chaque altération d'en-tête qui atteint l'authentification. Côté ligne de commande,
`le_code_3_est_indiscernable_de_ses_deux_causes` fait la même comparaison sur le code **et** le
message.

**Écart** : le code 3 n'est pas atteignable depuis un processus sans terminal, ce que
`tests/cli.rs` consigne. Le scénario suppose un shell interactif — c'est bien ainsi qu'il est
prévu d'être joué.

### 5 — Gros fichier sous contrainte mémoire · SC-010

**Preuve** : voir plus haut.

**Écart, réel** : le scénario écrit `head -c 4294967296`, soit **4 GiB**. La limite du format est
de **4 000 000 000 octets** (§6.5 de `docs/format.md`), et 4 294 967 296 la dépasse : la commande
telle qu'elle est écrite serait refusée par `Error::FileTooLarge`, avant toute écriture. La
valeur à employer est `4000000000`.

### 6 — Résistance à l'interruption · SC-007

**Preuve** : `atomicity.rs` injecte des échecs à chaque point d'écriture plutôt que de s'en
remettre au hasard d'un `kill`. `rekey_interruption.rs` complète par de vraies morts de processus
pendant le remplacement de l'en-tête, huit fois, à des instants différents.

**Écart** : le scénario met la commande d'ajout en arrière-plan (`&`) avant de la tuer. Une
commande qui réclame une passphrase masquée ne peut pas s'exécuter en arrière-plan — le shell
l'arrête dès qu'elle lit le terminal. Le scénario n'est jouable qu'en pilotant deux terminaux, ou
en s'en remettant aux suites automatisées, qui vont plus loin.

### 7 — Hors ligne · SC-005

**Preuve** : la suite complète passe sous `--network none`, qui est le **défaut** de
`scripts/dev.sh`. `offline.rs` y ajoute ce qu'un simple succès ne montre pas : après un cycle de
vie complet, le processus ne détient **aucun descripteur de socket**. Ce contrôle-là garde son
sens sur l'exécuteur d'intégration continue, qui est connecté.

**Écart** : `ip` n'est pas installé dans l'image, et la vérification
`ip addr show | grep -c eth0` échoue. Le substitut qui fonctionne :

```bash
./scripts/dev.sh bash -c 'tail -n +3 /proc/net/dev | awk "{print \$1}"'
# rend « lo: » et rien d'autre
```

### 8 — Accès concurrent · FR-012

**Preuve** : `un_vault_deja_ouvert_sort_en_code_4` dans `tests/cli.rs` tient le verrou depuis le
processus de test et vérifie que le binaire sort bien en code 4.

**Écart** : même problème d'arrière-plan qu'au scénario 6. À noter par ailleurs que depuis la
phase 4, le refus tombe **avant** la demande de passphrase : l'utilisateur d'une seconde instance
n'a plus à saisir son secret pour apprendre que le vault était déjà ouvert.

### 9 — Changement de passphrase · SC-008, FR-035

**Preuve** : `rekey.rs` vérifie que **tous les fichiers du vault sauf `header` sont identiques
octet pour octet** avant et après — la formulation exacte de « ne réécrit que l'en-tête ».
`rekey_interruption.rs` couvre FR-035.

**Écart de rattachement** : le scénario est étiqueté SC-008, qui porte sur la compatibilité
ascendante et non sur le changement de passphrase. SC-008 est vérifié par `compat.rs`, qui ouvre
des vaults de référence figés que le logiciel d'aujourd'hui n'a pas produits.

---

### Les sept scénarios de vérification, déroulés

| Scénario | Résultat |
|---|---|
| 1 — déchiffrer sans vault | 4 fichiers restitués octet pour octet |
| 2 — passphrase erronée | échec au désenveloppement, **rien d'écrit** |
| 3 — vecteurs publiés | 5 vérifications vertes, publiques et secrètes |
| 4 — entrée hostile | 5 suites vertes, 768 entrées par surface *(dispositif retiré depuis)* |
| 5 — corpus rejoué sans exploration | 4 suites vertes |
| 6 — provenance | reconstruction déterministe, signature vérifiée hors forge |
| 7 — signalement | `SECURITY.md` à la racine, canal et délais annoncés |

**Un écart, dans le quickstart lui-même** : les scénarios 3 à 5 y étaient écrits
`cargo test --workspace --all-targets <mot>`, ce qui filtre les **noms de tests** et non les
binaires. Aucun test de `regressions.rs` ne contenant le mot « regressions », la commande
rapportait « 0 passed » — c'est-à-dire un succès sans avoir rien exécuté. La forme juste est
`cargo test -p vault-core --test regressions`.

C'est le même défaut que celui relevé au scénario 2 du quickstart de `001-vault-core` : une
commande de vérification qui ne peut pas échouer. Elle est d'autant plus trompeuse ici qu'elle
affiche `ok`.

---

## Provenance des livraisons — SC-006, SC-007

**Reconstruction.** Depuis la même image et la même architecture, deux compilations successives —
la seconde après effacement complet des artefacts — produisent la **même empreinte au bit près** :
`6728fa10…a862a0` pour `vault-cli` en profil de publication. Ce n'est pas une espérance, c'est un
constat reproduit. La chaîne figée, le `Cargo.lock` versionné et la neutralisation du chemin de
compilation y suffisent.

Le drapeau `--remap-path-prefix` a d'abord été placé dans `.cargo/config.toml`, puis retiré :
appliqué à **toutes** les compilations, il perturbait l'instrumentation de couverture et faisait
tomber le seuil à 99,53 %. Il appartient à la commande de reconstruction, pas à la configuration
du dépôt.

**Signature.** La chaîne a été déroulée de bout en bout, pas seulement décrite : un tag signé se
vérifie hors de la forge avec le fichier de signataires versionné (code `0`), une clé étrangère
est refusée (code `1`), un fichier vide aussi.

Un piège a été trouvé à cette occasion et documenté dans
[`reconstruction.md`](reconstruction.md) : **`git` affiche « Good signature » même lorsque la clé
n'est pas autorisée.** Seules la ligne « No principal matched » et le code de retour font foi. Un
vérificateur pressé qui s'arrête à la première ligne n'a rien vérifié — c'est exactement le genre
de détail qui rend une procédure inutile s'il n'est pas écrit.

---

## Ce qui reste à confier à une relecture externe

Énoncé ici pour qu'une demande de devis puisse être faite **sans étude préalable**. Le périmètre
ci-dessous est ce que le projet ne peut pas se délivrer à lui-même.

**Volume** : deux crates Rust, environ 5 700 lignes couvertes, sans `unsafe`. Le format tient en un
document de quelque quatre cents lignes, avec vecteurs de test et procédure de déchiffrement pas à
pas — un relecteur n'a pas à reconstituer le format depuis le code.

**Ce qui est déjà écarté**, et n'a donc pas à être payé :

- la fidélité de la spécification au comportement réel — établie par le déchiffreur indépendant ;
- l'absence de fuite en clair, la détection d'altération, l'atomicité, la compatibilité ascendante
  — établies par les suites bloquantes depuis `v1.0.0` ;
- l'absence de dépendance réseau, même transitive.

**Ce qui reste**, et qui demande un regard extérieur compétent :

| Question | Pourquoi elle ne se répond pas ici |
|---|---|
| Les paramètres Argon2id retenus — 128 Mio, 3 passes, parallélisme 4 — sont-ils au niveau des recommandations actuelles ? | Un choix de coût se juge contre l'état de l'art d'une attaque, pas contre un test |
| L'absence d'**engagement de clé** de XChaCha20-Poly1305 sur le désenveloppement de la clé maîtresse importe-t-elle dans ce modèle de menace ? | Question de conception, pas de comportement |
| La construction du nonce STREAM et la dérivation par blob sont-elles correctement composées ? | Les tests montrent qu'elles sont cohérentes avec elles-mêmes, pas qu'elles sont sûres |
| Le remplissage par paliers de 10 % laisse-t-il fuir davantage qu'annoncé sur un corpus réel ? | Demande une analyse statistique, pas une assertion |
| Le modèle de menace omet-il quelque chose ? | Par construction, on ne voit pas ce qu'on n'a pas pensé |
| Les quatre surfaces de décodage résistent-elles à une entrée que personne n'a imaginée ? | L'exploration engendrée et les campagnes guidées ont été retirées du dépôt le 2026-08-09 ; le corpus permanent rejoue ce qui a déjà compté, il ne découvre rien |

**Pistes de financement**, pour un projet libre sans revenu : les programmes européens de type
NGI Zero financent des audits de sécurité pour les logiciels libres de confidentialité. Un audit
commercial ciblé sur ce périmètre se situe, pour ce volume, dans un ordre de grandeur de quelques
dizaines de milliers d'euros.

---

## Les sept portes

Passées en local avant chaque livraison, dans le conteneur :

```bash
./scripts/dev.sh cargo fmt --all --check
./scripts/dev.sh cargo clippy --workspace --all-targets --all-features -- -D warnings
./scripts/dev.sh cargo build --workspace --all-targets
./scripts/dev.sh cargo test --workspace --all-targets
./scripts/dev.sh coverage
./scripts/dev.sh deny bans
./scripts/dev.sh verifier-format
```

Elles étaient six jusqu'à la livraison de 002, qui a ajouté le déchiffreur indépendant et le
harnais d'exploration — huit, donc, avant le retrait du second le 2026-08-09.

À part, parce que sa portée est plus étroite : la **porte de livraison** ne bloque que les pull
requests `release/vX.Y.Z`, et n'a besoin d'aucune chaîne d'outils.

```bash
./scripts/verifier-version.sh 1.1.0
```

S'y ajoute, hors des portes mais avant chaque poussée, la compilation croisée qui écarte toute la
classe des erreurs de compilation Windows sans attendre l'intégration continue :

```bash
./scripts/dev.sh --net bash -c 'rustup target add x86_64-pc-windows-gnu \
  && cargo check --workspace --all-targets --target x86_64-pc-windows-gnu'
```

Les trois plateformes de la matrice, elles, ne sont exerçables que par l'intégration continue.
