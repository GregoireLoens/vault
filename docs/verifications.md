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

Deux dispositifs de nature différente, et non un seul.

### La porte : exploration engendrée, déterministe

`crates/vault-core/tests/hostile.rs` soumet **768 entrées par surface** — en-tête, index, blob,
chemins — en trois familles : octets arbitraires, structures presque valides lourdement altérées,
structures valides tronquées. Le générateur part d'une graine figée : la suite explorée est
exactement la même partout, à chaque exécution. Une porte dont la graine varie devient un
générateur d'échecs inexpliqués, celui qui voit rouge ne pouvant pas reproduire ce que la machine
d'en face a vu.

**Deux propriétés y ont été reformulées après un premier échec, et l'erreur était dans l'énoncé,
pas dans le logiciel :**

- exiger que `Vault::open` échoue sur tout en-tête altéré était **faux**. L'ouverture ne fait que
  décoder les champs publics et n'authentifie rien — c'est documenté, et c'est ce qui permet à
  `vault info` de travailler sans passphrase. La propriété juste est plus forte : *si* une entrée
  hostile mène jusqu'à une session ouverte, le contenu de cette session doit être **le bon** ;
- exiger que toute altération de blob fasse échouer l'extraction était **faux** aussi. Le
  remplissage n'est ni déchiffré ni interprété (VR-B3) : l'altérer laisse légitimement
  l'extraction aboutir. La propriété juste : ou bien l'extraction échoue **sans rien écrire**, ou
  bien elle aboutit et restitue le contenu d'origine octet pour octet. Le troisième cas — aboutir
  sur des données altérées — est le seul interdit.

`crates/vault-core/tests/regressions.rs` rejoue en permanence les entrées ayant compté. Aucune
campagne n'ayant encore révélé de défaut, il est amorcé avec les cas limites que le développement
a rencontrés — dont le nom de blob multi-octets, qui fait paniquer un découpage naïf de chaîne
hexadécimale.

### Les campagnes : exploration guidée par la couverture

Menées hors ligne, avec `cargo-afl` sur chaîne **stable** — introduire une chaîne *nightly* aurait
rompu la reproductibilité tenue depuis le premier commit.

Campagne initiale du 2026-08-08, **60 secondes par surface** :

| Surface | Exécutions | Vitesse | Chemins découverts | Plantages | Blocages |
|---|---|---|---|---|---|
| En-tête | 1 555 129 | 25 917/s | 1 237 | **0** | **0** |
| Index authentifié | 2 016 634 | 33 608/s | 986 | **0** | **0** |
| Chemins | 2 490 482 | 41 507/s | 71 | **0** | **0** |

Soit environ **six millions d'exécutions**, sans un seul plantage ni blocage.

**Ce que cela n'établit pas.** Soixante secondes par surface est une campagne **courte** : elle
écarte les défauts qui se trouvent vite, pas ceux qui demandent des heures. Les 1 237 chemins
découverts sur l'en-tête montrent d'ailleurs que l'exploration était encore en train de progresser
quand elle s'est arrêtée. L'absence de découverte n'est donc pas une preuve d'absence de défaut,
et ce tableau est publié pour que le lecteur en juge lui-même plutôt que de conclure du silence à
la sûreté.

**Comment relancer**, une fois pour toutes l'outil installé dans le montage persistant :

```bash
./scripts/dev.sh --net bash -c 'cargo install --locked cargo-afl@0.18.2 && cargo afl config --build'
./scripts/dev.sh bash -c 'cd fuzz && cargo afl build --release'
./scripts/dev.sh bash -c 'cd fuzz && AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
  cargo afl fuzz -i corpus/entete -o /tmp/afl -V 3600 target/release/entete'
```

Toute entrée fautive rejoint `regressions.rs` **avant même** que le défaut soit corrigé : versée
après, elle risque de ne jamais l'être.

**Une conséquence de l'exclusion, à ne pas taire** : `fuzz/` étant hors de l'espace de travail,
`cargo deny` ne voit pas sa dépendance `afl` — la porte d'approvisionnement porte sur ce qui est
livré, et ce crate ne l'est pas. La contrepartie est que cette dépendance-là n'est vérifiée par
aucun outil ; elle est figée par version, comme le reste, et n'entre dans aucun binaire.

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

## Les six portes

Passées en local avant chaque livraison, dans le conteneur :

```bash
./scripts/dev.sh cargo fmt --all --check
./scripts/dev.sh cargo clippy --workspace --all-targets --all-features -- -D warnings
./scripts/dev.sh cargo build --workspace --all-targets
./scripts/dev.sh cargo test --workspace --all-targets
./scripts/dev.sh coverage
./scripts/dev.sh deny bans
```

S'y ajoute, hors des portes mais avant chaque poussée, la compilation croisée qui écarte toute la
classe des erreurs de compilation Windows sans attendre l'intégration continue :

```bash
./scripts/dev.sh --net bash -c 'rustup target add x86_64-pc-windows-gnu \
  && cargo check --workspace --all-targets --target x86_64-pc-windows-gnu'
```

Les trois plateformes de la matrice, elles, ne sont exerçables que par l'intégration continue.
