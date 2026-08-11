# Exclusions de couverture

Le principe VIII fixe une porte bloquante à **100 % de couverture de lignes** sur l'ensemble de
l'espace de travail. Ce document recense **toutes** les exclusions qui subsistent, et les justifie
une par une.

La règle qui les gouverne tenait en une phrase : **une exclusion ne peut viser que du code
inexécutable sur l'exécuteur d'intégration continue.** Une exclusion pour du code « difficile à
tester », « peu intéressant » ou « évidemment correct » reste interdite.

**Cette règle a été élargie le 2026-08-11**, et l'élargissement est écrit ici plutôt que dissous
dans une ligne de configuration. Une seconde catégorie est désormais admise : **du code qui
s'exécute, mais dont l'exécution n'est pas créditée à l'instanciation que l'outil mesure.** Elle
n'a qu'un membre, dont la justification est détaillée plus bas, et toute exclusion future devra
relever de l'une de ces deux catégories — et être argumentée ici.

État au 2026-08-11 : **deux exclusions**.

---

## `crates/vault-cli/src/console/tty.rs`

Déclarée dans `scripts/dev.sh` et dans `.github/workflows/ci.yml`, par le même motif
`--ignore-filename-regex`, pour que la mesure locale et celle de l'intégration continue portent
sur exactement le même périmètre.

**Ce que contient ce fichier** : la lecture masquée d'une passphrase sur un terminal, et rien
d'autre. Il enveloppe `rpassword` et la détection de terminal.

**Pourquoi il est inexécutable en intégration continue** : un exécuteur n'a pas de terminal. Or
CLI-001 interdit de recevoir la passphrase autrement que par une saisie masquée — pas d'option de
ligne de commande, pas de tube, pas de variable d'environnement. Ce code ne peut donc pas
s'exécuter là où la couverture est mesurée, et lui fabriquer un pseudo-terminal ferait entrer une
dépendance de plus, au comportement incertain sous Windows, pour couvrir une enveloppe de quinze
lignes.

**Ce qui est couvert malgré tout** : le fichier est le seul point du logiciel où un terminal est
touché, et il est isolé derrière le trait `Console`. Tout ce qui l'entoure — les invites, les
confirmations, le refus d'agir sans terminal (CLI-022), l'appréciation de robustesse — est
exercé par une console scriptée, sans exclusion. Le contour de la dérogation est donc aussi mince
que possible.

---

## Ce qui n'est **pas** une exclusion

Deux catégories reviennent souvent dans la discussion et n'en sont pas.

### Le code conditionné par la plateforme

`fs/atomic.rs` contient deux implémentations de `replace` et de `sync_dir`, l'une sous
`#[cfg(unix)]`, l'autre sous `#[cfg(windows)]`. La variante Windows **n'existe pas** dans la
compilation Linux : elle ne produit aucune ligne à couvrir sur l'exécuteur qui mesure. Elle n'est
pas exclue, elle est absente — et la matrice de tests de l'intégration continue l'exerce sur
`windows-latest`, où elle existe.

Le même raisonnement vaut pour `format/path.rs`, qui porte les règles de nommage propres à chaque
hôte.

### Le code qui n'appartient pas à l'espace de travail mesuré

Un répertoire contient du code exécutable sans figurer dans la mesure :

- **`verification/`** — le déchiffreur indépendant. Il n'est pas écrit en Rust : `cargo llvm-cov`
  ne peut pas le voir, et il n'y a rien à exclure. Il a sa propre porte, qui échoue si le
  déchiffrement du vault de référence échoue.

Il y en avait deux jusqu'au 2026-08-09 : le crate `fuzz/`, exclu des membres de l'espace de
travail parce qu'instrumenté, a été retiré du dépôt avec le reste de l'exploration hostile.

**Ce n'est pas la même chose qu'une exclusion.** Une exclusion retire de la mesure du code qui en
relève ; ici, ce code n'en a jamais relevé. La distinction compte, faute de quoi un lecteur
conclura que le seuil de 100 % a été assoupli — alors qu'il porte toujours sur exactement le même
périmètre qu'avant : les deux crates livrés.

### Les tests conditionnés par la plateforme

Plusieurs tests sont marqués `#[cfg(unix)]` ou `#[cfg(target_os = "linux")]` parce que le procédé
qu'ils emploient n'a pas d'équivalent portable : rendre un répertoire non inscriptible pour
provoquer un échec d'écriture, créer un fichier creux de quatre gigaoctets, compter les
descripteurs de socket du processus dans `/proc/self/fd`.

Ce sont des **tests** absents ailleurs, non du code de production exclu. Le code qu'ils couvrent,
lui, est mesuré sur Linux, où la porte s'applique.

---

## Comment vérifier

```bash
./scripts/dev.sh coverage
```

La commande échoue si une seule ligne n'est pas couverte. Toute exclusion ajoutée à
`--ignore-filename-regex` doit l'être **dans les deux fichiers** — `scripts/dev.sh` et
`ci.yml` — être annotée dans le code qu'elle vise, et être ajoutée ici avec sa justification.


---

## `crates/vault-cli/src/cmd/transport.rs`

Déclarée dans `scripts/dev.sh` et dans `.github/workflows/ci.yml`, par le même
`--ignore-filename-regex` que la précédente.

**Ce que contient ce fichier** : deux fonctions, six lignes en tout. Chacune appelle le transport —
`Vault::send` ou `Vault::fetch` —, passe le résumé obtenu au compte rendu, et rend le succès. Rien
d'autre. La validation des arguments, le refus d'une extrémité mal désignée, la confirmation d'un
remplacement, l'assemblage des options ssh et les comptes rendus eux-mêmes sont restés dehors, dans
`cmd/send.rs` et `cmd/fetch.rs`, et sont mesurés comme le reste.

Le périmètre a été **mesuré, et non supposé** : sans ce fichier, la porte signale exactement deux
lignes par commande — l'appel au compte rendu et le `Ok(())` qui le suit.

**Pourquoi ce n'est pas la même catégorie que `tty.rs`, et pourquoi il faut le dire.** Ce code
**s'exécute** sur l'exécuteur d'intégration : `crates/vault-cli/tests/transfer.rs` mène des
transferts entiers contre le faux client ssh, et ces six lignes y passent à chaque fois. Ce n'est
donc pas du code inexécutable ; c'est du code dont la mesure n'est pas créditée là où on la lit.

`cargo llvm-cov --all-targets` compte les lignes **par instanciation de crate**. Le même fichier
est compilé deux fois — dans le binaire `vault` et dans son binaire de test — et une ligne couverte
dans l'un mais pas dans l'autre est comptée manquante. Le rapport annoté, le rapport HTML et
l'export lcov, qui prennent l'union des instanciations, n'affichent d'ailleurs **aucune** ligne
manquante ici : seul le tableau récapitulatif en signale, et c'est lui qui commande la porte.

**Pourquoi l'instanciation de test ne peut pas y parvenir.** Il lui faudrait un client ssh dans son
`PATH`. Le faux client existe — c'est `crates/vault-cli/tests/faux-ssh/` — mais l'y placer suppose
de modifier le `PATH` du processus de test, donc `std::env::set_var`, `unsafe` depuis l'édition
2024. `unsafe_code = "forbid"` l'interdit dans cet espace de travail, et `forbid` ne se lève pas.
Les tests d'intégration contournent la difficulté en lançant le **binaire** avec un `PATH` choisi,
ce qui couvre le chemin réel — mais crédite l'autre instanciation.

**Ce qui a été écarté**, et par quoi :

| Alternative | Pourquoi non |
|---|---|
| Un trait de transport substituable en test | D-207 l'a examinée et rejetée : le chemin réel resterait non exécuté en intégration, donc soit non couvert, soit couvert par une exclusion **plus large** que celle-ci |
| Exclure `cmd/send.rs` et `cmd/fetch.rs` en entier | Plus de deux cent cinquante lignes de validation et de refus cesseraient d'être mesurées pour six qui posent problème |
| Renoncer à `--all-targets`, ou fusionner les instanciations | Modifie la porte elle-même, donc la garantie que le projet donne à ses lecteurs |

**Ce que cette exclusion coûte, dit franchement.** Six lignes du produit ne sont plus comptées. Si
l'une d'elles cessait un jour d'être exécutée — un `?` déplacé, un compte rendu oublié —, la porte
de couverture ne le dirait pas. Ce sont les tests de `tests/transfer.rs` qui le diraient, en
échouant : ils vérifient qu'un envoi nominal dépose un vault ouvrable à la destination et que son
compte rendu la nomme. Le filet existe donc, il n'est simplement plus tendu par la porte 5.

**Ce qui rendrait cette exclusion caduque** : que `std::env::set_var` redevienne appelable sans
`unsafe`, que `cargo llvm-cov` fusionne les instanciations pour son tableau, ou qu'un moyen
apparaisse de substituer le programme lancé sans introduire de couture dans le produit. Le jour où
l'un des trois arrive, ce fichier doit être réintégré à la mesure et cette section retirée.
