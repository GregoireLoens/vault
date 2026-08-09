# Exclusions de couverture

Le principe VIII fixe une porte bloquante à **100 % de couverture de lignes** sur l'ensemble de
l'espace de travail. Ce document recense **toutes** les exclusions qui subsistent, et les justifie
une par une.

La règle qui les gouverne tient en une phrase : **une exclusion ne peut viser que du code
inexécutable sur l'exécuteur d'intégration continue.** Une exclusion pour du code « difficile à
tester », « peu intéressant » ou « évidemment correct » est interdite. Si un chemin est
exécutable, il est couvert ; s'il ne l'est pas, il figure ici.

État au 2026-08-08, logiciel en `v1.0.0` : **une seule exclusion**.

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

Deux répertoires contiennent du code exécutable sans figurer dans la mesure :

- **`verification/`** — le déchiffreur indépendant. Il n'est pas écrit en Rust : `cargo llvm-cov`
  ne peut pas le voir, et il n'y a rien à exclure. Il a sa propre porte, qui échoue si le
  déchiffrement du vault de référence échoue ;
- **`fuzz/`** — le harnais d'exploration guidée, **exclu des membres de l'espace de travail**.
  Instrumenté, il ne se comporte pas comme un crate ordinaire et fausserait la mesure. Son
  exclusion du périmètre est ce qui permet au seuil de rester à 100 % sans dérogation ;
  l'intégration continue en vérifie tout de même la compilation, un crate que rien ne compile
  pourrissant en silence.

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
