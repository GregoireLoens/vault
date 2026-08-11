# Faux client ssh

`ssh` est un script POSIX que les tests placent **en tête du `PATH`** du processus `vault` qu'ils
lancent. C'est le dispositif de la décision D-207, et son intérêt tient en une phrase :

> **Le code de production ne comporte aucune couture.**

Pas de trait `Transport` substituable, pas de paramètre de programme, pas de variable
d'environnement lue par vault. Le code lance `ssh` résolu par le `PATH`, toujours — et ce sont donc
ses **vraies lignes** que la suite exécute : construction des arguments, tubes, attente, lecture du
code de retour.

Les deux alternatives ont été écartées pour la même raison. Un trait substituable laisserait le
chemin réel non exécuté en intégration, donc soit non couvert, soit couvert par une exclusion — et
le principe VIII refuse les deux. Un vrai serveur ssh ajouterait un démon, des clés et du réseau
local à un environnement dont l'argument principal est qu'il n'a pas d'interface.

## Ce qu'il joue

Ce que le vrai client ne saurait pas produire à la demande : hôte inconnu, empreinte changée,
commande distante absente, canal rompu à mi-course, code de retour non nul, mort par signal.

Il est piloté par des variables d'environnement que **le test** pose, et que vault ne connaît pas.

| Variable | Rôle |
|---|---|
| `FAUX_SSH_JOURNAL` | fichier où consigner la ligne de commande reçue |
| `FAUX_SSH_RECU` | fichier où consigner tout ce qui traverse le tube |
| `FAUX_SSH_MODE` | comportement de la session de **transmission** |
| `FAUX_SSH_MODE_SONDAGE` | comportement de la session de **sondage** |

Les deux dernières prennent l'une de ces valeurs : `relais` (défaut), `absent`, `hote-inconnu`,
`empreinte`, `rompu`, `signal`, `code:<n>`.

Les piloter séparément est ce qui permet d'éprouver un sondage qui passe suivi d'une transmission
qui échoue — et l'inverse, qui est le cas de FR-028.

## Pourquoi `eval`

En mode `relais`, le script évalue la commande distante avec `eval`. C'est **exactement** ce que
fait le shell distant d'un vrai `ssh`, qui ne reçoit pas un tableau d'arguments mais une chaîne à
redécouper. C'est donc la seule façon d'éprouver pour de bon la citation POSIX de D-206 : une
citation fautive casse ici, comme elle casserait là-bas.

Les tests passent `--remote-command` pointant sur le binaire `vault` de la compilation en cours : le
relais exécute alors un vrai import ou un vrai export, et le transfert aboutit pour de bon dans un
répertoire voisin.

## Ce qu'il n'établit pas

**Qu'un transfert réel fonctionne.** Ce script éprouve ce que vault fait ; il n'éprouve pas OpenSSH.
Une validation manuelle entre deux vraies machines reste nécessaire avant livraison, et elle ne peut
pas être une porte — l'environnement d'intégration n'a pas d'interface réseau.
