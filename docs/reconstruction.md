# Vérifier une livraison

Comment s'assurer qu'un binaire de vault correspond bien au code publié, et qu'il vient bien de
son auteur.

Ces deux questions sont distinctes et se vérifient séparément. La reconstruction établit que **le
binaire correspond au code** ; la signature établit que **la livraison vient de l'auteur**. L'une
sans l'autre laisse un trou.

---

## 1. Reconstruire

### La procédure

```bash
git clone https://github.com/GregoireLoens/vault && cd vault
git checkout v1.0.0                     # la version à vérifier
./scripts/dev.sh build                  # image à version figée
./scripts/dev.sh bash -c '
  export RUSTFLAGS="--remap-path-prefix=/work=."
  cargo build --release -p vault-cli
  sha256sum target/release/vault'
```

**Le drapeau `--remap-path-prefix` fait partie de la procédure**, et non de la configuration du
dépôt. Placé dans `.cargo/config.toml`, il s'appliquerait à *toutes* les compilations — y compris
à celle qui mesure la couverture, dont il perturbe l'instrumentation. Le laisser dans la commande
le cantonne à l'usage où il sert.

Comparez l'empreinte obtenue à celle publiée avec la livraison.

### Ce qui est garanti identique

**Une reconstruction depuis la même image, sur la même architecture, redonne exactement le même
binaire.** Ce n'est pas une espérance : c'est mesuré. Deux compilations successives, la seconde
après effacement complet des artefacts, produisent la même empreinte au bit près.

Trois choses le permettent :

- la **chaîne d'outils est figée** — `rust-toolchain.toml` épingle la version, et le `Dockerfile`
  épingle l'image de base ;
- les **dépendances sont verrouillées** par `Cargo.lock`, versionné ;
- le **chemin de compilation est neutralisé** par le `--remap-path-prefix` de la commande ci-dessus.
  Sans lui, deux personnes compilant depuis des répertoires différents obtiendraient des binaires
  différents — pour une raison sans aucun rapport avec le code.

### Ce qui peut légitimement diverger

| Cause | Effet |
|---|---|
| **Architecture différente** | Binaire entièrement différent. Attendu. |
| **Image de base reconstruite** après une mise à jour amont de `rust:1.97.1-trixie` | Peut changer le binaire si l'éditeur de liens ou la bibliothèque C ont bougé. |
| **Compilation hors du conteneur**, avec une chaîne installée localement | Aucune garantie. La procédure ne couvre pas ce cas. |
| **Options de compilation modifiées** — `RUSTFLAGS`, profil, fonctionnalités | Binaire différent, par construction. |

### Comment distinguer une divergence attendue d'une divergence suspecte

C'est la question à laquelle une procédure doit répondre, faute de quoi elle ne conclut rien.

**Procédez par élimination, dans cet ordre :**

1. **L'empreinte de l'image correspond-elle ?** `docker image inspect vault-dev --format '{{.Id}}'`
   sur les deux machines. Si elles diffèrent, l'image a été reconstruite à un autre moment : la
   divergence est **attendue**. Refaites la comparaison en partant de la même image.
2. **L'architecture est-elle la même ?** `uname -m`. Si non, divergence **attendue**.
3. **Le dépôt est-il exactement à la même révision ?** `git status` doit être propre et
   `git rev-parse HEAD` identique. Une modification locale, fût-elle d'un commentaire, change le
   binaire — divergence **attendue**.
4. **`RUSTFLAGS` ou `CARGO_*` sont-ils positionnés dans votre environnement ?** Ils s'ajoutent à
   ceux du dépôt. Divergence **attendue**.

**Si ces quatre points sont identiques et que les empreintes diffèrent, la divergence est
suspecte.** Signalez-la comme une faille (voir [`SECURITY.md`](../SECURITY.md)) : cela signifierait
soit que le binaire publié n'a pas été produit à partir de ce code, soit que la reconstruction
n'est pas aussi déterministe qu'annoncé. Les deux méritent d'être élucidées.

### Ce que cette procédure n'établit pas

Elle établit que le binaire correspond au code. **Elle ne dit rien de la qualité de ce code** —
voir [`docs/verifications.md`](verifications.md) pour ce qui a été vérifié, et ce qui ne l'a pas
été.

---

## 2. Vérifier la signature

Les livraisons sont signées par **clé SSH**. Le fichier des signataires autorisés est versionné
dans le dépôt, ce qui rend la vérification possible **hors de la forge** — une vérification qui ne
serait possible que sur le site hébergeant le code reviendrait à lui demander d'attester de
lui-même.

### La procédure

```bash
git -c gpg.ssh.allowedSignersFile=.github/allowed_signers tag -v <version>
echo "code de retour : $?"
```

**Fiez-vous au code de retour, pas au texte.** C'est le point le plus important de cette section :

| Code | Signification |
|---|---|
| `0` | La signature est valide **et** la clé figure parmi les signataires autorisés |
| non nul | Signature invalide, **ou clé inconnue** |

Le piège est réel et mérite d'être connu : présenté avec un fichier de signataires qui ne contient
pas la bonne clé, `git` affiche tout de même

```text
Good "git" signature with RSA key SHA256:…
No principal matched.
```

La première ligne dit seulement que la signature est cohérente avec **une** clé — n'importe
laquelle. C'est la seconde qui compte, et le code de retour vaut alors `1`. Un lecteur pressé qui
s'arrête à « Good signature » n'a **rien vérifié du tout**.

### Ce qui a été éprouvé

La chaîne complète a été déroulée, et pas seulement décrite. Les quatre cas ci-dessous l'ont été
**sur `v1.1.0`**, le tag publié — et non sur un tag d'essai qui aurait quitté la machine de
l'auteur sans que personne puisse le refaire :

| Cas | Résultat |
|---|---|
| Tag signé, fichier de signataires du dépôt | `Good "git" signature`, code `0` |
| Même tag, fichier contenant une **autre** clé | `No principal matched`, code `1` |
| Même tag, fichier de signataires **vide** | code `1` |
| Depuis un **clone neuf**, sans configuration locale | code `0` |

Le deuxième cas est celui qui compte : il établit que le fichier de signataires est réellement
consulté, et non décoratif. Le quatrième écarte l'autre soupçon, celui d'une vérification qui ne
réussirait que sur le poste où la clé est installée.

Vous pouvez rejouer les quatre. Le premier et le dernier demandent le seul dépôt ; les deux du
milieu se fabriquent en une ligne, en substituant au fichier du dépôt une clé quelconque puis un
fichier vide.

### Le sort des livraisons déjà publiées

Les tags `v0.1.0` à `v1.0.0` sont **non signés** et le resteront. Les signer supposerait de les
déplacer, ce qui casserait les références existantes — et une signature apposée après coup
n'atteste de toute façon pas grand-chose sur les conditions dans lesquelles la version a été
produite.

**La politique s'applique à partir de `v1.1.0`**, qui est le premier tag signé du projet. C'est dit
ici pour qu'un tiers ne conclue pas à une anomalie en constatant l'absence de signature sur les
versions antérieures.

### Ce que la signature n'établit pas

Elle établit que la livraison vient bien du détenteur de la clé. **Elle ne dit rien du contenu** —
un mainteneur dont la machine serait compromise signerait de bonne foi un binaire qui ne l'est
pas. C'est précisément pour cela que la reconstruction de la section 1 existe : les deux
vérifications se complètent et ne se remplacent pas.
