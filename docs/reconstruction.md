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

> ⚠ **Pas encore en place.** Les livraisons `v0.1.0` à `v1.0.0` ne sont **pas** signées.
>
> Ce document décrira la procédure dès que la clé de signature sera en service. Il ne la décrit pas
> par avance : une marche à suivre qui ne fonctionne pas est pire qu'une absence de marche à
> suivre, parce qu'elle laisse croire qu'on a vérifié quelque chose.

### Ce qui est prévu

La signature se fera par **clé SSH**, et le dépôt contiendra le fichier de signataires autorisés
permettant la vérification **hors de la forge** :

```bash
git -c gpg.ssh.allowedSignersFile=.github/allowed_signers tag -v <version>
```

Vérifier hors de la forge est le point. Une vérification qui ne serait possible que sur le site
qui héberge le code reviendrait à lui demander d'attester de lui-même.

### Le sort des livraisons déjà publiées

Les tags `v0.1.0` à `v1.0.0` resteront **non signés**. Les signer supposerait de les déplacer, ce
qui casserait les références existantes — et une signature apposée après coup n'atteste de toute
façon pas grand-chose. **La politique s'appliquera à partir de la livraison suivante**, et c'est
dit ici pour qu'un tiers ne conclue pas à une anomalie en constatant leur absence de signature.
