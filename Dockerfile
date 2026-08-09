# Image de développement de vault — T001
#
# Rien ne s'installe sur la machine hôte (D-015) : toute la chaîne Rust vit ici.
# La version est figée pour que la chaîne soit reproductible à l'identique.
FROM rust:1.97.1-trixie

# llvm-tools-preview est requis par cargo-llvm-cov et n'est pas dans l'image de base.
RUN rustup component add llvm-tools-preview clippy rustfmt

# cargo-deny  : interdiction des dépendances réseau (D-012, principe III)
# cargo-llvm-cov : couverture de lignes, seuil bloquant à 100 % (principe VIII)
# Versions figées : la chaîne locale et celle de l'intégration continue doivent
# appliquer exactement les mêmes règles, sinon une porte passe ici et échoue là.
RUN cargo install --locked cargo-deny@0.20.2 cargo-llvm-cov@0.8.7 \
    && rm -rf "$CARGO_HOME/registry" "$CARGO_HOME/git"

# Exploration guidée par la couverture — 002, T023
#
# `cargo-afl` fonctionne sur chaîne **stable** : c'est ce qui permet de mener
# des campagnes sans introduire de chaîne *nightly*, qui romprait la
# reproductibilité tenue depuis le premier commit. AFL++ a besoin de clang pour
# instrumenter.
#
# Les campagnes se mènent **hors des portes** : leur durée n'est pas bornée, ce
# qui les rend impropres à une vérification bloquante. L'intégration continue se
# contente de compiler le crate `fuzz/`, pour qu'il ne pourrisse pas en silence.
# Seul clang est installé ici. `cargo-afl` s'installe dans le CARGO_HOME
# **d'exécution** — le montage persistant `.docker-cache/cargo` — car il conserve
# à côté de lui la bibliothèque d'instrumentation qu'il compile, et celle-ci
# doit se trouver là où l'outil la cherchera. L'installer dans l'image la
# placerait dans un CARGO_HOME que l'exécution ne voit pas.
#
#   ./scripts/dev.sh --net bash -c 'cargo install --locked cargo-afl@0.18.2 \
#                                    && cargo afl config --build'
#
# Une fois pour toutes : le montage survit aux conteneurs.
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang llvm \
    && rm -rf /var/lib/apt/lists/*

# Environnement du déchiffreur indépendant — 002, T001
#
# Le principe IV exige qu'un vault soit déchiffrable à partir de sa seule
# spécification, sans exécuter vault. Le vérifier demande une implémentation
# écrite ailleurs qu'en Rust, avec d'autres bibliothèques : réemployer celles du
# logiciel ferait partager à l'épreuve les erreurs d'interprétation qu'elle est
# censée débusquer.
#
# `ensurepip` ne fait pas partie de l'image de base ; `python3-venv` l'apporte.
# L'installation a lieu ici, à la construction de l'image, seul moment où le
# réseau est accordé — exactement comme `cargo install` ci-dessus. À
# l'exécution, le déchiffreur tourne sans réseau comme tout le reste.
#
# Les versions sont figées dans requirements.txt. `cargo deny` ne voit pas cet
# écosystème : la garantie repose ici sur le figement des versions et sur le
# fait que rien de tout cela n'entre dans un binaire livré.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3-venv \
    && rm -rf /var/lib/apt/lists/*
COPY verification/dechiffreur/requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/verification \
    && /opt/verification/bin/pip install --no-cache-dir --require-virtualenv \
       --disable-pip-version-check -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

WORKDIR /work

# CARGO_HOME est réassigné à l'exécution vers un bind mount accessible en
# écriture : avec --user, le HOME du conteneur ne l'est pas (D-015).
ENV CARGO_HOME=/cargo
