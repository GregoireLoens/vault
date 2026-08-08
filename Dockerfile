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
