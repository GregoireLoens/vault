# Image de développement de vault — T001
#
# Rien ne s'installe sur la machine hôte (D-015) : toute la chaîne Rust vit ici.
# La version est figée pour que la chaîne soit reproductible à l'identique.
FROM rust:1.97.1-trixie

# llvm-tools-preview est requis par cargo-llvm-cov et n'est pas dans l'image de base.
RUN rustup component add llvm-tools-preview clippy rustfmt

# cargo-deny  : interdiction des dépendances réseau (D-012, principe III)
# cargo-llvm-cov : couverture de lignes, seuil bloquant à 100 % (principe VIII)
RUN cargo install --locked cargo-deny cargo-llvm-cov \
    && rm -rf "$CARGO_HOME/registry" "$CARGO_HOME/git"

WORKDIR /work

# CARGO_HOME est réassigné à l'exécution vers un bind mount accessible en
# écriture : avec --user, le HOME du conteneur ne l'est pas (D-015).
ENV CARGO_HOME=/cargo
