#!/usr/bin/env bash
#
# Enveloppe de la chaîne d'outils conteneurisée — T003, T004, T005
#
# Rien ne s'installe sur la machine hôte (D-015). Toute commande cargo passe
# par ici.
#
#   ./scripts/dev.sh build              construit l'image
#   ./scripts/dev.sh fetch              cargo fetch — SEULE commande avec réseau
#   ./scripts/dev.sh shell              shell interactif dans le conteneur
#   ./scripts/dev.sh coverage           couverture, seuil bloquant à 100 %
#   ./scripts/dev.sh deny               cargo deny — avec réseau (base RustSec)
#   ./scripts/dev.sh <commande...>      exécute sans réseau
#   ./scripts/dev.sh --net <cmd...>     exécute avec réseau (exceptionnel)
#   ./scripts/dev.sh --mem 2g <cmd...>  exécute sous limite mémoire
#
set -euo pipefail

IMAGE=vault-dev
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE_DIR="$REPO_ROOT/.docker-cache"

# Le répertoire de cache DOIT exister avant le montage : Docker crée un point de
# montage manquant avec la propriété de root, ce qui le rendrait inaccessible à
# l'utilisateur du conteneur (D-015).
mkdir -p "$CACHE_DIR/cargo"

network="none"
memory=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --net) network="bridge"; shift ;;
        --mem) memory="$2"; shift 2 ;;
        *) break ;;
    esac
done

[[ $# -eq 0 ]] && { sed -n '3,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2; }

case "$1" in
    build)
        # La construction de l'image a besoin du réseau : c'est attendu.
        exec docker build -t "$IMAGE" "$REPO_ROOT"
        ;;
    fetch)
        network="bridge"
        set -- cargo fetch
        ;;
    deny)
        # La vérification des vulnérabilités doit cloner la base RustSec : c'est
        # de l'outillage de développement, pas le produit. Le réseau lui est
        # accordé explicitement, comme à fetch.
        shift
        network="bridge"
        set -- cargo deny check "$@"
        ;;
    coverage)
        shift
        # L'exclusion porte sur un seul fichier, qui ne contient que la lecture
        # masquée sur le terminal. Un exécuteur d'intégration continue n'a pas
        # de terminal, et CLI-001 interdit de recevoir la passphrase autrement
        # que par une saisie masquée : ce code ne peut donc pas s'exécuter sur
        # la plateforme d'intégration. C'est la seule catégorie de dérogation
        # que le principe VIII admet, et elle est justifiée dans le fichier.
        set -- cargo llvm-cov --workspace --all-targets \
            --ignore-filename-regex 'vault-cli/src/console/tty\.rs' \
            --fail-under-lines 100 "$@"
        ;;
    shell)
        shift
        set -- bash "$@"
        ;;
esac

docker_args=(
    --rm
    # Docker est rootful sur cet hôte : sans --user, tout fichier écrit dans le
    # dépôt appartiendrait à root et exigerait sudo pour être nettoyé (T004).
    --user "$(id -u):$(id -g)"
    --volume "$REPO_ROOT:/work"
    --volume "$CACHE_DIR/cargo:/cargo"
    --workdir /work
    --env CARGO_HOME=/cargo
    # Avec --user, l'utilisateur n'a pas d'entrée dans /etc/passwd et donc pas
    # de HOME exploitable : on le pointe vers un emplacement accessible.
    --env HOME=/cargo
    --network "$network"
)

[[ -n "$memory" ]] && docker_args+=(--memory "$memory" --memory-swap "$memory")
[[ -t 0 && -t 1 ]] && docker_args+=(--interactive --tty)

exec docker run "${docker_args[@]}" "$IMAGE" "$@"
