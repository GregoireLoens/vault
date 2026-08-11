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
#   ./scripts/dev.sh verifier-format    déchiffreur indépendant sur la référence
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
    verifier-format)
        # Le principe IV exige qu'un vault soit déchiffrable à partir de sa
        # seule spécification, sans exécuter vault. Cette porte l'éprouve : un
        # déchiffreur écrit depuis le seul docs/format.md ouvre le vault de
        # référence, et son résultat est comparé octet pour octet à un contenu
        # attendu dérivé, lui aussi, de la documentation.
        #
        # Un échec ici désigne une partie du document qui est fausse ou
        # incomplète. Voir verification/dechiffreur/README.md.
        shift
        set -- bash -c '
            set -e
            sortie=$(mktemp -d)
            depaquete=$(mktemp -d)
            depuis_conteneur=$(mktemp -d)
            trap "rm -rf $sortie $depaquete $depuis_conteneur" EXIT

            # Le vault de référence, depuis le seul docs/format.md.
            echo "vault fixture v1 passphrase de reference" \
              | /opt/verification/bin/python verification/dechiffreur/dechiffrer.py \
                  crates/vault-core/tests/fixtures/v1 "$sortie"
            /opt/verification/bin/python verification/dechiffreur/verifier.py \
              verification/dechiffreur/attendu.json "$sortie"

            # Le conteneur de référence, dépaqueté depuis le seul
            # docs/conteneur.md, puis déchiffré depuis le seul docs/format.md.
            # Les deux documents sont ainsi éprouvés bout à bout, sans qu aucune
            # ligne de Rust n intervienne.
            /opt/verification/bin/python verification/dechiffreur/conteneur.py \
              crates/vault-core/tests/fixtures/container-v1/container.vaultx "$depaquete"
            echo "vault fixture v1 passphrase de reference" \
              | /opt/verification/bin/python verification/dechiffreur/dechiffrer.py \
                  "$depaquete" "$depuis_conteneur"
            /opt/verification/bin/python verification/dechiffreur/verifier.py \
              verification/dechiffreur/attendu.json "$depuis_conteneur"
        '
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
