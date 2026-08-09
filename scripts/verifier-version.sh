#!/usr/bin/env bash
#
# Vérifie que les numéros de version du dépôt valent exactement celui attendu.
#
#   ./scripts/verifier-version.sh 1.1.0
#   ./scripts/verifier-version.sh v1.1.0     (le « v » est toléré)
#
# Pourquoi ce script existe
# -------------------------
# `clap` lit CARGO_PKG_VERSION : le numéro de crate EST ce que `vault --version`
# annonce à l'utilisateur. Rien ne le reliait au tag de la livraison.
#
# Le défaut s'est produit deux fois. Les tags v0.1.0 à v0.4.0 ont été posés sur
# des crates restées en 0.1.0 — quatre livraisons pendant lesquelles le binaire
# a menti sur sa propre version. La 1.1.0 y a échappé de justesse, parce que
# quelqu'un s'est souvenu de regarder.
#
# Une garantie qui tient à ce que quelqu'un se souvienne n'est pas une garantie.
#
# Ce script n'a besoin d'aucune chaîne d'outils : bash suffit, il tourne sur
# l'hôte comme dans l'exécuteur d'intégration continue.
#
set -euo pipefail

attendue="${1:-}"
if [[ -z "$attendue" ]]; then
    echo "usage : $0 <X.Y.Z>" >&2
    exit 2
fi
attendue="${attendue#v}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Le numéro déclaré dans un manifeste : première ligne `version = "…"`, qui est
# celle du [package] — les dépendances déclarent leur version autrement.
version_du_manifeste() {
    awk -F'"' '/^version = /{print $2; exit}' "$1"
}

# Le numéro épinglé dans un verrou pour un paquet donné : la ligne `version`
# qui suit immédiatement son `name`.
version_du_verrou() {
    awk -F'"' -v paquet="$2" '
        $0 == "name = \"" paquet "\"" { trouve = 1; next }
        trouve && /^version = / { print $2; exit }
    ' "$1"
}

# Le verrou de fuzz/ compte : le crate est hors de l'espace de travail, donc
# aucune porte de compilation ne le remet à jour. Oublié, il épingle l'ancienne
# version et la voit changer sous lui à la prochaine campagne.
declare -a sujets=(
    "crates/vault-core/Cargo.toml|$(version_du_manifeste crates/vault-core/Cargo.toml)"
    "crates/vault-cli/Cargo.toml|$(version_du_manifeste crates/vault-cli/Cargo.toml)"
    "Cargo.lock (vault-core)|$(version_du_verrou Cargo.lock vault-core)"
    "Cargo.lock (vault-cli)|$(version_du_verrou Cargo.lock vault-cli)"
    "fuzz/Cargo.lock (vault-core)|$(version_du_verrou fuzz/Cargo.lock vault-core)"
)

echo "Version attendue : $attendue"
echo

ecarts=0
for sujet in "${sujets[@]}"; do
    ou="${sujet%%|*}"
    trouvee="${sujet#*|}"

    if [[ -z "$trouvee" ]]; then
        # Une extraction vide ne veut pas dire « conforme » : elle veut dire que
        # le fichier n'a plus la forme attendue. Le taire ferait passer la porte
        # au vert sans avoir rien vérifié — exactement le défaut qu'elle traque.
        printf '  ✗ %-32s introuvable — le fichier a changé de forme\n' "$ou"
        ecarts=$((ecarts + 1))
    elif [[ "$trouvee" != "$attendue" ]]; then
        printf '  ✗ %-32s %s\n' "$ou" "$trouvee"
        ecarts=$((ecarts + 1))
    else
        printf '  ✓ %-32s %s\n' "$ou" "$trouvee"
    fi
done

echo
if (( ecarts > 0 )); then
    if (( ecarts == 1 )); then
        echo "1 écart. Corrigez-le avant de livrer." >&2
    else
        echo "$ecarts écarts. Corrigez-les avant de livrer." >&2
    fi
    echo "Un numéro qui ne suit pas le tag fait mentir \`vault --version\`." >&2
    exit 1
fi
echo "Les cinq numéros valent $attendue."
