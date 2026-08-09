#!/usr/bin/env python3
"""Vérificateur de restitution — 002, T009.

Compare **octet pour octet** ce que le déchiffreur indépendant a restitué au
contenu attendu, lequel est dérivé de la seule documentation du vault de
référence (voir ``attendu.py``).

Les dates du système de fichiers ne sont pas comparées : la restitution ne
prétend pas les reproduire pour le vault de référence, et git ne les conserve
pas de toute façon.
"""

import hashlib
import json
import os
import pathlib
import sys


def empreintes(racine):
    """Chemins relatifs et empreintes de tout ce qui a été restitué."""
    trouves = {}
    dossiers = set()
    for repertoire, sous_repertoires, fichiers in os.walk(racine):
        relatif_base = os.path.relpath(repertoire, racine)
        for sous in sous_repertoires:
            chemin = sous if relatif_base == "." else os.path.join(relatif_base, sous)
            dossiers.add(chemin.replace(os.sep, "/"))
        for fichier in fichiers:
            chemin = fichier if relatif_base == "." else os.path.join(relatif_base, fichier)
            octets = pathlib.Path(repertoire, fichier).read_bytes()
            trouves[chemin.replace(os.sep, "/")] = {
                "taille": len(octets),
                "sha256": hashlib.sha256(octets).hexdigest(),
            }
    return trouves, dossiers


def comparer(attendu, trouves, dossiers):
    """Rend la liste des divergences, la plus parlante d'abord."""
    divergences = []

    for nom in sorted(attendu["dossiers"]):
        if nom not in dossiers:
            divergences.append(f"dossier manquant : {nom}")

    for nom, prevu in sorted(attendu["fichiers"].items()):
        obtenu = trouves.get(nom)
        if obtenu is None:
            divergences.append(f"fichier manquant : {nom}")
        elif obtenu["taille"] != prevu["taille"]:
            divergences.append(
                f"{nom} : {obtenu['taille']} octets restitués, {prevu['taille']} attendus"
            )
        elif obtenu["sha256"] != prevu["sha256"]:
            divergences.append(f"{nom} : contenu différent à taille égale")

    for nom in sorted(set(trouves) - set(attendu["fichiers"])):
        divergences.append(f"fichier restitué en trop : {nom}")

    return divergences


def main(arguments):
    if len(arguments) != 2:
        print(
            "usage : verifier.py <attendu.json> <répertoire-restitué>",
            file=sys.stderr,
        )
        return 2

    attendu = json.loads(pathlib.Path(arguments[0]).read_text(encoding="utf-8"))
    trouves, dossiers = empreintes(arguments[1])
    divergences = comparer(attendu, trouves, dossiers)

    if divergences:
        for divergence in divergences:
            print(f"DIVERGENCE {divergence}", file=sys.stderr)
        return 1

    print(f"{len(attendu['fichiers'])} fichier(s) restitué(s) à l'identique, octet pour octet")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
