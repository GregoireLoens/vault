#!/usr/bin/env python3
"""Contenu attendu du vault de référence — 002, T007.

**Source unique : `crates/vault-core/tests/fixtures/README.md`**, dont la table
« Contenu » définit chaque fichier à l'octet près.

Ni le code Rust ni la sortie du logiciel n'entrent ici. Un contenu attendu qu'on
ne pourrait obtenir qu'en exécutant vault ne prouverait rien : il faudrait
croire le logiciel sur parole pour vérifier le logiciel.

Exécuté sans argument, ce module réécrit ``attendu.json`` sur la sortie
standard, ce qui rend la dérivation reproductible par quiconque.
"""

import hashlib
import json
import sys

# Transcription de la table « Contenu » du README des références.
DOSSIERS = ["photos"]

CONTENUS = {
    "lisez-moi.txt": "Vault de référence, format 1.\nCe fichier ne doit jamais changer.\n".encode(
        "utf-8"
    ),
    "vide.bin": b"",
    "photos/été.jpg": bytes(range(256)),
    "photos/grand.bin": bytes(index % 251 for index in range(70000)),
}


def attendu():
    return {
        "source": "crates/vault-core/tests/fixtures/README.md",
        "dossiers": DOSSIERS,
        "fichiers": {
            nom: {"taille": len(octets), "sha256": hashlib.sha256(octets).hexdigest()}
            for nom, octets in sorted(CONTENUS.items())
        },
    }


if __name__ == "__main__":
    json.dump(attendu(), sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
