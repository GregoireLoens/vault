#!/usr/bin/env python3
"""Vecteurs de test du format — 002, T013.

Imprime les valeurs intermédiaires de la chaîne de dérivation, pour le vault de
référence de format 1. Elles sont publiées dans ``docs/format.md`` afin qu'un
tiers puisse situer l'étape exacte où son implémentation diverge, **sans
exécuter vault**.

Elles sont calculées ici par le déchiffreur indépendant, et non par le logiciel :
des vecteurs produits par le code qu'ils servent à vérifier ne vérifieraient
rien.

Ces valeurs appartiennent à un vault dont la passphrase est publique et qui ne
protège rien. Ce n'est pas un exemple à imiter.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dechiffrer import (  # noqa: E402
    BLOB_AAD_PREFIX,
    MASTER_KEY_AAD_PREFIX,
    STREAM_NONCE_LEN,
    contexte_public,
    dechiffrer_index,
    deriver_cle_blob,
    deriver_cle_enveloppe,
    desenvelopper_cle_maitresse,
    lire_en_tete,
    lire_fichier,
)

PASSPHRASE = "vault fixture v1 passphrase de reference"
REFERENCE = b"crates/vault-core/tests/fixtures/v1"
ENTREE_TEMOIN = "lisez-moi.txt"


def ligne(intitule, valeur):
    if isinstance(valeur, bytes):
        print(f"{intitule:<28} {valeur.hex()}  ({len(valeur)} o)")
    else:
        print(f"{intitule:<28} {valeur}")


def main():
    entete = lire_en_tete(REFERENCE)
    print("== En-tête, champs publics ==")
    ligne("format_version", entete["format_version"])
    ligne("kdf_salt", entete["kdf_salt"])
    ligne("kdf_memory_kib", entete["kdf_memory_kib"])
    ligne("kdf_iterations", entete["kdf_iterations"])
    ligne("kdf_parallelism", entete["kdf_parallelism"])

    print("\n== Chaîne de dérivation ==")
    ligne("passphrase (UTF-8)", PASSPHRASE.encode("utf-8"))
    cle_enveloppe = deriver_cle_enveloppe(PASSPHRASE, entete)
    ligne("clé d'enveloppe", cle_enveloppe)
    ligne("contexte public", contexte_public(entete))
    ligne("AAD clé maîtresse", MASTER_KEY_AAD_PREFIX + contexte_public(entete))
    cle_maitresse = desenvelopper_cle_maitresse(entete, cle_enveloppe)
    ligne("clé maîtresse", cle_maitresse)

    print("\n== Une entrée témoin ==")
    index = dechiffrer_index(REFERENCE, cle_maitresse)
    entree = next(
        e for e in index["entries"] if b"/".join(e["path"]).decode("utf-8") == ENTREE_TEMOIN
    )
    ligne("chemin", ENTREE_TEMOIN)
    ligne("size", entree["size"])
    ligne("blob_id", entree["blob_id"])
    ligne("clé de blob", deriver_cle_blob(cle_maitresse, entree["blob_id"]))
    ligne("AAD du blob", BLOB_AAD_PREFIX + entree["blob_id"])

    blob = lire_fichier(
        os.path.join(REFERENCE, b"objects", entree["blob_id"].hex().encode("ascii"))
    )
    nonce_stream = blob[:STREAM_NONCE_LEN]
    ligne("nonce STREAM", nonce_stream)
    ligne("nonce du morceau 0", nonce_stream + (0).to_bytes(4, "big") + b"\x01")
    ligne("blob_padded_size", entree["blob_padded_size"])


if __name__ == "__main__":
    main()
