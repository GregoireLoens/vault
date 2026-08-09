#!/usr/bin/env python3
"""Déchiffreur indépendant de vault — 002, T008.

Écrit depuis le seul ``docs/format.md``. Voir ``README.md`` pour la règle qui
donne sa valeur à ce programme, et pour ce qu'un échec signifie.

Chaque étape porte en commentaire la section du document dont elle est tirée.
Rien ici ne vient du code Rust : si une étape est fausse, c'est que la section
correspondante l'est aussi, ou qu'elle est incomplète.
"""

import hashlib
import os
import sys

import cbor2
import nacl.bindings as sodium
from argon2.low_level import ARGON2_VERSION, Type, hash_secret_raw
from blake3 import blake3

# §3 — constante d'identification et version de format.
MAGIC = b"VAULTFMT"
FORMAT_VERSION = 1

# §2 — identifiants d'algorithmes, tels qu'ils figurent dans l'en-tête.
KDF_ALGORITHM = "argon2id"
AEAD_ALGORITHM = "xchacha20poly1305"

# §2 — « Toutes les clés font 256 bits. Tous les tags Poly1305 font 16 octets.
# Un nonce XChaCha20-Poly1305 fait 24 octets. »
KEY_LEN = 32
TAG_LEN = 16
NONCE_LEN = 24

# §3 — le sel de dérivation fait 16 octets.
SALT_LEN = 16

# §4.2, §5, §6.2 — données associées, en ASCII.
MASTER_KEY_AAD_PREFIX = b"vault master key v1"
INDEX_AAD = b"vault index v1"
BLOB_AAD_PREFIX = b"vault blob v1"

# §4.3 — contexte de dérivation des clés de blob.
BLOB_KEY_CONTEXT = "vault 2026 blob key v1"

# §6 — disposition d'un blob et découpage STREAM.
STREAM_NONCE_LEN = 19
CHUNK_SIZE = 65536

# §6.1 — un identifiant de blob fait 32 octets, soit 64 chiffres hexadécimaux.
BLOB_ID_LEN = 32


def lire_fichier(chemin):
    """Lit un fichier désigné par un chemin en **octets**.

    §5 : les composants de chemin sont conservés en octets bruts. `pathlib`
    refuse les chemins en octets ; `os.path` et `open` les acceptent, ce qui
    permet de restituer un nom à l'identique quel que soit son encodage.
    """
    with open(chemin, "rb") as fichier:
        return fichier.read()


class EchecDeDechiffrement(Exception):
    """Échec nommant l'étape en défaut.

    L'étape est l'information recherchée : elle désigne la partie du document
    qui est fausse ou incomplète.
    """

    def __init__(self, etape, detail):
        super().__init__(f"[{etape}] {detail}")


def lire_en_tete(repertoire):
    """§3 — décode le fichier ``header``, une carte CBOR à neuf clés."""
    etape = "lecture de l'en-tête"
    try:
        octets = lire_fichier(os.path.join(repertoire, b"header"))
    except OSError as erreur:
        raise EchecDeDechiffrement(etape, f"fichier illisible : {erreur}") from erreur

    try:
        entete = cbor2.loads(octets)
    except Exception as erreur:
        raise EchecDeDechiffrement(etape, f"CBOR illisible : {erreur}") from erreur

    # §3, règles de lecture : « magic et format_version sont lus avant toute
    # autre chose ».
    if entete.get("magic") != MAGIC:
        raise EchecDeDechiffrement(etape, "ce fichier n'est pas un en-tête de vault")
    if entete.get("format_version") != FORMAT_VERSION:
        raise EchecDeDechiffrement(
            etape, f"version de format non gérée : {entete.get('format_version')}"
        )
    if entete.get("kdf_algorithm") != KDF_ALGORITHM:
        raise EchecDeDechiffrement(etape, f"KDF inconnue : {entete.get('kdf_algorithm')}")
    if entete.get("aead_algorithm") != AEAD_ALGORITHM:
        raise EchecDeDechiffrement(etape, f"AEAD inconnu : {entete.get('aead_algorithm')}")
    if len(entete.get("kdf_salt", b"")) != SALT_LEN:
        raise EchecDeDechiffrement(etape, "sel de longueur inattendue")

    return entete


def deriver_cle_enveloppe(passphrase, entete):
    """§4.1 — Argon2id sur la passphrase encodée en UTF-8."""
    etape = "dérivation de la clé d'enveloppe"
    if ARGON2_VERSION != 0x13:
        raise EchecDeDechiffrement(etape, f"version Argon2 inattendue : {ARGON2_VERSION}")
    try:
        return hash_secret_raw(
            secret=passphrase.encode("utf-8"),
            salt=entete["kdf_salt"],
            time_cost=entete["kdf_iterations"],
            memory_cost=entete["kdf_memory_kib"],
            parallelism=entete["kdf_parallelism"],
            hash_len=KEY_LEN,
            type=Type.ID,
            version=ARGON2_VERSION,
        )
    except Exception as erreur:
        raise EchecDeDechiffrement(etape, str(erreur)) from erreur


def contexte_public(entete):
    """§4.2 — encodage à champs de largeur fixe, dans un ordre figé.

    Le document insiste : ce n'est **pas** le CBOR de l'en-tête. Deux encodeurs
    CBOR peuvent produire des octets différents pour la même structure, et
    l'authentification cesserait d'être reproductible.
    """
    return b"".join(
        [
            MAGIC,
            entete["format_version"].to_bytes(4, "big"),
            KDF_ALGORITHM.encode("ascii"),
            entete["kdf_salt"],
            entete["kdf_memory_kib"].to_bytes(4, "big"),
            entete["kdf_iterations"].to_bytes(4, "big"),
            entete["kdf_parallelism"].to_bytes(4, "big"),
            AEAD_ALGORITHM.encode("ascii"),
        ]
    )


def desenvelopper_cle_maitresse(entete, cle_enveloppe):
    """§4.2 — ouvre ``wrapped_master_key``."""
    etape = "désenveloppement de la clé maîtresse"
    enveloppe = entete["wrapped_master_key"]
    if len(enveloppe) < NONCE_LEN + TAG_LEN:
        raise EchecDeDechiffrement(etape, "enveloppe trop courte")

    nonce, chiffre = enveloppe[:NONCE_LEN], enveloppe[NONCE_LEN:]
    aad = MASTER_KEY_AAD_PREFIX + contexte_public(entete)
    try:
        return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(chiffre, aad, nonce, cle_enveloppe)
    except Exception as erreur:
        raise EchecDeDechiffrement(
            etape, "passphrase erronée, ou en-tête altéré — indiscernables par conception"
        ) from erreur


def dechiffrer_index(repertoire, cle_maitresse):
    """§5 — ``nonce (24 o) ‖ CBOR chiffré ‖ tag (16 o)``."""
    etape = "déchiffrement de l'index"
    try:
        octets = lire_fichier(os.path.join(repertoire, b"index"))
    except OSError as erreur:
        raise EchecDeDechiffrement(etape, f"fichier illisible : {erreur}") from erreur
    if len(octets) < NONCE_LEN + TAG_LEN:
        raise EchecDeDechiffrement(etape, "fichier trop court")

    nonce, chiffre = octets[:NONCE_LEN], octets[NONCE_LEN:]
    try:
        clair = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            chiffre, INDEX_AAD, nonce, cle_maitresse
        )
    except Exception as erreur:
        raise EchecDeDechiffrement(etape, "index altéré ou clé erronée") from erreur

    try:
        index = cbor2.loads(clair)
    except Exception as erreur:
        raise EchecDeDechiffrement(etape, f"CBOR illisible : {erreur}") from erreur

    verifier_invariants(index)
    return index


def verifier_invariants(index):
    """§5, invariants — « une implémentation lisant l'index doit les vérifier ».

    Le document précise pourquoi : un vault forgé puis remis à sa victime ne
    doit pas pouvoir faire écrire l'extraction hors de sa destination. La
    vérification a donc lieu **après** une authentification réussie.
    """
    etape = "invariants de l'index"
    entrees = index.get("entries")
    if entrees is None:
        raise EchecDeDechiffrement(etape, "l'index ne porte pas de champ « entries »")

    chemins = [entree.get("path") for entree in entrees]
    if any(precedent >= suivant for precedent, suivant in zip(chemins, chemins[1:])):
        raise EchecDeDechiffrement(etape, "entrées non strictement ordonnées par chemin")

    for entree in entrees:
        genre = entree.get("kind")
        porte = (
            entree.get("size") is not None
            and entree.get("blob_id") is not None
            and entree.get("blob_padded_size") is not None
        )
        if genre == "File" and not porte:
            raise EchecDeDechiffrement(etape, "entrée « File » incomplète")
        if genre == "Directory" and porte:
            raise EchecDeDechiffrement(etape, "entrée « Directory » porteuse de champs de fichier")
        if genre not in ("File", "Directory"):
            raise EchecDeDechiffrement(etape, f"genre d'entrée inconnu : {genre}")

        for composant in entree.get("path", []):
            if composant in (b"", b".", b"..") or any(o in composant for o in (b"/", b"\\", b"\0")):
                raise EchecDeDechiffrement(etape, "composant de chemin interdit")


def deriver_cle_blob(cle_maitresse, blob_id):
    """§4.3 — BLAKE3 en mode ``derive_key``.

    « Initialiser BLAKE3 en mode dérivation avec la chaîne de contexte,
    absorber les 32 octets de la clé maîtresse puis les 32 octets de
    l'identifiant, et prendre les 32 premiers octets de la sortie. »
    """
    empreinte = blake3(cle_maitresse + blob_id, derive_key_context=BLOB_KEY_CONTEXT)
    return empreinte.digest(length=KEY_LEN)


def nombre_de_morceaux(taille):
    """§6.2 — ``max(1, plafond(taille / 65536))``."""
    return max(1, -(-taille // CHUNK_SIZE))


def dechiffrer_blob(chemin_blob, cle_blob, blob_id, taille):
    """§6.2 — STREAM BE32 sur XChaCha20-Poly1305.

    Aucune bibliothèque Python n'implémente STREAM : la construction est
    rebâtie ici à partir de la primitive, en suivant la description du nonce
    donnée par le document. C'est le point où une spécification approximative se
    paie le plus cher, et donc celui que ce programme éprouve le mieux.
    """
    etape = "déchiffrement d'un blob"
    try:
        octets = lire_fichier(chemin_blob)
    except OSError as erreur:
        raise EchecDeDechiffrement(etape, f"blob illisible : {erreur}") from erreur

    morceaux = nombre_de_morceaux(taille)
    longueur_chiffre = taille + TAG_LEN * morceaux
    if len(octets) < STREAM_NONCE_LEN + longueur_chiffre:
        raise EchecDeDechiffrement(etape, "blob tronqué")

    # §6 — au-delà de la zone lue commence le remplissage, qui n'est ni
    # déchiffré ni interprété.
    nonce_stream = octets[:STREAM_NONCE_LEN]
    chiffre = octets[STREAM_NONCE_LEN : STREAM_NONCE_LEN + longueur_chiffre]
    aad = BLOB_AAD_PREFIX + blob_id

    clair = bytearray()
    position = 0
    for numero in range(morceaux):
        dernier = numero == morceaux - 1
        clair_attendu = taille - position if dernier else CHUNK_SIZE
        bloc = chiffre[position + numero * TAG_LEN :][: clair_attendu + TAG_LEN]

        # §6.2 — « nonce_stream ‖ n en gros-boutiste sur 4 o ‖ drapeau », le
        # drapeau valant 0x01 pour le dernier morceau et 0x00 pour les autres.
        nonce = nonce_stream + numero.to_bytes(4, "big") + (b"\x01" if dernier else b"\x00")
        try:
            morceau = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                bloc, aad, nonce, cle_blob
            )
        except Exception as erreur:
            raise EchecDeDechiffrement(
                etape, f"morceau {numero} non authentifié — blob altéré ou nonce mal construit"
            ) from erreur

        clair += morceau
        position += len(morceau)

    if len(clair) != taille:
        raise EchecDeDechiffrement(etape, f"{len(clair)} octets restitués, {taille} attendus")
    return bytes(clair)


def restituer(repertoire, sortie, passphrase):
    """§8 — procédure de déchiffrement complète, dans l'ordre du document."""
    entete = lire_en_tete(repertoire)
    cle_enveloppe = deriver_cle_enveloppe(passphrase, entete)
    cle_maitresse = desenvelopper_cle_maitresse(entete, cle_enveloppe)
    index = dechiffrer_index(repertoire, cle_maitresse)

    restitues = {}
    for entree in index["entries"]:
        relatif = os.path.join(*entree["path"]) if entree["path"] else b""
        cible = os.path.join(sortie, relatif)

        if entree["kind"] == "Directory":
            os.makedirs(cible, exist_ok=True)
            continue

        blob_id = entree["blob_id"]
        if len(blob_id) != BLOB_ID_LEN:
            raise EchecDeDechiffrement("index", "identifiant de blob de longueur inattendue")

        # §6 — le blob est nommé par les 64 chiffres hexadécimaux minuscules de
        # son identifiant.
        chemin_blob = os.path.join(repertoire, b"objects", blob_id.hex().encode("ascii"))
        cle_blob = deriver_cle_blob(cle_maitresse, blob_id)
        contenu = dechiffrer_blob(chemin_blob, cle_blob, blob_id, entree["size"])

        os.makedirs(os.path.dirname(cible), exist_ok=True)
        with open(cible, "wb") as fichier:
            fichier.write(contenu)
        restitues[relatif] = hashlib.sha256(contenu).hexdigest()

    return restitues


def main(arguments):
    if len(arguments) != 2:
        print(
            "usage : dechiffrer.py <répertoire-du-vault> <répertoire-de-sortie>\n"
            "        la passphrase est lue sur l'entrée standard",
            file=sys.stderr,
        )
        return 2

    repertoire = os.fsencode(arguments[0])
    sortie = os.fsencode(arguments[1])
    passphrase = sys.stdin.readline().rstrip("\n")

    os.makedirs(sortie, exist_ok=True)
    try:
        restitues = restituer(repertoire, sortie, passphrase)
    except EchecDeDechiffrement as echec:
        print(f"ÉCHEC {echec}", file=sys.stderr)
        return 1

    print(f"{len(restitues)} fichier(s) restitué(s) dans {os.fsdecode(sortie)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
