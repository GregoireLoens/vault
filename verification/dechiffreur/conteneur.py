#!/usr/bin/env python3
"""Dépaqueteur indépendant d'un conteneur d'export — 003, T043.

Écrit depuis le seul ``docs/conteneur.md``. **Rien ici ne vient du code Rust** :
si une étape est fausse, c'est que la section correspondante du document l'est
aussi, ou qu'elle est incomplète. C'est tout ce que ce programme sert à établir.

Il s'arrête là où ``docs/conteneur.md`` s'arrête : il produit un **répertoire de
vault**, et la lecture de ce répertoire revient à ``dechiffrer.py``, qui est
écrit depuis ``docs/format.md``. Cette séparation n'est pas une commodité — elle
est la §1 du document : *le déchiffrement d'un conteneur est exactement celui
d'un vault*.

Usage :

    conteneur.py <conteneur.vaultx> <répertoire-de-sortie>
"""

import os
import sys

import cbor2
from blake3 import blake3

# §3 — constante d'identification et version de ce format.
MAGIC = b"VAULTXFR"
CONTAINER_VERSION = 1

# §5 — marque de fin, en tête du sceau.
END = b"VAULTEND"

# §3 — versions du format de **vault** que ce programme sait produire.
VAULT_FORMAT_VERSIONS = (1,)

# §3 — le `header` et l'`index` sont obligatoires.
MIN_MEMBER_COUNT = 2

# §4 — un identifiant de blob fait 32 octets.
BLOB_ID_LEN = 32

# §4 — bornes de `length`, par type de membre. Une annonce hors bornes est
# refusée **avant toute allocation** : c'est ce qui empêche un conteneur forgé
# de faire réserver de la mémoire à celui qui le lit.
BORNES = {
    "header": 65_536,
    "index": 268_435_456,
    "blob": 4_400_000_000,
}

# §5 — l'empreinte fait 32 octets.
DIGEST_LEN = 32


class Refus(Exception):
    """Le conteneur ne satisfait pas le document."""


class FluxAbsorbant:
    """Un flux d'octets qui absorbe dans un BLAKE3 tout ce qu'il rend.

    §5 : ``digest`` porte sur **tous les octets du conteneur qui précèdent le
    sceau**. L'absorption cesse donc avant de lire le sceau, faute de quoi
    l'empreinte porterait sur elle-même.
    """

    def __init__(self, octets):
        self.octets = octets
        self.position = 0
        self.hacheur = blake3()
        self.absorbe = True

    def lire(self, combien):
        """Rend exactement ``combien`` octets, ou lève ``Refus``."""
        fin = self.position + combien
        if fin > len(self.octets):
            raise Refus(
                f"flux tronqué : {combien} octets attendus, "
                f"{len(self.octets) - self.position} disponibles"
            )
        tranche = self.octets[self.position : fin]
        self.position = fin
        if self.absorbe:
            self.hacheur.update(tranche)
        return tranche

    def lire_carte(self):
        """Lit **une** carte CBOR, sans consommer un octet de plus.

        ``cbor2.loads`` refuse les octets excédentaires ; ``cbor2.load`` sur un
        flux ne dit pas où il s'est arrêté. Le décodage se fait donc sur un
        objet fichier dont on relève la position — c'est le seul moyen, avec
        cette bibliothèque, de respecter la §2 : *le flux se lit d'un bout à
        l'autre, sans jamais revenir en arrière*.
        """
        import io

        tampon = io.BytesIO(self.octets)
        tampon.seek(self.position)
        try:
            valeur = cbor2.load(tampon)
        except Exception as erreur:  # noqa: BLE001 — toute erreur est un refus
            raise Refus(f"CBOR illisible à l'octet {self.position} : {erreur}") from erreur
        consommes = tampon.tell() - self.position
        # Relire par `lire` plutôt que de sauter : c'est ainsi que les octets
        # de la carte entrent dans l'empreinte.
        self.lire(consommes)
        return valeur

    def reste(self):
        return len(self.octets) - self.position


def exiger(condition, message):
    if not condition:
        raise Refus(message)


def champ(carte, nom):
    exiger(isinstance(carte, dict), "une carte CBOR était attendue")
    exiger(nom in carte, f"champ absent : {nom}")
    return carte[nom]


def lire_en_tete(flux):
    """§3 — en-tête, et les règles de lecture qui l'accompagnent."""
    en_tete = flux.lire_carte()

    # « magic et container_version sont lus avant toute autre chose. »
    exiger(champ(en_tete, "magic") == MAGIC, "ce n'est pas un conteneur d'export")
    version = champ(en_tete, "container_version")
    exiger(
        version == CONTAINER_VERSION,
        f"version de conteneur {version} non gérée : ce programme lit la {CONTAINER_VERSION}",
    )

    # « vault_format_version est vérifiée avant d'écrire le moindre octet. »
    version_vault = champ(en_tete, "vault_format_version")
    exiger(
        version_vault in VAULT_FORMAT_VERSIONS,
        f"version de format de vault {version_vault} non gérée",
    )

    membres = champ(en_tete, "member_count")
    exiger(
        isinstance(membres, int) and membres >= MIN_MEMBER_COUNT,
        "un conteneur porte au moins un header et un index",
    )

    volume = champ(en_tete, "payload_bytes")
    exiger(isinstance(volume, int) and volume >= 0, "payload_bytes invalide")

    return membres


def lire_cadre(flux, rang, dernier_blob):
    """§4 — cadre d'un membre, invariants compris.

    Rend ``(kind, identifiant, length, dernier_blob)``.
    """
    cadre = flux.lire_carte()
    kind = champ(cadre, "kind")
    identifiant = champ(cadre, "id")
    length = champ(cadre, "length")

    exiger(kind in BORNES, f"type de membre inconnu : {kind!r}")

    # « header, puis index, puis blob par id strictement croissant. »
    attendu = "header" if rang == 0 else "index" if rang == 1 else "blob"
    exiger(kind == attendu, f"ordre violé : {kind!r} au rang {rang}, {attendu!r} attendu")

    if kind == "blob":
        exiger(
            isinstance(identifiant, bytes) and len(identifiant) == BLOB_ID_LEN,
            "un membre blob porte un identifiant de 32 octets",
        )
        exiger(
            dernier_blob is None or identifiant > dernier_blob,
            "les blobs doivent être triés par identifiant strictement croissant",
        )
        dernier_blob = identifiant
    else:
        exiger(identifiant is None, f"un membre {kind} ne porte pas d'identifiant")

    # Bornée **avant toute allocation**, et avant de lire la charge.
    exiger(isinstance(length, int) and length >= 0, "length invalide")
    exiger(
        length <= BORNES[kind],
        f"length hors bornes pour un membre {kind} : {length}",
    )

    return kind, identifiant, length, dernier_blob


def lire_sceau(flux, membres):
    """§5 — sceau, et refus de tout octet qui le suivrait."""
    # L'empreinte porte sur ce qui précède : l'absorption cesse ici.
    flux.absorbe = False
    calculee = flux.hacheur.digest()

    sceau = flux.lire_carte()
    exiger(champ(sceau, "end") == END, "marque de fin absente ou étrangère")
    exiger(
        champ(sceau, "member_count") == membres,
        "le sceau et l'en-tête ne comptent pas les mêmes membres",
    )
    publiee = champ(sceau, "digest")
    exiger(
        isinstance(publiee, bytes) and len(publiee) == DIGEST_LEN,
        "empreinte de sceau invalide",
    )
    exiger(publiee == calculee, "l'empreinte du sceau diverge : conteneur altéré ou tronqué")

    # « Aucun octet ne suit le sceau. »
    exiger(flux.reste() == 0, f"{flux.reste()} octet(s) suivent le sceau")


def depaqueter(chemin_conteneur, sortie):
    """§6 — la procédure de lecture, pas à pas."""
    flux = FluxAbsorbant(open(chemin_conteneur, "rb").read())

    membres = lire_en_tete(flux)

    os.makedirs(os.path.join(sortie, "objects"), exist_ok=True)

    dernier_blob = None
    blobs = 0
    for rang in range(membres):
        kind, identifiant, length, dernier_blob = lire_cadre(flux, rang, dernier_blob)
        charge = flux.lire(length)

        if kind == "header":
            cible = os.path.join(sortie, "header")
        elif kind == "index":
            cible = os.path.join(sortie, "index")
        else:
            blobs += 1
            cible = os.path.join(sortie, "objects", identifiant.hex())

        with open(cible, "wb") as fichier:
            fichier.write(charge)

        if kind == "blob":
            # §6 — « la date de modification des blobs est ramenée à l'époque
            # Unix », par renvoi à format.md §6.4.
            os.utime(cible, (0, 0))

    lire_sceau(flux, membres)
    return blobs


def main(arguments):
    if len(arguments) != 2:
        print(
            "usage : conteneur.py <conteneur.vaultx> <répertoire-de-sortie>",
            file=sys.stderr,
        )
        return 2

    try:
        blobs = depaqueter(arguments[0], arguments[1])
    except Refus as refus:
        print(f"REFUS {refus}", file=sys.stderr)
        return 1

    print(f"conteneur dépaqueté : header, index et {blobs} blob(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
