//! Conteneur d'export — T007 à T012.
//!
//! Un conteneur **cadre** un vault ; il ne le chiffre pas. Tous les octets de
//! contenu qu'il transporte sont ceux que le vault a écrits, recopiés sans être
//! ouverts (D-201). Ce module n'ajoute donc **aucune** chaîne de dérivation,
//! aucune donnée associée, aucune primitive : le déchiffrement d'un conteneur
//! est exactement celui d'un vault, décrit par `docs/format.md`.
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │ EN-TÊTE     carte CBOR, en clair            │
//! ├─────────────────────────────────────────────┤
//! │ CADRE 1 ‖ CHARGE 1                          │
//! │ CADRE 2 ‖ CHARGE 2 …                        │
//! ├─────────────────────────────────────────────┤
//! │ SCEAU       carte CBOR, en clair            │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! # Ce que le sceau établit, et ce qu'il n'établit pas
//!
//! Le sceau détecte une **troncature** et une **corruption accidentelle**. Il
//! **ne détecte pas une falsification** : c'est un BLAKE3 nu, sans clé, et
//! quiconque réécrit un conteneur peut le recalculer. L'authenticité du contenu
//! vient des tags AEAD du format de vault, contrôlés au **déverrouillage**,
//! avec la passphrase — dont un import ne dispose pas (FR-018).
//!
//! Ce paragraphe est normatif au même titre que la disposition : une
//! implémentation qui présenterait un sceau vert comme une garantie d'intégrité
//! au sens fort tromperait son utilisateur.
//!
//! # `length` est la surface hostile de ce format
//!
//! C'est une valeur annoncée par une source non authentifiée, qui commande une
//! lecture. Elle est donc **bornée avant tout usage**, par type de membre, et
//! une annonce hors bornes est refusée sans qu'aucune allocation ne soit
//! tentée. Le conteneur devient ainsi la cinquième surface de décodage du
//! projet, aux côtés de l'en-tête, de l'index, des chemins et des blobs.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::format::blob::BlobId;
use crate::format::version;

/// Constante d'identification d'un conteneur, en tête de son en-tête.
///
/// Distincte de [`crate::format::version::MAGIC`], qui vaut `VAULTFMT` : c'est
/// elle qui permet de dire qu'un fichier est un conteneur **avant** toute autre
/// lecture.
pub const CONTAINER_MAGIC: [u8; 8] = *b"VAULTXFR";

/// Marque de fin, en tête du sceau.
pub const CONTAINER_END: [u8; 8] = *b"VAULTEND";

/// Version du format de conteneur produite par cette version du logiciel.
///
/// **Indépendante** de [`crate::format::version::FORMAT_VERSION`] : les deux
/// formats évoluent séparément (FR-003).
pub const CONTAINER_VERSION: u32 = 1;

/// Versions de format de conteneur que cette version du logiciel sait lire.
///
/// Point unique où la liste s'étendra, plutôt que de laisser la comparaison se
/// disséminer dans le code. FR-017 : toute version future doit lire toutes les
/// versions antérieures.
const READABLE_CONTAINER_VERSIONS: &[u32] = &[1];

/// Borne supérieure de la charge d'un membre `header`, en octets.
///
/// Un en-tête réel fait environ deux cents octets.
const MAX_HEADER_PAYLOAD: u64 = 65_536;

/// Borne supérieure de la charge d'un membre `index`, en octets.
///
/// Des millions d'entrées, largement au delà de l'usage.
const MAX_INDEX_PAYLOAD: u64 = 268_435_456;

/// Borne supérieure de la charge d'un membre `blob`, en octets.
///
/// La borne de contenu de `docs/format.md` §6.5, tags, nonce et remplissage
/// compris, arrondie au large.
const MAX_BLOB_PAYLOAD: u64 = 4_400_000_000;

/// Nombre minimal de membres : le `header` et l'`index` sont obligatoires.
const MIN_MEMBER_COUNT: u64 = 2;

/// Type d'un membre du conteneur.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberKind {
    /// Le fichier `header` du vault.
    Header,
    /// Le fichier `index` du vault.
    Index,
    /// Un fichier de `objects/`.
    Blob,
}

impl MemberKind {
    /// Le nom que porte ce type dans le cadre CBOR. Il fait partie du format.
    fn as_str(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::Index => "index",
            Self::Blob => "blob",
        }
    }

    /// Relit un type depuis un cadre.
    fn from_str(texte: &str) -> Result<Self> {
        match texte {
            "header" => Ok(Self::Header),
            "index" => Ok(Self::Index),
            "blob" => Ok(Self::Blob),
            _ => Err(Error::Corrupted),
        }
    }

    /// Borne supérieure de la charge d'un membre de ce type.
    fn max_payload(self) -> u64 {
        match self {
            Self::Header => MAX_HEADER_PAYLOAD,
            Self::Index => MAX_INDEX_PAYLOAD,
            Self::Blob => MAX_BLOB_PAYLOAD,
        }
    }
}

/// Représentation CBOR de l'en-tête. Les noms de champs font partie du format.
#[derive(Serialize, Deserialize)]
struct ContainerHeaderRepr {
    magic: serde_bytes::ByteBuf,
    container_version: u32,
    vault_format_version: u32,
    member_count: u64,
    payload_bytes: u64,
}

/// Représentation CBOR d'un cadre de membre.
#[derive(Serialize, Deserialize)]
struct MemberFrameRepr {
    kind: String,
    id: Option<serde_bytes::ByteBuf>,
    length: u64,
}

/// Représentation CBOR du sceau.
#[derive(Serialize, Deserialize)]
struct SealRepr {
    end: serde_bytes::ByteBuf,
    member_count: u64,
    digest: serde_bytes::ByteBuf,
}

/// En-tête d'un conteneur, tel qu'il a été lu et validé.
///
/// C'est exactement ce que `vault info` a le droit d'afficher d'un conteneur
/// (FR-034) : rien n'y renseigne sur le contenu du vault transporté.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContainerHeader {
    /// Version du format de conteneur.
    pub container_version: u32,
    /// Version du format du vault transporté.
    pub vault_format_version: u32,
    /// Nombre de membres annoncés.
    pub member_count: u64,
    /// Somme des longueurs de charge annoncées.
    pub payload_bytes: u64,
}

/// Cadre d'un membre, tel qu'il a été lu et validé.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberFrame {
    /// Type du membre.
    pub kind: MemberKind,
    /// Identifiant du blob, pour un membre `blob` uniquement.
    pub id: Option<BlobId>,
    /// Nombre d'octets de la charge qui suit immédiatement.
    pub length: u64,
}

/// Lecteur qui absorbe dans un BLAKE3 tout ce qu'il rend.
///
/// L'absorption cesse avant le sceau : le sceau porte l'empreinte de ce qui le
/// précède, donc pas de lui-même.
struct HashingReader<R> {
    inner: R,
    hasher: blake3::Hasher,
    hashing: bool,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let lus = self.inner.read(buf)?;
        if self.hashing {
            self.hasher.update(&buf[..lus]);
        }
        Ok(lus)
    }
}

/// Écrivain qui absorbe dans un BLAKE3 tout ce qu'il transmet.
struct HashingWriter<W> {
    inner: W,
    hasher: blake3::Hasher,
    hashing: bool,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let ecrits = self.inner.write(buf)?;
        if self.hashing {
            self.hasher.update(&buf[..ecrits]);
        }
        Ok(ecrits)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Écriture d'un conteneur, membre après membre.
///
/// L'en-tête annonce le nombre de membres et le volume total : ils doivent donc
/// être connus **avant** d'écrire le premier octet. C'est ce qui permet à un
/// import de contrôler l'espace disponible avant sa première écriture (FR-014
/// et le cas limite du disque plein).
pub(crate) struct ContainerWriter<W: Write> {
    writer: HashingWriter<W>,
    member_count: u64,
}

impl<W: Write> ContainerWriter<W> {
    /// Écrit l'en-tête et ouvre le conteneur.
    ///
    /// # Errors
    ///
    /// [`Error::Corrupted`] si l'encodage CBOR échoue, [`Error::Io`] si
    /// l'écriture échoue.
    pub(crate) fn begin(
        writer: W,
        vault_format_version: u32,
        member_count: u64,
        payload_bytes: u64,
    ) -> Result<Self> {
        let mut writer = HashingWriter {
            inner: writer,
            hasher: blake3::Hasher::new(),
            hashing: true,
        };

        let repr = ContainerHeaderRepr {
            magic: serde_bytes::ByteBuf::from(CONTAINER_MAGIC.to_vec()),
            container_version: CONTAINER_VERSION,
            vault_format_version,
            member_count,
            payload_bytes,
        };
        ciborium::into_writer(&repr, &mut writer).map_err(encodage)?;

        Ok(Self {
            writer,
            member_count,
        })
    }

    /// Écrit le cadre d'un membre puis sa charge, prise à la source.
    ///
    /// La charge n'est **jamais** rassemblée en mémoire : un blob de plusieurs
    /// gigaoctets passe par le tampon de [`std::io::copy`].
    ///
    /// # Errors
    ///
    /// - [`Error::Corrupted`] si l'encodage échoue, ou si la source rend moins
    ///   d'octets qu'annoncé — le conteneur serait alors incohérent, et il vaut
    ///   mieux échouer que produire un flux qu'aucun import ne pourra lire ;
    /// - [`Error::Io`] si l'écriture ou la lecture échouent.
    pub(crate) fn member<R: Read>(
        &mut self,
        kind: MemberKind,
        id: Option<BlobId>,
        length: u64,
        source: &mut R,
    ) -> Result<()> {
        let repr = MemberFrameRepr {
            kind: kind.as_str().to_owned(),
            id: id.map(Into::into),
            length,
        };
        ciborium::into_writer(&repr, &mut self.writer).map_err(encodage)?;

        let copies = std::io::copy(&mut source.take(length), &mut self.writer)?;
        if copies != length {
            return Err(Error::Corrupted);
        }
        Ok(())
    }

    /// Écrit le sceau et rend l'écrivain sous-jacent.
    ///
    /// # Errors
    ///
    /// [`Error::Corrupted`] si l'encodage échoue, [`Error::Io`] si l'écriture
    /// échoue.
    pub(crate) fn finish(mut self) -> Result<W> {
        // Le sceau porte l'empreinte de ce qui le précède : l'absorption cesse
        // avant de l'écrire.
        self.writer.hashing = false;
        let digest = self.writer.hasher.finalize();

        let repr = SealRepr {
            end: serde_bytes::ByteBuf::from(CONTAINER_END.to_vec()),
            member_count: self.member_count,
            digest: serde_bytes::ByteBuf::from(digest.as_bytes().to_vec()),
        };
        ciborium::into_writer(&repr, &mut self.writer).map_err(encodage)?;
        self.writer.flush()?;
        Ok(self.writer.inner)
    }
}

/// Lecture d'un conteneur, membre après membre.
///
/// Le flux se lit d'un bout à l'autre, sans jamais revenir en arrière : c'est
/// ce qui le rend utilisable dans un tube.
pub(crate) struct ContainerReader<R: Read> {
    reader: HashingReader<R>,
    header: ContainerHeader,
    lus: u64,
    dernier_blob: Option<BlobId>,
}

impl<R: Read> ContainerReader<R> {
    /// Lit et valide l'en-tête.
    ///
    /// `magic` et `container_version` sont vérifiés **avant toute autre
    /// chose** : une constante différente signifie que ce n'est pas un
    /// conteneur, et une version inconnue provoque un refus explicite, jamais
    /// une lecture approximative.
    ///
    /// # Errors
    ///
    /// - [`Error::Corrupted`] si le flux n'est pas un conteneur lisible, ou si
    ///   son en-tête annonce moins de deux membres ;
    /// - [`Error::UnsupportedFormatVersion`] si la version de conteneur ou celle
    ///   du vault transporté dépasse ce que ce logiciel sait lire.
    pub(crate) fn open(reader: R) -> Result<Self> {
        let mut reader = HashingReader {
            inner: reader,
            hasher: blake3::Hasher::new(),
            hashing: true,
        };

        let repr: ContainerHeaderRepr =
            ciborium::from_reader(&mut reader).map_err(|_| Error::Corrupted)?;

        if repr.magic.as_slice() != CONTAINER_MAGIC {
            return Err(Error::Corrupted);
        }
        if !READABLE_CONTAINER_VERSIONS.contains(&repr.container_version) {
            return Err(Error::UnsupportedFormatVersion {
                found: repr.container_version,
                supported: CONTAINER_VERSION,
            });
        }
        // Refusée ici, donc **avant** d'écrire le moindre octet à destination.
        if !version::is_readable(repr.vault_format_version) {
            return Err(Error::UnsupportedFormatVersion {
                found: repr.vault_format_version,
                supported: version::FORMAT_VERSION,
            });
        }
        if repr.member_count < MIN_MEMBER_COUNT {
            return Err(Error::Corrupted);
        }

        Ok(Self {
            header: ContainerHeader {
                container_version: repr.container_version,
                vault_format_version: repr.vault_format_version,
                member_count: repr.member_count,
                payload_bytes: repr.payload_bytes,
            },
            reader,
            lus: 0,
            dernier_blob: None,
        })
    }

    /// L'en-tête déjà validé.
    pub(crate) fn header(&self) -> ContainerHeader {
        self.header
    }

    /// Lit le cadre du membre suivant, ou `None` quand tous ont été lus.
    ///
    /// Applique les invariants normatifs : type connu, présence ou absence de
    /// l'identifiant selon le type, bornes de la longueur, et **ordre** —
    /// `header`, puis `index`, puis les blobs par identifiant **strictement**
    /// croissant, ce qui exclut du même coup les doublons.
    ///
    /// # Errors
    ///
    /// [`Error::Corrupted`] si le cadre est illisible ou viole un invariant,
    /// [`Error::Io`] si la lecture échoue.
    pub(crate) fn next_frame(&mut self) -> Result<Option<MemberFrame>> {
        if self.lus == self.header.member_count {
            return Ok(None);
        }

        let repr: MemberFrameRepr =
            ciborium::from_reader(&mut self.reader).map_err(|_| Error::Corrupted)?;
        let kind = MemberKind::from_str(&repr.kind)?;

        // L'ordre est normatif : c'est ce qui rend deux exports d'un vault
        // inchangé identiques octet pour octet, et donc ce qui permet de
        // comparer deux conteneurs sans les ouvrir.
        let attendu = match self.lus {
            0 => MemberKind::Header,
            1 => MemberKind::Index,
            _ => MemberKind::Blob,
        };
        if kind != attendu {
            return Err(Error::Corrupted);
        }

        let id = match (kind, repr.id) {
            (MemberKind::Blob, Some(octets)) => {
                let id = BlobId::try_from(octets)?;
                if self.dernier_blob.is_some_and(|dernier| id <= dernier) {
                    return Err(Error::Corrupted);
                }
                self.dernier_blob = Some(id);
                Some(id)
            }
            (MemberKind::Header | MemberKind::Index, None) => None,
            _ => return Err(Error::Corrupted),
        };

        // Bornée **avant** toute allocation et avant toute lecture de la charge.
        if repr.length > kind.max_payload() {
            return Err(Error::Corrupted);
        }

        self.lus += 1;
        Ok(Some(MemberFrame {
            kind,
            id,
            length: repr.length,
        }))
    }

    /// Copie la charge du membre que [`Self::next_frame`] vient de rendre.
    ///
    /// # Errors
    ///
    /// [`Error::Corrupted`] si le flux s'arrête avant la fin de la charge —
    /// une troncature à mi-charge —, [`Error::Io`] si la lecture ou l'écriture
    /// échouent.
    pub(crate) fn copy_payload(&mut self, frame: &MemberFrame, sink: &mut dyn Write) -> Result<()> {
        let copies = std::io::copy(&mut (&mut self.reader).take(frame.length), sink)?;
        if copies != frame.length {
            return Err(Error::Corrupted);
        }
        Ok(())
    }

    /// Lit le sceau, le vérifie, et refuse tout octet qui le suivrait.
    ///
    /// # Errors
    ///
    /// [`Error::Corrupted`] si le sceau est absent, si sa marque de fin ou son
    /// compte de membres ne correspondent pas, si l'empreinte diverge, ou si le
    /// flux ne s'arrête pas là. [`Error::Io`] si la lecture échoue.
    pub(crate) fn finish(mut self) -> Result<()> {
        // Le sceau porte l'empreinte de ce qui le précède : l'absorption cesse
        // avant de le lire.
        self.reader.hashing = false;
        let attendu = self.reader.hasher.finalize();

        let repr: SealRepr =
            ciborium::from_reader(&mut self.reader).map_err(|_| Error::Corrupted)?;

        if repr.end.as_slice() != CONTAINER_END
            || repr.member_count != self.header.member_count
            || repr.digest.as_slice() != attendu.as_bytes()
        {
            return Err(Error::Corrupted);
        }

        // Aucun octet ne suit le sceau. Sans cette vérification, un conteneur
        // valide suivi de n'importe quoi passerait pour intact.
        let mut surplus = [0u8; 1];
        if self.reader.inner.read(&mut surplus)? != 0 {
            return Err(Error::Corrupted);
        }
        Ok(())
    }
}

/// Un échec d'encodage CBOR suppose une défaillance mémoire ou un écrivain
/// rompu ; dans les deux cas le conteneur produit serait inexploitable.
fn encodage<E>(_: ciborium::ser::Error<E>) -> Error {
    Error::Corrupted
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construit un conteneur minimal : un `header`, un `index`, et les blobs
    /// demandés dans l'ordre où ils sont fournis.
    fn conteneur(membres: &[(MemberKind, Option<BlobId>, &[u8])]) -> Vec<u8> {
        let volume = membres.iter().map(|(_, _, c)| c.len() as u64).sum();
        let mut writer =
            ContainerWriter::begin(Vec::new(), 1, membres.len() as u64, volume).expect("ouvrable");
        for (kind, id, contenu) in membres {
            writer
                .member(*kind, *id, contenu.len() as u64, &mut &contenu[..])
                .expect("écrivable");
        }
        writer.finish().expect("scellable")
    }

    fn blob_id(premier: u8) -> BlobId {
        let mut octets = vec![0u8; crate::format::blob::BLOB_ID_LEN];
        octets[0] = premier;
        BlobId::try_from(serde_bytes::ByteBuf::from(octets)).expect("32 octets")
    }

    fn temoin() -> Vec<u8> {
        conteneur(&[
            (MemberKind::Header, None, b"en-tete"),
            (MemberKind::Index, None, b"index"),
            (MemberKind::Blob, Some(blob_id(1)), b"premier blob"),
            (MemberKind::Blob, Some(blob_id(2)), b"second blob"),
        ])
    }

    /// Ce qu'une relecture rend : type, identifiant et charge de chaque membre.
    type Membres = Vec<(MemberKind, Option<BlobId>, Vec<u8>)>;

    /// Relit un conteneur et rend les charges de ses membres.
    fn relire(octets: &[u8]) -> Result<Membres> {
        let mut reader = ContainerReader::open(octets)?;
        let mut membres = Vec::new();
        while let Some(frame) = reader.next_frame()? {
            let mut charge = Vec::new();
            reader.copy_payload(&frame, &mut charge)?;
            membres.push((frame.kind, frame.id, charge));
        }
        reader.finish()?;
        Ok(membres)
    }

    #[test]
    fn un_conteneur_fait_l_aller_retour() {
        let octets = temoin();
        let membres = relire(&octets).expect("relisible");

        assert_eq!(membres.len(), 4);
        assert_eq!(membres[0], (MemberKind::Header, None, b"en-tete".to_vec()));
        assert_eq!(membres[1], (MemberKind::Index, None, b"index".to_vec()));
        assert_eq!(
            membres[2],
            (MemberKind::Blob, Some(blob_id(1)), b"premier blob".to_vec())
        );
        assert_eq!(membres[3].1, Some(blob_id(2)));
    }

    /// Le décodage CBOR ne doit **pas** consommer au delà de la valeur lue :
    /// tout le format en dépend, puisque cadres et charges s'enchaînent sans
    /// séparateur. Le test le vérifie sur un conteneur dont les charges sont
    /// choisies pour ressembler à du CBOR.
    #[test]
    fn le_decodage_ne_consomme_pas_au_dela_de_la_valeur() {
        let octets = conteneur(&[
            (MemberKind::Header, None, &[0xa5, 0x64, 0x6b, 0x69, 0x6e]),
            (MemberKind::Index, None, &[0xff; 64]),
            (MemberKind::Blob, Some(blob_id(9)), &[0x00; 3]),
        ]);
        let membres = relire(&octets).expect("relisible");
        assert_eq!(membres[0].2, vec![0xa5, 0x64, 0x6b, 0x69, 0x6e]);
        assert_eq!(membres[1].2, vec![0xff; 64]);
        assert_eq!(membres[2].2, vec![0x00; 3]);
    }

    #[test]
    fn l_en_tete_publie_ce_qu_il_annonce() {
        let octets = temoin();
        let reader = ContainerReader::open(&octets[..]).expect("ouvrable");
        let header = reader.header();

        assert_eq!(header.container_version, CONTAINER_VERSION);
        assert_eq!(header.vault_format_version, version::FORMAT_VERSION);
        assert_eq!(header.member_count, 4);
        assert_eq!(header.payload_bytes, 7 + 5 + 12 + 11);
        assert!(format!("{header:?}").contains("ContainerHeader"));
    }

    #[test]
    fn un_flux_qui_n_est_pas_un_conteneur_est_refuse() {
        assert!(matches!(
            ContainerReader::open(&b""[..]),
            Err(Error::Corrupted)
        ));
        assert!(matches!(
            ContainerReader::open(&b"ceci n'est pas un conteneur"[..]),
            Err(Error::Corrupted)
        ));

        // La magie d'un vault sur disque n'est pas celle d'un conteneur.
        let etrangere = en_tete_force(
            &version::MAGIC,
            CONTAINER_VERSION,
            version::FORMAT_VERSION,
            2,
            0,
        );
        assert!(matches!(
            ContainerReader::open(&etrangere[..]),
            Err(Error::Corrupted)
        ));
    }

    /// Encode un en-tête arbitraire, pour éprouver les refus.
    fn en_tete_force(
        magic: &[u8],
        container_version: u32,
        vault_format_version: u32,
        member_count: u64,
        payload_bytes: u64,
    ) -> Vec<u8> {
        let repr = ContainerHeaderRepr {
            magic: serde_bytes::ByteBuf::from(magic.to_vec()),
            container_version,
            vault_format_version,
            member_count,
            payload_bytes,
        };
        let mut octets = Vec::new();
        ciborium::into_writer(&repr, &mut octets).expect("encodable");
        octets
    }

    /// VR-H1 appliqué au conteneur : refus explicite, nommant la version
    /// rencontrée. Les deux versions sont indépendantes, et refusées
    /// séparément.
    #[test]
    fn une_version_inconnue_est_refusee_en_nommant_la_version() {
        let conteneur_futur = en_tete_force(&CONTAINER_MAGIC, 2, version::FORMAT_VERSION, 2, 0);
        assert!(matches!(
            ContainerReader::open(&conteneur_futur[..]),
            Err(Error::UnsupportedFormatVersion { found: 2, supported })
                if supported == CONTAINER_VERSION
        ));

        let vault_futur = en_tete_force(&CONTAINER_MAGIC, CONTAINER_VERSION, 99, 2, 0);
        assert!(matches!(
            ContainerReader::open(&vault_futur[..]),
            Err(Error::UnsupportedFormatVersion { found: 99, supported })
                if supported == version::FORMAT_VERSION
        ));
    }

    /// Un conteneur annonçant moins de deux membres ne peut pas porter un
    /// vault : le `header` et l'`index` sont obligatoires.
    #[test]
    fn un_conteneur_sans_ses_deux_membres_obligatoires_est_refuse() {
        for compte in [0, 1] {
            let octets = en_tete_force(
                &CONTAINER_MAGIC,
                CONTAINER_VERSION,
                version::FORMAT_VERSION,
                compte,
                0,
            );
            assert!(matches!(
                ContainerReader::open(&octets[..]),
                Err(Error::Corrupted)
            ));
        }
    }

    /// Encode un cadre arbitraire à la suite d'un en-tête valide, pour éprouver
    /// les refus d'invariants.
    fn avec_cadre(kind: &str, id: Option<Vec<u8>>, length: u64) -> Vec<u8> {
        let mut octets = en_tete_force(
            &CONTAINER_MAGIC,
            CONTAINER_VERSION,
            version::FORMAT_VERSION,
            2,
            0,
        );
        let repr = MemberFrameRepr {
            kind: kind.to_owned(),
            id: id.map(serde_bytes::ByteBuf::from),
            length,
        };
        ciborium::into_writer(&repr, &mut octets).expect("encodable");
        octets
    }

    fn premier_cadre(octets: &[u8]) -> Result<Option<MemberFrame>> {
        ContainerReader::open(octets)?.next_frame()
    }

    #[test]
    fn un_type_de_membre_inconnu_est_refuse() {
        assert!(matches!(
            premier_cadre(&avec_cadre("manifeste", None, 0)),
            Err(Error::Corrupted)
        ));
    }

    /// L'ordre est normatif. Un `blob` en tête, ou un `index` là où le `header`
    /// est attendu, sont des refus.
    #[test]
    fn un_ordre_viole_est_refuse() {
        assert!(matches!(
            premier_cadre(&avec_cadre(
                "blob",
                Some(vec![0u8; crate::format::blob::BLOB_ID_LEN]),
                0
            )),
            Err(Error::Corrupted)
        ));
        assert!(matches!(
            premier_cadre(&avec_cadre("index", None, 0)),
            Err(Error::Corrupted)
        ));

        // Et un `header` là où l'`index` est attendu : le refus vient au
        // deuxième cadre, une fois le premier accepté.
        assert!(matches!(
            relire(&force_seconde_position("header", None)),
            Err(Error::Corrupted)
        ));

        // Un `blob` là où l'`index` est attendu, aussi.
        assert!(matches!(
            relire(&force_seconde_position(
                "blob",
                Some(vec![0u8; crate::format::blob::BLOB_ID_LEN])
            )),
            Err(Error::Corrupted)
        ));
    }

    /// Bâtit un conteneur dont le **deuxième** membre porte le type demandé,
    /// le premier restant un `header` légitime. Sert à éprouver l'ordre au delà
    /// du premier cadre.
    fn force_seconde_position(kind: &str, id: Option<Vec<u8>>) -> Vec<u8> {
        let mut octets = en_tete_force(
            &CONTAINER_MAGIC,
            CONTAINER_VERSION,
            version::FORMAT_VERSION,
            2,
            2,
        );
        for (position, (kind, id)) in [("header", None), (kind, id)].into_iter().enumerate() {
            let repr = MemberFrameRepr {
                kind: kind.to_owned(),
                id: id.map(serde_bytes::ByteBuf::from),
                length: 1,
            };
            ciborium::into_writer(&repr, &mut octets).expect("encodable");
            octets.push(b'a' + u8::try_from(position).expect("deux membres"));
        }
        octets
    }

    /// L'identifiant est obligatoire pour un blob, et interdit ailleurs.
    #[test]
    fn la_presence_de_l_identifiant_suit_le_type() {
        // Un `header` porteur d'identifiant.
        assert!(matches!(
            premier_cadre(&avec_cadre(
                "header",
                Some(vec![0u8; crate::format::blob::BLOB_ID_LEN]),
                0
            )),
            Err(Error::Corrupted)
        ));

        // Un `blob` sans identifiant, en troisième position.
        let mut octets = conteneur(&[
            (MemberKind::Header, None, b"a"),
            (MemberKind::Index, None, b"b"),
            (MemberKind::Blob, Some(blob_id(1)), b"c"),
        ]);
        let sans_id = {
            let repr = MemberFrameRepr {
                kind: "blob".to_owned(),
                id: None,
                length: 1,
            };
            let mut cadre = Vec::new();
            ciborium::into_writer(&repr, &mut cadre).expect("encodable");
            cadre
        };
        let avec_id = {
            let repr = MemberFrameRepr {
                kind: "blob".to_owned(),
                id: Some(blob_id(1).into()),
                length: 1,
            };
            let mut cadre = Vec::new();
            ciborium::into_writer(&repr, &mut cadre).expect("encodable");
            cadre
        };
        let debut = octets
            .windows(avec_id.len())
            .position(|f| f == avec_id)
            .expect("cadre du blob présent");
        octets.splice(debut..debut + avec_id.len(), sans_id);
        assert!(matches!(relire(&octets), Err(Error::Corrupted)));

        // Un identifiant de longueur fausse.
        assert!(matches!(
            premier_cadre(&avec_cadre("blob", Some(vec![0u8; 4]), 0)),
            Err(Error::Corrupted)
        ));
    }

    /// Les blobs sont triés par identifiant **strictement** croissant : un
    /// doublon et un désordre sont refusés par la même règle.
    #[test]
    fn un_doublon_ou_un_desordre_de_blobs_est_refuse() {
        for (premier, second) in [(blob_id(1), blob_id(1)), (blob_id(2), blob_id(1))] {
            let octets = conteneur(&[
                (MemberKind::Header, None, b"a"),
                (MemberKind::Index, None, b"b"),
                (MemberKind::Blob, Some(premier), b"c"),
                (MemberKind::Blob, Some(second), b"d"),
            ]);
            assert!(matches!(relire(&octets), Err(Error::Corrupted)));
        }
    }

    /// La borne est appliquée **avant toute allocation**. Le test annonce des
    /// longueurs astronomiques : si elles étaient réservées, il ne finirait pas.
    #[test]
    fn une_longueur_hors_bornes_est_refusee_avant_toute_allocation() {
        for (kind, longueur) in [
            ("header", MAX_HEADER_PAYLOAD + 1),
            ("header", u64::MAX),
            ("header", 1 << 63),
        ] {
            assert!(matches!(
                premier_cadre(&avec_cadre(kind, None, longueur)),
                Err(Error::Corrupted)
            ));
        }

        // Les trois bornes sont distinctes, et chacune est celle du contrat.
        assert_eq!(MemberKind::Header.max_payload(), 65_536);
        assert_eq!(MemberKind::Index.max_payload(), 268_435_456);
        assert_eq!(MemberKind::Blob.max_payload(), 4_400_000_000);

        // Une longueur à la borne exacte passe le contrôle de cadre.
        let cadre = premier_cadre(&avec_cadre("header", None, MAX_HEADER_PAYLOAD))
            .expect("cadre lisible")
            .expect("présent");
        assert_eq!(cadre.length, MAX_HEADER_PAYLOAD);
    }

    #[test]
    fn un_flux_tronque_a_mi_charge_est_refuse() {
        let octets = temoin();
        for coupe in [octets.len() - 1, octets.len() / 2, 30] {
            assert!(
                matches!(relire(&octets[..coupe]), Err(Error::Corrupted)),
                "coupé à {coupe}"
            );
        }
    }

    /// Un octet retourné au milieu d'une charge ne change ni les cadres ni le
    /// nombre de membres : seule l'empreinte du sceau le voit.
    #[test]
    fn un_octet_retourne_fait_diverger_l_empreinte() {
        let mut octets = temoin();
        let milieu = octets.len() / 2;
        octets[milieu] ^= 0x01;
        assert!(matches!(relire(&octets), Err(Error::Corrupted)));
    }

    #[test]
    fn un_sceau_altere_est_refuse() {
        let temoin = temoin();

        // Marque de fin étrangère.
        let sceau = |end: &[u8], member_count: u64, digest: Vec<u8>| {
            let repr = SealRepr {
                end: serde_bytes::ByteBuf::from(end.to_vec()),
                member_count,
                digest: serde_bytes::ByteBuf::from(digest),
            };
            let mut octets = Vec::new();
            ciborium::into_writer(&repr, &mut octets).expect("encodable");
            octets
        };

        let empreinte = empreinte_du_temoin(&temoin);

        // Le corps du conteneur, sans son sceau.
        let corps_len = temoin.len() - sceau(&CONTAINER_END, 4, empreinte.clone()).len();
        let corps = &temoin[..corps_len];

        for faux in [
            sceau(b"PASLAFIN", 4, empreinte.clone()),
            sceau(&CONTAINER_END, 3, empreinte.clone()),
            sceau(&CONTAINER_END, 4, vec![0u8; 32]),
        ] {
            let mut altere = corps.to_vec();
            altere.extend_from_slice(&faux);
            assert!(matches!(relire(&altere), Err(Error::Corrupted)));
        }

        // Et le sceau légitime remis en place : le conteneur redevient valide.
        let mut refait = corps.to_vec();
        refait.extend_from_slice(&sceau(&CONTAINER_END, 4, empreinte));
        assert_eq!(refait, temoin);
        assert!(relire(&refait).is_ok());
    }

    /// **Aucun octet du conteneur ne peut être retourné sans que la lecture le
    /// voie, et aucune troncature ne passe.**
    ///
    /// Le balayage est exhaustif parce qu'il est **gratuit ici** : la lecture
    /// se fait en mémoire, sans toucher au disque. La même propriété, éprouvée
    /// à travers un import réel, coûterait un `fsync` par membre et par
    /// position — quelques millisecondes sur ext4, plusieurs dizaines sur
    /// NTFS. `tests/tamper.rs` s'y borne donc à un échantillon structurel, et
    /// c'est ici que l'exhaustivité vit.
    #[test]
    fn aucune_alteration_ni_troncature_ne_passe_a_la_lecture() {
        let temoin = temoin();

        let alterations: Vec<bool> = (0..temoin.len())
            .map(|position| {
                let mut altere = temoin.clone();
                altere[position] ^= 0x01;
                relire(&altere).is_err()
            })
            .collect();
        assert_eq!(
            alterations,
            vec![true; temoin.len()],
            "un octet retourné est passé inaperçu"
        );

        let troncatures: Vec<bool> = (0..temoin.len())
            .map(|coupe| relire(&temoin[..coupe]).is_err())
            .collect();
        assert_eq!(
            troncatures,
            vec![true; temoin.len()],
            "une troncature est passée inaperçue"
        );
    }

    #[test]
    fn des_octets_apres_le_sceau_sont_refuses() {
        let mut octets = temoin();
        octets.push(0x00);
        assert!(matches!(relire(&octets), Err(Error::Corrupted)));
    }

    /// Le sceau porte l'empreinte de ce qui le **précède**, donc pas de
    /// lui-même : c'est ce qui rend la vérification possible en un seul passage.
    #[test]
    fn l_empreinte_ne_porte_pas_sur_le_sceau() {
        let octets = temoin();

        // L'empreinte publiée dans le sceau est celle d'un préfixe **strict**
        // du flux : elle ne peut donc pas être celle du flux entier, ni celle
        // d'un préfixe qui mordrait sur le sceau.
        let publiee = empreinte_du_temoin(&octets);
        assert_ne!(publiee, blake3::hash(&octets).as_bytes().to_vec());
        assert!(
            octets
                .windows(publiee.len())
                .any(|fenetre| fenetre == publiee),
            "l'empreinte figure bien dans le sceau"
        );
    }

    /// Rejoue la lecture d'un conteneur jusqu'au sceau et rend l'empreinte
    /// calculée — c'est-à-dire celle que le sceau doit porter.
    fn empreinte_du_temoin(octets: &[u8]) -> Vec<u8> {
        let mut reader = ContainerReader::open(octets).expect("ouvrable");
        while let Some(frame) = reader.next_frame().expect("cadre") {
            reader
                .copy_payload(&frame, &mut Vec::new())
                .expect("charge");
        }
        reader.reader.hashing = false;
        reader.reader.hasher.finalize().as_bytes().to_vec()
    }

    /// Une source qui rend moins d'octets qu'annoncé fait échouer l'écriture :
    /// mieux vaut refuser que produire un flux qu'aucun import ne lira.
    #[test]
    fn une_source_trop_courte_fait_echouer_l_ecriture() {
        let mut writer = ContainerWriter::begin(Vec::new(), 1, 2, 100).expect("ouvrable");
        assert!(matches!(
            writer.member(MemberKind::Header, None, 100, &mut &b"court"[..]),
            Err(Error::Corrupted)
        ));
    }

    /// Un écrivain rompu remonte une erreur d'entrée-sortie, sans panique.
    #[test]
    fn un_ecrivain_rompu_remonte_l_erreur() {
        struct Rompu;
        impl Write for Rompu {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("tube fermé"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("tube fermé"))
            }
        }

        assert!(Write::flush(&mut Rompu).is_err());
        assert!(matches!(
            ContainerWriter::begin(Rompu, 1, 2, 0),
            Err(Error::Corrupted | Error::Io(_))
        ));
    }

    /// Un lecteur rompu remonte une erreur d'entrée-sortie, sans panique.
    #[test]
    fn un_lecteur_rompu_remonte_l_erreur() {
        struct Rompu;
        impl Read for Rompu {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("canal rompu"))
            }
        }

        assert!(matches!(
            ContainerReader::open(Rompu),
            Err(Error::Corrupted | Error::Io(_))
        ));
    }

    /// Le contrôle des octets suivant le sceau doit remonter une défaillance de
    /// lecture plutôt que de la prendre pour une fin de flux.
    #[test]
    fn une_defaillance_apres_le_sceau_remonte_l_erreur() {
        struct RompuApres {
            reste: std::io::Cursor<Vec<u8>>,
        }
        impl Read for RompuApres {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                match self.reste.read(buf)? {
                    0 => Err(std::io::Error::other("canal rompu")),
                    lus => Ok(lus),
                }
            }
        }

        let source = RompuApres {
            reste: std::io::Cursor::new(temoin()),
        };
        let mut reader = ContainerReader::open(source).expect("ouvrable");
        while let Some(frame) = reader.next_frame().expect("cadre") {
            reader
                .copy_payload(&frame, &mut Vec::new())
                .expect("charge");
        }
        assert!(matches!(reader.finish(), Err(Error::Io(_))));
    }

    #[test]
    fn les_constantes_du_contrat_sont_celles_du_document() {
        assert_eq!(&CONTAINER_MAGIC, b"VAULTXFR");
        assert_eq!(&CONTAINER_END, b"VAULTEND");
        assert_eq!(CONTAINER_VERSION, 1);
        assert_eq!(READABLE_CONTAINER_VERSIONS, &[1]);
        assert_ne!(CONTAINER_MAGIC, version::MAGIC);

        assert_eq!(MemberKind::Header.as_str(), "header");
        assert_eq!(MemberKind::Index.as_str(), "index");
        assert_eq!(MemberKind::Blob.as_str(), "blob");
        assert_eq!(
            MemberKind::from_str("header").expect("connu"),
            MemberKind::Header
        );
        assert_eq!(
            MemberKind::from_str("index").expect("connu"),
            MemberKind::Index
        );
        assert_eq!(
            MemberKind::from_str("blob").expect("connu"),
            MemberKind::Blob
        );
        assert!(format!("{:?}", MemberKind::Blob).contains("Blob"));
        assert_ne!(MemberKind::Header, MemberKind::Index);
    }
}
