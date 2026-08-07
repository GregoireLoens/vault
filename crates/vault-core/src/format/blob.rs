//! Disposition d'un blob sur disque — T025.
//!
//! ```text
//! ┌────────────────┬──────────────────────────────┬──────────────┐
//! │ nonce (19 o)   │ morceaux STREAM chiffrés     │ remplissage  │
//! └────────────────┴──────────────────────────────┴──────────────┘
//! ```
//!
//! Trois règles :
//!
//! - **VR-B1** — l'identifiant est tiré du CSPRNG, sans aucun lien avec le
//!   contenu ni le nom du fichier. Ce n'est **pas** une empreinte : deux
//!   fichiers identiques donnent deux blobs distincts, sans quoi le vault
//!   révélerait ses doublons.
//! - **VR-B3** — le blob est complété jusqu'au palier supérieur d'une suite
//!   géométrique de raison 1,1, plancher à 4 KiB (D-007). Un observateur
//!   n'apprend donc qu'une fourchette de taille, jamais la taille exacte
//!   (FR-037).
//! - **VR-B4** — le contenu est plafonné à 4 Go (FR-022).
//!
//! Le remplissage est tiré aléatoirement et n'est **jamais** déchiffré ni
//! interprété : à la lecture, seuls les `ciphertext_len(size)` premiers octets
//! qui suivent le nonce sont consommés, `size` venant de l'index chiffré.

use serde::{Deserialize, Serialize};

use crate::crypto::random;
use crate::crypto::stream::{STREAM_NONCE_LEN, ciphertext_len};
use crate::error::{Error, Result};

/// Longueur d'un identifiant de blob, en octets.
pub const BLOB_ID_LEN: usize = 32;

/// Plancher de remplissage, en octets (D-007).
pub(crate) const PADDING_FLOOR: u64 = 4096;

/// Taille maximale du contenu d'un fichier, en octets (FR-022, VR-B4).
pub const MAX_FILE_SIZE: u64 = 4 * 1000 * 1000 * 1000;

/// Identifiant opaque d'un blob.
///
/// Sert aussi de nom de fichier dans `objects/`, sous sa forme hexadécimale.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "serde_bytes::ByteBuf", into = "serde_bytes::ByteBuf")]
pub struct BlobId([u8; BLOB_ID_LEN]);

impl BlobId {
    /// Tire un identifiant neuf du CSPRNG du système (VR-B1).
    #[must_use]
    pub fn generate() -> Self {
        Self(random::bytes::<BLOB_ID_LEN>())
    }

    /// Les octets de l'identifiant.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; BLOB_ID_LEN] {
        &self.0
    }

    /// Le nom de fichier du blob dans `objects/`.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut hex = String::with_capacity(BLOB_ID_LEN * 2);
        for byte in self.0 {
            hex.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
            hex.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
        }
        hex
    }

    /// Relit un identifiant depuis son nom de fichier.
    ///
    /// # Errors
    ///
    /// [`Error::Corrupted`] si le nom n'est pas exactement 64 chiffres
    /// hexadécimaux — un fichier étranger déposé dans `objects/`.
    pub fn from_hex(hex: &str) -> Result<Self> {
        if hex.len() != BLOB_ID_LEN * 2 {
            return Err(Error::Corrupted);
        }
        let mut bytes = [0u8; BLOB_ID_LEN];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let pair = hex.get(index * 2..index * 2 + 2).ok_or(Error::Corrupted)?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| Error::Corrupted)?;
        }
        Ok(Self(bytes))
    }
}

impl TryFrom<serde_bytes::ByteBuf> for BlobId {
    type Error = Error;

    fn try_from(bytes: serde_bytes::ByteBuf) -> Result<Self> {
        let bytes: [u8; BLOB_ID_LEN] = bytes.into_vec().try_into().map_err(|_| Error::Corrupted)?;
        Ok(Self(bytes))
    }
}

impl From<BlobId> for serde_bytes::ByteBuf {
    fn from(id: BlobId) -> Self {
        Self::from(id.0.to_vec())
    }
}

/// Palier de remplissage immédiatement supérieur ou égal à `actual`.
///
/// Suite géométrique de raison 1,1 à partir de 4 KiB, calculée en arithmétique
/// entière : un calcul en virgule flottante donnerait des paliers légèrement
/// différents d'une plateforme à l'autre, et le remplissage cesserait d'être
/// reproductible (principe IV).
pub(crate) fn padded_size(actual: u64) -> u64 {
    let mut step = PADDING_FLOOR;
    while step < actual {
        // step × 1,1 arrondi au supérieur. La progression est strictement
        // croissante dès 4 KiB, donc la boucle termine.
        step = step.saturating_mul(11).div_ceil(10);
    }
    step
}

/// Taille sur disque du blob correspondant à un contenu de `plaintext_len`
/// octets, remplissage compris.
pub(crate) fn blob_size(plaintext_len: u64) -> u64 {
    padded_size(STREAM_NONCE_LEN as u64 + ciphertext_len(plaintext_len))
}

/// Domaine de séparation du chiffrement des blobs.
const BLOB_DOMAIN: &[u8] = b"vault blob v1";

/// Données associées du chiffrement d'un blob.
///
/// L'identifiant du blob y figure : un blob ne peut donc pas être renommé en
/// un autre identifiant sans que son déchiffrement échoue. La clé du blob en
/// dépend déjà, mais lier aussi les données associées rend l'intention
/// explicite dans `docs/format.md` et coûte quelques octets par morceau.
pub(crate) fn blob_aad(blob_id: &BlobId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(BLOB_DOMAIN.len() + BLOB_ID_LEN);
    aad.extend_from_slice(BLOB_DOMAIN);
    aad.extend_from_slice(blob_id.as_bytes());
    aad
}

/// Produit les octets de remplissage à ajouter après le chiffré.
pub(crate) fn padding(written: u64, padded: u64) -> Vec<u8> {
    let mut filler = vec![0u8; usize::try_from(padded.saturating_sub(written)).unwrap_or(0)];
    random::fill(&mut filler);
    filler
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deux_identifiants_different() {
        let a = BlobId::generate();
        let b = BlobId::generate();
        assert_ne!(a, b);
        assert_ne!(a.as_bytes(), &[0u8; BLOB_ID_LEN]);
    }

    #[test]
    fn l_identifiant_fait_l_aller_retour_en_hexadecimal() {
        let id = BlobId::generate();
        let hex = id.to_hex();
        assert_eq!(hex.len(), BLOB_ID_LEN * 2);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(BlobId::from_hex(&hex).expect("relisible"), id);
    }

    #[test]
    fn un_nom_de_fichier_etranger_est_refuse() {
        for etranger in ["", "court", &"z".repeat(64), &"0".repeat(63)] {
            assert!(
                matches!(BlobId::from_hex(etranger), Err(Error::Corrupted)),
                "aurait dû refuser {etranger}"
            );
        }
        // Un caractère multi-octets ne doit pas faire paniquer le découpage.
        assert!(matches!(
            BlobId::from_hex(&format!("é{}", "0".repeat(61))),
            Err(Error::Corrupted)
        ));
    }

    #[test]
    fn l_identifiant_fait_l_aller_retour_en_cbor() {
        let id = BlobId::generate();
        let mut encoded = Vec::new();
        ciborium::into_writer(&id, &mut encoded).expect("encodable");
        let decoded: BlobId = ciborium::from_reader(&encoded[..]).expect("décodable");
        assert_eq!(decoded, id);

        let mauvaise_longueur = serde_bytes::ByteBuf::from(vec![0u8; 5]);
        let mut encoded = Vec::new();
        ciborium::into_writer(&mauvaise_longueur, &mut encoded).expect("encodable");
        let decoded: std::result::Result<BlobId, _> = ciborium::from_reader(&encoded[..]);
        assert!(decoded.is_err());
    }

    /// VR-B3 : plancher à 4 KiB, puis progression de 10 % par palier.
    #[test]
    fn le_remplissage_suit_les_paliers() {
        assert_eq!(padded_size(0), PADDING_FLOOR);
        assert_eq!(padded_size(1), PADDING_FLOOR);
        assert_eq!(padded_size(PADDING_FLOOR), PADDING_FLOOR);
        assert_eq!(padded_size(PADDING_FLOOR + 1), 4506);
        assert_eq!(padded_size(4506), 4506);
        assert_eq!(padded_size(4507), 4957);
    }

    /// Le surcoût de stockage reste sous les 10 % promis par D-007, sur toute
    /// l'étendue des tailles gérées.
    #[test]
    fn le_surcout_reste_borne() {
        let mut taille = PADDING_FLOOR;
        while taille < MAX_FILE_SIZE {
            let rempli = padded_size(taille);
            assert!(rempli >= taille);
            assert!(
                rempli <= taille + taille / 10 + 1,
                "surcoût excessif pour {taille} : {rempli}"
            );
            taille = taille + taille / 7 + 1;
        }
    }

    #[test]
    fn les_paliers_sont_strictement_croissants() {
        let mut precedent = 0;
        let mut taille = 0;
        while taille < 10 * PADDING_FLOOR {
            let rempli = padded_size(taille);
            assert!(rempli >= precedent);
            precedent = rempli;
            taille += 137;
        }
    }

    #[test]
    fn la_taille_du_blob_englobe_nonce_tag_et_remplissage() {
        for contenu in [0u64, 1, 100_000, 1_000_000] {
            let taille = blob_size(contenu);
            assert!(taille >= STREAM_NONCE_LEN as u64 + ciphertext_len(contenu));
            assert_eq!(taille, padded_size(taille));
        }
    }

    #[test]
    fn le_remplissage_est_aleatoire_et_de_la_bonne_longueur() {
        let filler = padding(100, 4096);
        assert_eq!(filler.len(), 3996);
        assert!(filler.iter().any(|byte| *byte != 0));
        assert!(padding(4096, 100).is_empty());
    }

    #[test]
    fn les_donnees_associees_lient_le_blob_a_son_identifiant() {
        let a = BlobId::generate();
        let b = BlobId::generate();
        assert_eq!(blob_aad(&a), blob_aad(&a));
        assert_ne!(blob_aad(&a), blob_aad(&b));
        assert_eq!(blob_aad(&a).len(), BLOB_DOMAIN.len() + BLOB_ID_LEN);
        assert!(blob_aad(&a).ends_with(a.as_bytes()));
        assert!(blob_aad(&a).starts_with(BLOB_DOMAIN));
    }

    #[test]
    fn la_limite_de_taille_est_celle_de_la_specification() {
        assert_eq!(MAX_FILE_SIZE, 4_000_000_000);
    }
}
