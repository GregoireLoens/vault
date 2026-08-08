//! En-tête du vault — T023.
//!
//! Le fichier `header` est le **seul** élément lisible d'un vault, et il ne
//! contient que ce qui est nécessaire au déchiffrement (principe I, principe
//! IV). VR-H3 : ni nombre d'entrées, ni taille totale, ni date — rien qui
//! caractérise le contenu.
//!
//! VR-H2 : tous les paramètres de dérivation y figurent. Un vault produit avec
//! des paramètres Argon2 relevés reste ouvrable par une version du logiciel
//! dont les valeurs par défaut diffèrent, parce que le chemin de lecture
//! n'emploie **que** ce qu'il lit ici.
//!
//! # Intégrité de l'en-tête
//!
//! Les champs publics servent de données associées à l'enveloppement de la clé
//! maîtresse. Altérer le sel, un paramètre de coût ou un identifiant
//! d'algorithme fait donc échouer le désenveloppement, en
//! [`Error::Authentication`] — le même variant qu'une passphrase erronée
//! (C-024). Un en-tête structurellement illisible, lui, donne
//! [`Error::Corrupted`] : ce n'est pas un vault, et le dire ne renseigne
//! personne sur la passphrase.
//!
//! # Écart assumé avec `data-model.md`
//!
//! Le modèle de données plaçait `index_nonce` dans l'en-tête. Ce champ n'y est
//! pas, et le nonce de l'index vit en tête du fichier `index` — voir la note
//! du module [`crate::format::index`] pour le raisonnement.

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::crypto::aead;
use crate::crypto::kdf::{self, KdfParams, SALT_LEN};
use crate::crypto::keys::MasterKey;
use crate::crypto::random;
use crate::error::{Error, Result};
use crate::format::version::{self, FORMAT_VERSION, MAGIC};

/// Identifiant de la KDF employée par la version 1 du format.
const KDF_ALGORITHM: &str = "argon2id";

/// Identifiant de l'AEAD employé par la version 1 du format.
const AEAD_ALGORITHM: &str = "xchacha20poly1305";

/// Représentation sérialisée de l'en-tête, encodée en CBOR (D-011).
///
/// Les noms de champs sont ceux de `docs/format.md` : ils font partie du
/// format, au même titre que les valeurs.
#[derive(Serialize, Deserialize)]
struct HeaderRepr {
    magic: serde_bytes::ByteBuf,
    format_version: u32,
    kdf_algorithm: String,
    kdf_salt: serde_bytes::ByteBuf,
    kdf_memory_kib: u32,
    kdf_iterations: u32,
    kdf_parallelism: u32,
    aead_algorithm: String,
    wrapped_master_key: serde_bytes::ByteBuf,
}

/// En-tête d'un vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    format_version: u32,
    kdf_params: KdfParams,
    salt: [u8; SALT_LEN],
    wrapped_master_key: Vec<u8>,
}

impl Header {
    /// Crée un en-tête neuf et la clé maîtresse qu'il enveloppe.
    ///
    /// La clé maîtresse est tirée du CSPRNG, **jamais** dérivée de la
    /// passphrase (D-004).
    ///
    /// # Errors
    ///
    /// [`Error::Authentication`] si Argon2id refuse les paramètres — voir
    /// [`kdf::derive_wrapping_key`].
    pub(crate) fn create(
        passphrase: &SecretString,
        kdf_params: KdfParams,
    ) -> Result<(Self, MasterKey)> {
        let salt = random::bytes::<SALT_LEN>();
        let wrapping_key = kdf::derive_wrapping_key(passphrase, &salt, kdf_params)?;

        let master_key = MasterKey::generate();
        let mut header = Self {
            format_version: FORMAT_VERSION,
            kdf_params,
            salt,
            wrapped_master_key: Vec::new(),
        };
        header.wrapped_master_key = master_key.wrap(&wrapping_key, &header.public_context())?;

        Ok((header, master_key))
    }

    /// Retrouve la clé maîtresse à partir de la passphrase.
    ///
    /// VR-P1 : c'est le seul moyen de vérifier une passphrase — aucune
    /// empreinte de vérification n'est stockée.
    ///
    /// # Errors
    ///
    /// [`Error::Authentication`], sans distinction possible entre passphrase
    /// erronée, en-tête altéré et clé maîtresse corrompue (C-024, VR-P2).
    pub(crate) fn unlock(&self, passphrase: &SecretString) -> Result<MasterKey> {
        let wrapping_key = kdf::derive_wrapping_key(passphrase, &self.salt, self.kdf_params)?;
        let master_key = aead::unwrap_master_key(
            &wrapping_key,
            &self.wrapped_master_key,
            &self.public_context(),
        )?;
        Ok(MasterKey::from_secret(master_key))
    }

    /// Ré-enveloppe la clé maîtresse sous une nouvelle passphrase, et
    /// éventuellement de nouveaux paramètres de coût (C-021, C-023).
    ///
    /// D-004 : seule l'enveloppe change. La clé maîtresse et tout le contenu
    /// restent inchangés, ce qui rend l'opération indépendante de la taille du
    /// vault (FR-033, FR-034).
    ///
    /// # Errors
    ///
    /// [`Error::Authentication`] si la dérivation échoue.
    pub(crate) fn rewrap(
        &mut self,
        master_key: &MasterKey,
        new_passphrase: &SecretString,
        kdf_params: KdfParams,
    ) -> Result<()> {
        let salt = random::bytes::<SALT_LEN>();
        let wrapping_key = kdf::derive_wrapping_key(new_passphrase, &salt, kdf_params)?;

        let mut candidate = Self {
            format_version: self.format_version,
            kdf_params,
            salt,
            wrapped_master_key: Vec::new(),
        };
        candidate.wrapped_master_key =
            master_key.wrap(&wrapping_key, &candidate.public_context())?;

        // L'en-tête n'est remplacé qu'une fois le nouvel enveloppement produit :
        // un échec en cours de route laisse l'ancien intact.
        *self = candidate;
        Ok(())
    }

    /// Encode l'en-tête pour écriture sur disque.
    ///
    /// # Errors
    ///
    /// [`Error::Corrupted`] si l'encodage CBOR échoue, ce qui suppose une
    /// défaillance mémoire.
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let repr = HeaderRepr {
            magic: serde_bytes::ByteBuf::from(MAGIC.to_vec()),
            format_version: self.format_version,
            kdf_algorithm: KDF_ALGORITHM.to_owned(),
            kdf_salt: serde_bytes::ByteBuf::from(self.salt.to_vec()),
            kdf_memory_kib: self.kdf_params.memory_kib(),
            kdf_iterations: self.kdf_params.iterations(),
            kdf_parallelism: self.kdf_params.parallelism(),
            aead_algorithm: AEAD_ALGORITHM.to_owned(),
            wrapped_master_key: serde_bytes::ByteBuf::from(self.wrapped_master_key.clone()),
        };

        let mut encoded = Vec::new();
        ciborium::into_writer(&repr, &mut encoded).map_err(|_| Error::Corrupted)?;
        Ok(encoded)
    }

    /// Décode un en-tête lu sur disque.
    ///
    /// VR-H1 : `magic` et `format_version` sont vérifiés avant toute autre
    /// chose. Une version inconnue provoque un refus explicite, jamais une
    /// lecture approximative.
    ///
    /// # Errors
    ///
    /// - [`Error::Corrupted`] si le fichier n'est pas un en-tête de vault
    ///   lisible, ou emploie des algorithmes inconnus ;
    /// - [`Error::UnsupportedFormatVersion`] si la version dépasse celles que
    ///   ce logiciel sait lire.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let repr: HeaderRepr = ciborium::from_reader(bytes).map_err(|_| Error::Corrupted)?;

        version::check(&repr.magic, repr.format_version)?;

        if repr.kdf_algorithm != KDF_ALGORITHM || repr.aead_algorithm != AEAD_ALGORITHM {
            return Err(Error::Corrupted);
        }

        let salt: [u8; SALT_LEN] = repr
            .kdf_salt
            .into_vec()
            .try_into()
            .map_err(|_| Error::Corrupted)?;

        Ok(Self {
            format_version: repr.format_version,
            // Volontairement non validés : des paramètres aberrants lus sur
            // disque doivent échouer à la dérivation, en Authentication, et
            // non produire une erreur qui les distinguerait (C-024).
            kdf_params: KdfParams::from_header(
                repr.kdf_memory_kib,
                repr.kdf_iterations,
                repr.kdf_parallelism,
            ),
            salt,
            wrapped_master_key: repr.wrapped_master_key.into_vec(),
        })
    }

    /// Version de format de ce vault.
    #[must_use]
    pub fn format_version(&self) -> u32 {
        self.format_version
    }

    /// Paramètres de dérivation de ce vault (VR-H2).
    #[must_use]
    pub fn kdf_params(&self) -> KdfParams {
        self.kdf_params
    }

    /// Identifiant de la fonction de dérivation employée par ce vault.
    ///
    /// La valeur est constante, et ce n'est pas un raccourci : [`Header::decode`]
    /// refuse tout en-tête qui en annonce une autre. Un vault lu est donc
    /// nécessairement celui-ci. Le jour où une version 2 du format admettra un
    /// autre algorithme, c'est ici que le choix se fera — d'où un accesseur
    /// plutôt qu'une constante publique, qui figerait l'interface.
    // `self` n'est pas lu aujourd'hui, et c'est exactement ce que dit le
    // paragraphe ci-dessus : la valeur est déterminée par la version de format,
    // dont une seule existe. En faire une fonction associée, comme le suggère
    // clippy, obligerait à rompre l'interface le jour où il y en aura deux.
    #[allow(clippy::unused_self)]
    #[must_use]
    pub fn kdf_algorithm(&self) -> &'static str {
        KDF_ALGORITHM
    }

    /// Identifiant du chiffrement authentifié employé par ce vault.
    ///
    /// Voir [`Header::kdf_algorithm`] pour la raison d'un accesseur.
    #[allow(clippy::unused_self)]
    #[must_use]
    pub fn aead_algorithm(&self) -> &'static str {
        AEAD_ALGORITHM
    }

    /// Partie publique de l'en-tête, telle qu'elle est liée à l'enveloppement
    /// de la clé maîtresse.
    ///
    /// L'encodage est à champs de largeur fixe et dans un ordre figé, plutôt
    /// que le CBOR de [`Header::encode`] : deux encodeurs CBOR peuvent
    /// légitimement produire des octets différents pour la même structure, et
    /// l'authentification cesserait d'être reproductible.
    fn public_context(&self) -> Vec<u8> {
        let mut context = Vec::new();
        context.extend_from_slice(&MAGIC);
        context.extend_from_slice(&self.format_version.to_be_bytes());
        context.extend_from_slice(KDF_ALGORITHM.as_bytes());
        context.extend_from_slice(&self.salt);
        context.extend_from_slice(&self.kdf_params.memory_kib().to_be_bytes());
        context.extend_from_slice(&self.kdf_params.iterations().to_be_bytes());
        context.extend_from_slice(&self.kdf_params.parallelism().to_be_bytes());
        context.extend_from_slice(AEAD_ALGORITHM.as_bytes());
        context
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> KdfParams {
        KdfParams::new(64, 1, 1).expect("paramètres valides")
    }

    fn passphrase() -> SecretString {
        SecretString::from("une passphrase suffisamment longue".to_owned())
    }

    fn en_tete() -> (Header, MasterKey) {
        Header::create(&passphrase(), params()).expect("créable")
    }

    #[test]
    fn un_en_tete_neuf_ouvre_avec_sa_passphrase() {
        let (header, master) = en_tete();
        assert_eq!(header.format_version(), FORMAT_VERSION);
        assert_eq!(header.kdf_params(), params());

        let retrouvee = header.unlock(&passphrase()).expect("déverrouillable");
        assert_eq!(retrouvee.expose(), master.expose());
    }

    #[test]
    fn une_passphrase_erronee_est_refusee() {
        let (header, _) = en_tete();
        let fausse = SecretString::from("une passphrase parfaitement fausse".to_owned());
        assert!(matches!(header.unlock(&fausse), Err(Error::Authentication)));
    }

    #[test]
    fn l_en_tete_fait_l_aller_retour_sur_disque() {
        let (header, master) = en_tete();
        let encoded = header.encode().expect("encodable");

        // VR-H3 : l'en-tête reste de l'ordre de quelques centaines d'octets,
        // parce qu'il ne contient rien du contenu.
        assert!(encoded.len() < 300, "en-tête de {} octets", encoded.len());

        let relu = Header::decode(&encoded).expect("décodable");
        assert_eq!(relu, header);
        assert_eq!(
            relu.unlock(&passphrase())
                .expect("déverrouillable")
                .expose(),
            master.expose()
        );
    }

    /// C-024 : toute altération d'un champ public fait échouer le
    /// désenveloppement avec la même erreur qu'une passphrase erronée, parce
    /// que ces champs sont les données associées de l'enveloppe.
    #[test]
    fn l_alteration_d_un_champ_public_donne_authentication() {
        let (header, _) = en_tete();

        let mut sel_altere = header.clone();
        sel_altere.salt[0] ^= 0x01;
        assert!(matches!(
            sel_altere.unlock(&passphrase()),
            Err(Error::Authentication)
        ));

        let mut params_alteres = header.clone();
        params_alteres.kdf_params = KdfParams::from_header(65, 1, 1);
        assert!(matches!(
            params_alteres.unlock(&passphrase()),
            Err(Error::Authentication)
        ));

        let mut cle_alteree = header.clone();
        cle_alteree.wrapped_master_key[0] ^= 0x01;
        assert!(matches!(
            cle_alteree.unlock(&passphrase()),
            Err(Error::Authentication)
        ));
    }

    /// VR-H1 : refus explicite d'une version inconnue, et d'un fichier qui
    /// n'est pas un en-tête.
    #[test]
    fn un_en_tete_illisible_est_refuse() {
        assert!(matches!(Header::decode(b""), Err(Error::Corrupted)));
        assert!(matches!(
            Header::decode(b"ceci n'est pas du CBOR d'en-tete"),
            Err(Error::Corrupted)
        ));

        let (header, _) = en_tete();
        let encoded = header.encode().expect("encodable");
        let mut tronque = encoded.clone();
        tronque.truncate(encoded.len() / 2);
        assert!(matches!(Header::decode(&tronque), Err(Error::Corrupted)));
    }

    #[test]
    fn une_version_ou_un_algorithme_inconnus_sont_refuses() {
        let (header, _) = en_tete();
        let base = HeaderRepr {
            magic: serde_bytes::ByteBuf::from(MAGIC.to_vec()),
            format_version: FORMAT_VERSION,
            kdf_algorithm: KDF_ALGORITHM.to_owned(),
            kdf_salt: serde_bytes::ByteBuf::from(header.salt.to_vec()),
            kdf_memory_kib: 64,
            kdf_iterations: 1,
            kdf_parallelism: 1,
            aead_algorithm: AEAD_ALGORITHM.to_owned(),
            wrapped_master_key: serde_bytes::ByteBuf::from(header.wrapped_master_key.clone()),
        };

        let encode = |repr: &HeaderRepr| {
            let mut bytes = Vec::new();
            ciborium::into_writer(repr, &mut bytes).expect("encodable");
            bytes
        };

        let futur = HeaderRepr {
            format_version: FORMAT_VERSION + 1,
            ..clone_repr(&base)
        };
        assert!(matches!(
            Header::decode(&encode(&futur)),
            Err(Error::UnsupportedFormatVersion { found, supported })
                if found == FORMAT_VERSION + 1 && supported == FORMAT_VERSION
        ));

        let magie_etrangere = HeaderRepr {
            magic: serde_bytes::ByteBuf::from(b"PASVAULT".to_vec()),
            ..clone_repr(&base)
        };
        assert!(matches!(
            Header::decode(&encode(&magie_etrangere)),
            Err(Error::Corrupted)
        ));

        let kdf_inconnue = HeaderRepr {
            kdf_algorithm: "scrypt".to_owned(),
            ..clone_repr(&base)
        };
        assert!(matches!(
            Header::decode(&encode(&kdf_inconnue)),
            Err(Error::Corrupted)
        ));

        let aead_inconnu = HeaderRepr {
            aead_algorithm: "aes-gcm".to_owned(),
            ..clone_repr(&base)
        };
        assert!(matches!(
            Header::decode(&encode(&aead_inconnu)),
            Err(Error::Corrupted)
        ));

        let sel_court = HeaderRepr {
            kdf_salt: serde_bytes::ByteBuf::from(vec![0u8; 4]),
            ..clone_repr(&base)
        };
        assert!(matches!(
            Header::decode(&encode(&sel_court)),
            Err(Error::Corrupted)
        ));
    }

    fn clone_repr(repr: &HeaderRepr) -> HeaderRepr {
        HeaderRepr {
            magic: repr.magic.clone(),
            format_version: repr.format_version,
            kdf_algorithm: repr.kdf_algorithm.clone(),
            kdf_salt: repr.kdf_salt.clone(),
            kdf_memory_kib: repr.kdf_memory_kib,
            kdf_iterations: repr.kdf_iterations,
            kdf_parallelism: repr.kdf_parallelism,
            aead_algorithm: repr.aead_algorithm.clone(),
            wrapped_master_key: repr.wrapped_master_key.clone(),
        }
    }

    /// FR-033 à FR-035, C-021 : le changement de passphrase ne touche que
    /// l'enveloppe. La clé maîtresse — donc tout le contenu — est inchangée.
    #[test]
    fn le_changement_de_passphrase_conserve_la_cle_maitresse() {
        let (mut header, master) = en_tete();
        let nouvelle = SecretString::from("une toute nouvelle passphrase".to_owned());

        header
            .rewrap(&master, &nouvelle, params())
            .expect("ré-enveloppable");

        assert!(matches!(
            header.unlock(&passphrase()),
            Err(Error::Authentication)
        ));
        assert_eq!(
            header.unlock(&nouvelle).expect("déverrouillable").expose(),
            master.expose()
        );
    }

    /// C-023 : le changement de passphrase permet de relever les paramètres
    /// de coût au passage.
    #[test]
    fn le_changement_de_passphrase_peut_relever_les_parametres() {
        let (mut header, master) = en_tete();
        let sel_initial = header.salt;
        let releves = KdfParams::new(128, 2, 1).expect("valides");
        let nouvelle = SecretString::from("une toute nouvelle passphrase".to_owned());

        header
            .rewrap(&master, &nouvelle, releves)
            .expect("ré-enveloppable");

        assert_eq!(header.kdf_params(), releves);
        assert_ne!(header.salt, sel_initial, "le sel doit être renouvelé");
        assert_eq!(
            header.unlock(&nouvelle).expect("déverrouillable").expose(),
            master.expose()
        );
    }

    /// Un échec de dérivation laisse l'en-tête intact : on ne remplace qu'une
    /// fois le nouvel enveloppement produit.
    #[test]
    fn un_rewrap_en_echec_laisse_l_en_tete_intact() {
        let (mut header, master) = en_tete();
        let avant = header.clone();
        let nouvelle = SecretString::from("une toute nouvelle passphrase".to_owned());

        assert!(matches!(
            header.rewrap(&master, &nouvelle, KdfParams::from_header(0, 0, 0)),
            Err(Error::Authentication)
        ));
        assert_eq!(header, avant);
        assert!(header.unlock(&passphrase()).is_ok());
    }

    #[test]
    fn le_debug_de_l_en_tete_existe() {
        let (header, _) = en_tete();
        assert!(format!("{header:?}").contains("Header"));
    }
}
