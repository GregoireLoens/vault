//! Dérivation de clé depuis la passphrase — T018.
//!
//! Argon2id (D-004) transforme la passphrase en **clé d'enveloppe**. Cette clé
//! ne chiffre que la clé maîtresse ; elle ne touche jamais au contenu. C'est
//! cette indirection qui rend le changement de passphrase proportionnel à
//! l'en-tête et non à la taille du vault (FR-033 à FR-035).
//!
//! VR-H2 : **aucun paramètre n'est codé en dur sur le chemin de lecture.** Les
//! valeurs de [`KdfParams::default`] ne servent qu'à la création d'un vault
//! neuf ; l'ouverture d'un vault existant emploie exclusivement les paramètres
//! inscrits dans son en-tête. Un vault produit avec des paramètres relevés
//! reste donc ouvrable par une version du logiciel dont les défauts diffèrent.

use argon2::{Algorithm, Argon2, Version};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Longueur de la clé d'enveloppe, en octets.
pub(crate) const WRAPPING_KEY_LEN: usize = 32;

/// Longueur du sel de dérivation, en octets.
pub(crate) const SALT_LEN: usize = 16;

/// Clé d'enveloppe dérivée de la passphrase, effacée à sa libération.
pub(crate) type WrappingKey = Zeroizing<[u8; WRAPPING_KEY_LEN]>;

/// Paramètres de coût d'Argon2id, tels qu'ils figurent dans l'en-tête.
///
/// Ils appartiennent au vault, pas au logiciel (VR-H2, C-003).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl KdfParams {
    /// Coût mémoire par défaut : 128 MiB.
    ///
    /// Assez coûteux pour gêner une attaque massivement parallèle, assez
    /// modeste pour un déverrouillage occasionnel sur un poste de bureau.
    pub const DEFAULT_MEMORY_KIB: u32 = 131_072;

    /// Nombre de passes par défaut.
    pub const DEFAULT_ITERATIONS: u32 = 3;

    /// Degré de parallélisme par défaut.
    pub const DEFAULT_PARALLELISM: u32 = 4;

    /// Construit des paramètres après validation.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKdfParams`] si la combinaison est hors des bornes
    /// admises par Argon2id.
    pub fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self> {
        let params = Self {
            memory_kib,
            iterations,
            parallelism,
        };
        params.to_argon2().map_err(|_| Error::InvalidKdfParams)?;
        Ok(params)
    }

    /// Construit des paramètres **sans** les valider.
    ///
    /// Réservé au décodage de l'en-tête : des paramètres aberrants lus sur
    /// disque ne doivent pas produire une erreur distincte de celle d'une
    /// passphrase erronée (C-024). Ils échoueront à la dérivation, en
    /// [`Error::Authentication`] comme tout le reste.
    pub(crate) fn from_header(memory_kib: u32, iterations: u32, parallelism: u32) -> Self {
        Self {
            memory_kib,
            iterations,
            parallelism,
        }
    }

    /// Coût mémoire, en kibioctets.
    #[must_use]
    pub fn memory_kib(&self) -> u32 {
        self.memory_kib
    }

    /// Nombre de passes.
    #[must_use]
    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    /// Degré de parallélisme.
    #[must_use]
    pub fn parallelism(&self) -> u32 {
        self.parallelism
    }

    fn to_argon2(self) -> std::result::Result<argon2::Params, argon2::Error> {
        argon2::Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(WRAPPING_KEY_LEN),
        )
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: Self::DEFAULT_MEMORY_KIB,
            iterations: Self::DEFAULT_ITERATIONS,
            parallelism: Self::DEFAULT_PARALLELISM,
        }
    }
}

/// Dérive la clé d'enveloppe depuis la passphrase et le sel de l'en-tête.
///
/// # Errors
///
/// [`Error::Authentication`] si Argon2id refuse la combinaison — sel trop
/// court ou paramètres aberrants. Un en-tête altéré passe par ce chemin et
/// doit rester indiscernable d'une passphrase erronée (C-024, VR-P2).
pub(crate) fn derive_wrapping_key(
    passphrase: &SecretString,
    salt: &[u8],
    params: KdfParams,
) -> Result<WrappingKey> {
    let argon2_params = params.to_argon2().map_err(|_| Error::Authentication)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut key: WrappingKey = Zeroizing::new([0u8; WRAPPING_KEY_LEN]);
    argon2
        .hash_password_into(passphrase.expose_secret().as_bytes(), salt, key.as_mut())
        .map_err(|_| Error::Authentication)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Paramètres volontairement minuscules : ces tests vérifient la
    /// mécanique de dérivation, pas le coût de calcul. Employer 128 MiB ici
    /// ajouterait des dizaines de secondes à chaque exécution de la suite.
    fn params_de_test() -> KdfParams {
        KdfParams::new(64, 1, 1).expect("paramètres valides")
    }

    fn sel() -> [u8; SALT_LEN] {
        [7u8; SALT_LEN]
    }

    #[test]
    fn les_defauts_sont_ceux_de_la_decision_d004() {
        let defaut = KdfParams::default();
        assert_eq!(defaut.memory_kib(), 131_072);
        assert_eq!(defaut.iterations(), 3);
        assert_eq!(defaut.parallelism(), 4);
        assert!(defaut.to_argon2().is_ok());
    }

    #[test]
    fn des_parametres_aberrants_sont_refuses_a_la_construction() {
        assert!(matches!(
            KdfParams::new(0, 1, 1),
            Err(Error::InvalidKdfParams)
        ));
        assert!(matches!(
            KdfParams::new(64, 0, 1),
            Err(Error::InvalidKdfParams)
        ));
        assert!(matches!(
            KdfParams::new(64, 1, 0),
            Err(Error::InvalidKdfParams)
        ));
    }

    #[test]
    fn la_derivation_est_deterministe() {
        let passphrase = SecretString::from("une passphrase suffisamment longue".to_owned());
        let a = derive_wrapping_key(&passphrase, &sel(), params_de_test()).expect("dérivable");
        let b = derive_wrapping_key(&passphrase, &sel(), params_de_test()).expect("dérivable");
        assert_eq!(a.as_ref(), b.as_ref());
        assert_ne!(a.as_ref(), &[0u8; WRAPPING_KEY_LEN]);
    }

    #[test]
    fn chaque_entree_change_la_cle() {
        let passphrase = SecretString::from("une passphrase suffisamment longue".to_owned());
        let autre = SecretString::from("une AUTRE passphrase suffisamment longue".to_owned());
        let reference = derive_wrapping_key(&passphrase, &sel(), params_de_test()).expect("ok");

        let par_passphrase = derive_wrapping_key(&autre, &sel(), params_de_test()).expect("ok");
        assert_ne!(reference.as_ref(), par_passphrase.as_ref());

        let par_sel =
            derive_wrapping_key(&passphrase, &[9u8; SALT_LEN], params_de_test()).expect("ok");
        assert_ne!(reference.as_ref(), par_sel.as_ref());

        let par_params = derive_wrapping_key(
            &passphrase,
            &sel(),
            KdfParams::new(64, 2, 1).expect("valides"),
        )
        .expect("ok");
        assert_ne!(reference.as_ref(), par_params.as_ref());
    }

    /// C-024 : un en-tête altéré — paramètres aberrants ou sel tronqué — se
    /// solde par la même erreur qu'une passphrase erronée.
    #[test]
    fn un_en_tete_altere_donne_une_erreur_d_authentification() {
        let passphrase = SecretString::from("une passphrase suffisamment longue".to_owned());

        let params_aberrants = KdfParams::from_header(0, 0, 0);
        assert!(matches!(
            derive_wrapping_key(&passphrase, &sel(), params_aberrants),
            Err(Error::Authentication)
        ));

        // Argon2 exige un sel d'au moins 8 octets.
        assert!(matches!(
            derive_wrapping_key(&passphrase, b"court", params_de_test()),
            Err(Error::Authentication)
        ));
    }

    #[test]
    fn les_parametres_lus_dans_un_en_tete_sont_conserves_tels_quels() {
        let params = KdfParams::from_header(1024, 5, 2);
        assert_eq!(params.memory_kib(), 1024);
        assert_eq!(params.iterations(), 5);
        assert_eq!(params.parallelism(), 2);
        assert_eq!(params, KdfParams::new(1024, 5, 2).expect("valides"));
        assert!(!format!("{params:?}").is_empty());
    }
}
