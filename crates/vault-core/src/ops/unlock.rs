//! Ouverture, déverrouillage et verrouillage — T036, T037.
//!
//! FR-007 à FR-012. La séparation entre [`Vault::open`] et [`Vault::unlock`]
//! n'est pas cosmétique : elle permet de lire les paramètres publics d'un vault
//! — version de format, coûts de dérivation — **sans** demander la passphrase,
//! ce qu'exige `vault info` (CLI-018), tout en garantissant par le système de
//! types qu'un vault verrouillé n'expose aucune méthode de lecture du contenu
//! (C-007, FR-011).
//!
//! Le verrou exclusif est pris **avant** la dérivation de la clé (C-005) : sans
//! cela, deux instances lancées ensemble paieraient chacune une dérivation
//! Argon2id de plusieurs centaines de millisecondes avant que la seconde
//! n'apprenne qu'elle n'aurait pas dû.

use std::path::Path;

use secrecy::SecretString;

use crate::error::{Error, Result};
use crate::format::header::Header;
use crate::format::index::Index;
use crate::fs::lock::VaultLock;
use crate::ops::{HEADER_FILE, INDEX_FILE};
use crate::{UnlockedVault, Vault};

impl Vault {
    /// Ouvre un vault sans le déverrouiller.
    ///
    /// Ne lit que l'en-tête, qui est public par conception. Aucun secret n'est
    /// manipulé, aucune passphrase n'est demandée.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] s'il n'y a pas de vault à cet emplacement ;
    /// - [`Error::Corrupted`] si l'en-tête est illisible ;
    /// - [`Error::UnsupportedFormatVersion`] si le format dépasse ce que cette
    ///   version sait lire (VR-H1) ;
    /// - [`Error::Io`] pour toute autre défaillance de lecture.
    pub fn open(path: &Path) -> Result<Self> {
        let bytes = match std::fs::read(path.join(HEADER_FILE)) {
            Ok(bytes) => bytes,
            Err(erreur) if erreur.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::NotFound);
            }
            Err(erreur) => return Err(erreur.into()),
        };
        Ok(Self::new(path.to_path_buf(), Header::decode(&bytes)?))
    }

    /// Déverrouille le vault et ouvre une session.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyInUse`] si une autre instance détient le verrou
    ///   (FR-012, C-005) ;
    /// - [`Error::Authentication`] si la passphrase est erronée, l'en-tête
    ///   altéré ou la clé maîtresse corrompue — **sans distinction possible**
    ///   (FR-008, C-004) ;
    /// - [`Error::Corrupted`] si l'index est illisible ;
    /// - [`Error::Io`] si l'index ne peut pas être lu.
    // Par valeur délibérément : voir la note de `Vault::create`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn unlock(self, passphrase: SecretString) -> Result<UnlockedVault> {
        let Self { path, header } = self;

        let lock = VaultLock::acquire(&path)?;
        let master_key = header.unlock(&passphrase)?;
        let index = Index::decrypt(&master_key, &std::fs::read(path.join(INDEX_FILE))?)?;

        Ok(UnlockedVault::new(path, header, master_key, index, lock))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::KdfParams;

    fn params() -> KdfParams {
        KdfParams::new(64, 1, 1).expect("paramètres valides")
    }

    fn passphrase() -> SecretString {
        SecretString::from("passphrase de test bien assez longue".to_owned())
    }

    fn coffre_neuf(atelier: &Path) -> std::path::PathBuf {
        let coffre = atelier.join("coffre");
        Vault::create(&coffre, passphrase(), params())
            .expect("créable")
            .lock();
        coffre
    }

    #[test]
    fn un_vault_se_referme_et_se_rouvre() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());

        let verrouille = Vault::open(&coffre).expect("ouvrable");
        assert_eq!(verrouille.format_version(), crate::FORMAT_VERSION);
        assert_eq!(verrouille.kdf_params(), params());

        let session = verrouille.unlock(passphrase()).expect("déverrouillable");
        assert!(session.list(None).is_empty());
        assert_eq!(session.index_version(), 0);
    }

    #[test]
    fn un_emplacement_sans_vault_est_introuvable() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        assert!(matches!(Vault::open(atelier.path()), Err(Error::NotFound)));
        assert!(matches!(
            Vault::open(&atelier.path().join("nulle-part")),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn un_en_tete_illisible_est_signale() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());
        std::fs::write(coffre.join(HEADER_FILE), b"ceci n'est pas un en-tete").expect("écrivable");

        assert!(matches!(Vault::open(&coffre), Err(Error::Corrupted)));
    }

    /// Une défaillance de lecture qui n'est pas une absence remonte telle
    /// quelle, et non déguisée en `NotFound` : dire « il n'y a pas de vault ici »
    /// alors qu'il y en a un mais illisible enverrait l'utilisateur chercher au
    /// mauvais endroit.
    #[cfg(unix)]
    #[test]
    fn un_en_tete_illisible_par_permission_remonte_l_erreur() {
        use std::os::unix::fs::PermissionsExt;

        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());
        let en_tete = coffre.join(HEADER_FILE);

        let mut permissions = std::fs::metadata(&en_tete).expect("lisible").permissions();
        permissions.set_mode(0o000);
        std::fs::set_permissions(&en_tete, permissions).expect("modifiable");

        let resultat = Vault::open(&coffre);

        let mut permissions = std::fs::metadata(&en_tete).expect("lisible").permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&en_tete, permissions).expect("modifiable");

        assert!(
            matches!(resultat, Err(Error::Io(_))),
            "obtenu : {resultat:?}"
        );
    }

    /// C-004, FR-008 : une passphrase erronée renvoie `Authentication`, le même
    /// variant qu'un en-tête altéré.
    #[test]
    fn une_passphrase_erronee_est_refusee() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());

        let fausse = SecretString::from("une passphrase parfaitement fausse".to_owned());
        assert!(matches!(
            Vault::open(&coffre).expect("ouvrable").unlock(fausse),
            Err(Error::Authentication)
        ));
    }

    /// FR-012, C-005 : une seconde session sur le même vault est refusée.
    #[test]
    fn une_seconde_session_est_refusee() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        let premiere = Vault::create(&coffre, passphrase(), params()).expect("créable");

        assert!(matches!(
            Vault::open(&coffre).expect("ouvrable").unlock(passphrase()),
            Err(Error::AlreadyInUse)
        ));

        premiere.lock();
        assert!(
            Vault::open(&coffre)
                .expect("ouvrable")
                .unlock(passphrase())
                .is_ok()
        );
    }

    #[test]
    fn un_index_absent_ou_altere_est_signale() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());

        let index = std::fs::read(coffre.join(INDEX_FILE)).expect("lisible");
        let mut altere = index.clone();
        let dernier = altere.len() - 1;
        altere[dernier] ^= 0x01;
        std::fs::write(coffre.join(INDEX_FILE), &altere).expect("écrivable");
        assert!(matches!(
            Vault::open(&coffre).expect("ouvrable").unlock(passphrase()),
            Err(Error::Authentication)
        ));

        std::fs::remove_file(coffre.join(INDEX_FILE)).expect("supprimable");
        assert!(matches!(
            Vault::open(&coffre).expect("ouvrable").unlock(passphrase()),
            Err(Error::Io(_))
        ));
    }

    /// C-003 bis, VR-S3 : le délai d'inactivité est conservé et ne déclenche
    /// rien. FR-010 est différé.
    #[test]
    fn le_delai_d_inactivite_reste_sans_effet() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let mut session =
            Vault::create(&atelier.path().join("coffre"), passphrase(), params()).expect("créable");

        assert_eq!(session.idle_timeout(), None);
        session.set_idle_timeout(Some(std::time::Duration::from_secs(1)));
        assert_eq!(
            session.idle_timeout(),
            Some(std::time::Duration::from_secs(1))
        );
        assert!(
            session.list(None).is_empty(),
            "la session reste exploitable"
        );
    }
}
