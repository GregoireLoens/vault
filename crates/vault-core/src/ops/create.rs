//! Création d'un vault — T035.
//!
//! FR-001 à FR-006. Trois exigences gouvernent cette opération :
//!
//! - **FR-004** : refus si un vault existe déjà à cet emplacement. Écraser un
//!   coffre-fort par inadvertance détruirait des données irrécupérables.
//! - **FR-005, C-001** : refus d'une passphrase de moins de 12 caractères,
//!   **avant** toute écriture.
//! - **C-002** : la création est atomique. Le vault est bâti dans un répertoire
//!   temporaire voisin, puis mis en place par un unique `rename`. Un échec en
//!   cours de route ne laisse donc jamais de vault à moitié construit, qui
//!   s'ouvrirait sans contenir ce qu'il faut.
//!
//! L'avertissement d'irréversibilité (FR-003) n'est **pas** affiché ici : la
//! bibliothèque ne parle pas à l'utilisateur. Sa présentation incombe à
//! l'appelant, et le contrat de la ligne de commande l'exige avant tout appel.

use std::path::Path;

use secrecy::{ExposeSecret, SecretString};

use crate::crypto::kdf::KdfParams;
use crate::error::{Error, Result};
use crate::format::header::Header;
use crate::format::index::Index;
use crate::fs::atomic;
use crate::fs::lock::VaultLock;
use crate::ops::{HEADER_FILE, INDEX_FILE, OBJECTS_DIR};
use crate::{MIN_PASSPHRASE_LEN, UnlockedVault, Vault};

impl Vault {
    /// Crée un vault et ouvre immédiatement la session correspondante.
    ///
    /// N'affiche aucun avertissement : la présentation de l'irréversibilité
    /// (FR-003) incombe à l'appelant.
    ///
    /// # Errors
    ///
    /// - [`Error::WeakPassphrase`] si la passphrase fait moins de
    ///   [`MIN_PASSPHRASE_LEN`] caractères (FR-005, C-001) ;
    /// - [`Error::AlreadyExists`] si l'emplacement est déjà occupé (FR-004) ;
    /// - [`Error::Io`] si le répertoire parent n'existe pas ou n'est pas
    ///   accessible en écriture ;
    /// - [`Error::AlreadyInUse`] si le verrou du vault neuf ne peut pas être
    ///   pris.
    // La passphrase est prise **par valeur** bien que le corps n'en ait besoin
    // que par référence : c'est ce qui garantit qu'elle est libérée — donc
    // effacée par `secrecy` — au retour de l'appel, plutôt que de rester
    // vivante chez l'appelant après usage (FR-041). Le contrat de
    // `contracts/library.md` la fixe ainsi.
    #[allow(clippy::needless_pass_by_value)]
    pub fn create(
        path: &Path,
        passphrase: SecretString,
        params: KdfParams,
    ) -> Result<UnlockedVault> {
        // La longueur se compte en caractères et non en octets : une
        // passphrase de douze caractères accentués ferait plus de douze octets,
        // et une règle exprimée en octets serait plus permissive pour les uns
        // que pour les autres.
        if passphrase.expose_secret().chars().count() < MIN_PASSPHRASE_LEN {
            return Err(Error::WeakPassphrase {
                minimum: MIN_PASSPHRASE_LEN,
            });
        }
        if path.exists() {
            return Err(Error::AlreadyExists);
        }

        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };

        // Le chantier est voisin de la destination, donc sur le même système
        // de fichiers : c'est la condition pour que le `rename` final soit
        // atomique (D-008).
        let chantier = tempfile::Builder::new()
            .prefix(".vault-neuf-")
            .tempdir_in(parent)?;

        let (header, master_key) = Header::create(&passphrase, params)?;
        let index = Index::new();

        std::fs::create_dir(chantier.path().join(OBJECTS_DIR))?;
        atomic::write(&chantier.path().join(HEADER_FILE), &header.encode()?)?;
        let index_chiffre = index.encrypt(&master_key)?;
        atomic::write(&chantier.path().join(INDEX_FILE), &index_chiffre)?;

        let chantier = chantier.keep();
        if let Err(erreur) = std::fs::rename(&chantier, path) {
            // La mise en place a échoué : le chantier ne doit pas survivre.
            drop(std::fs::remove_dir_all(&chantier));
            return Err(erreur.into());
        }

        let lock = VaultLock::acquire(path)?;
        Ok(UnlockedVault::new(
            path.to_path_buf(),
            header,
            master_key,
            index,
            lock,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> KdfParams {
        KdfParams::new(64, 1, 1).expect("paramètres valides")
    }

    fn passphrase() -> SecretString {
        SecretString::from("passphrase de test bien assez longue".to_owned())
    }

    #[test]
    fn un_vault_neuf_a_la_disposition_attendue() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");

        let vault = Vault::create(&coffre, passphrase(), params()).expect("créable");

        assert_eq!(vault.path(), coffre);
        assert_eq!(vault.kdf_params(), params());
        assert_eq!(vault.index_version(), 0);
        assert!(vault.list(None).is_empty());

        assert!(coffre.join(HEADER_FILE).is_file());
        assert!(coffre.join(INDEX_FILE).is_file());
        assert!(coffre.join(OBJECTS_DIR).is_dir());
    }

    /// FR-005, C-001 : la longueur se compte en caractères. Douze caractères
    /// accentués passent, onze ne passent pas.
    #[test]
    fn la_longueur_de_passphrase_se_compte_en_caracteres() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");

        assert!(matches!(
            Vault::create(
                &atelier.path().join("court"),
                SecretString::from("onze carac".to_owned()),
                params()
            ),
            Err(Error::WeakPassphrase { minimum: 12 })
        ));
        assert!(!atelier.path().join("court").exists());

        // Douze caractères, vingt-quatre octets.
        let accentuee = SecretString::from("éàèùéàèùéàèù".to_owned());
        assert_eq!(accentuee.expose_secret().chars().count(), 12);
        assert!(Vault::create(&atelier.path().join("accentuee"), accentuee, params()).is_ok());
    }

    #[test]
    fn un_emplacement_occupe_est_refuse() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let occupe = atelier.path().join("occupe");
        std::fs::write(&occupe, b"un fichier ordinaire").expect("écrivable");

        assert!(matches!(
            Vault::create(&occupe, passphrase(), params()),
            Err(Error::AlreadyExists)
        ));
        assert_eq!(
            std::fs::read(&occupe).expect("lisible"),
            b"un fichier ordinaire",
            "l'emplacement occupé ne doit pas être touché"
        );
    }

    /// C-002 : un parent inexistant fait échouer la création sans laisser le
    /// moindre résidu.
    #[test]
    fn un_parent_inexistant_ne_laisse_aucun_residu() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let impossible = atelier.path().join("absent").join("coffre");

        assert!(matches!(
            Vault::create(&impossible, passphrase(), params()),
            Err(Error::Io(_))
        ));
        assert!(!atelier.path().join("absent").exists());
        assert_eq!(
            std::fs::read_dir(atelier.path()).expect("listable").count(),
            0,
            "aucun chantier ne doit subsister"
        );
    }

    /// Un chemin relatif sans parent explicite vise le répertoire courant.
    #[test]
    fn un_chemin_relatif_est_accepte() {
        // `set_current_dir` est global au processus : ce test et son jumeau de
        // `ops::import` prennent le même verrou, et rétablissent l'état avant
        // de rendre la main (voir `ops::serie`).
        let _serie = crate::ops::serie::repertoire_courant();
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let ancien = std::env::current_dir().expect("répertoire courant");
        std::env::set_current_dir(atelier.path()).expect("déplaçable");

        let resultat = Vault::create(Path::new("coffre-relatif"), passphrase(), params());

        std::env::set_current_dir(&ancien).expect("rétablissable");
        assert!(resultat.is_ok());
        assert!(
            atelier
                .path()
                .join("coffre-relatif")
                .join(HEADER_FILE)
                .is_file()
        );
    }

    /// C-002 : si la mise en place échoue, le chantier ne survit pas.
    ///
    /// Un lien symbolique cassé n'« existe » pas au sens de `Path::exists`, qui
    /// suit les liens — la création dépasse donc le refus d'emplacement occupé
    /// et va jusqu'au `rename`, que le système refuse. C'est le seul moyen
    /// portable de provoquer cet échec sans course entre deux processus.
    #[cfg(unix)]
    #[test]
    fn un_echec_de_mise_en_place_ne_laisse_aucun_chantier() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        std::os::unix::fs::symlink(atelier.path().join("cible-inexistante"), &coffre)
            .expect("lien créable");

        assert!(matches!(
            Vault::create(&coffre, passphrase(), params()),
            Err(Error::Io(_))
        ));

        let restants: Vec<std::ffi::OsString> = std::fs::read_dir(atelier.path())
            .expect("listable")
            .filter_map(std::result::Result::ok)
            .map(|entree| entree.file_name())
            .collect();
        assert_eq!(
            restants,
            vec![std::ffi::OsString::from("coffre")],
            "{restants:?}"
        );
    }

    /// Des paramètres de dérivation aberrants font échouer la création sans
    /// rien laisser derrière.
    #[test]
    fn des_parametres_aberrants_ne_laissent_aucun_residu() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");

        assert!(matches!(
            Vault::create(&coffre, passphrase(), KdfParams::from_header(0, 0, 0)),
            Err(Error::Authentication)
        ));
        assert!(!coffre.exists());
        assert_eq!(
            std::fs::read_dir(atelier.path()).expect("listable").count(),
            0
        );
    }
}
