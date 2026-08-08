//! Verrou d'accès exclusif — T027, décision D-009.
//!
//! FR-012 exige d'empêcher deux instances de modifier le même vault. Le verrou
//! est consultatif, posé sur le fichier `.lock` via `fd-lock`, qui enveloppe
//! `flock` et `LockFileEx` derrière une interface unique.
//!
//! Le point qui décide du choix : **le noyau libère ce verrou à la fermeture
//! du descripteur**, y compris lorsque le processus est tué sans ménagement.
//! Un fichier témoin, lui, survivrait à l'arrêt brutal et laisserait le vault
//! définitivement « occupé » par un processus mort.
//!
//! VR-S4 : le verrou est tenu pendant toute la session déverrouillée.
//!
//! # Une conséquence à connaître si l'on duplique le processus
//!
//! Un verrou `flock` appartient à la **description de fichier ouverte**, et
//! `fork` la partage entre les deux processus. Une application qui embarquerait
//! cette bibliothèque et se dupliquerait pendant qu'un de ses fils d'exécution
//! détient le verrou d'un vault en léguerait donc une copie à l'enfant : le
//! verrou resterait pris jusqu'à ce que l'enfant ferme le descripteur, ce que
//! son `exec` fait — les descripteurs ouverts par la bibliothèque standard sont
//! marqués « à fermer sur exec » — mais pas avant.
//!
//! Le binaire `vault` ne se duplique jamais, et n'est donc pas concerné. La
//! remarque vaut pour un appelant tiers, et la suite de tests l'a rencontrée
//! pour de bon : voir l'en-tête de `tests/rekey_interruption.rs`.

use std::fs::{File, OpenOptions};
use std::path::Path;

use crate::error::{Error, Result};

/// Nom du fichier support du verrou, dans le répertoire du vault.
pub(crate) const LOCK_FILE: &str = ".lock";

/// Verrou exclusif tenu sur un vault.
///
/// Le verrou est relâché à la libération de cette valeur, qui ferme le
/// descripteur.
#[derive(Debug)]
pub(crate) struct VaultLock {
    // `fd_lock::RwLock` possède le descripteur ; c'est sa libération qui rend
    // le verrou. Le champ n'est jamais relu, mais il ne peut pas disparaître.
    _lock: fd_lock::RwLock<File>,
}

impl VaultLock {
    /// Prend le verrou exclusif du vault situé dans `vault_dir`.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyInUse`] si une autre instance le détient (C-005) ;
    /// - [`Error::Io`] si le fichier support ne peut pas être ouvert.
    pub(crate) fn acquire(vault_dir: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(vault_dir.join(LOCK_FILE))?;

        let mut lock = fd_lock::RwLock::new(file);

        // Le garde relâcherait le verrou en se libérant, alors qu'il doit
        // tenir toute la session (VR-S4). L'oublier laisse le verrou en place
        // jusqu'à la fermeture du descripteur, c'est-à-dire jusqu'à la
        // libération du `RwLock` conservé ci-dessous — exactement la durée de
        // vie voulue. Le garde ne détient qu'un emprunt : l'oublier ne fuit
        // aucune ressource.
        let acquired = lock.try_write().map(std::mem::forget).is_ok();
        if !acquired {
            return Err(Error::AlreadyInUse);
        }
        Ok(Self { _lock: lock })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_verrou_se_prend_et_cree_son_fichier() {
        let repertoire = tempfile::tempdir().expect("répertoire temporaire");
        let verrou = VaultLock::acquire(repertoire.path()).expect("verrouillable");
        assert!(repertoire.path().join(LOCK_FILE).exists());
        assert!(format!("{verrou:?}").contains("VaultLock"));
    }

    /// FR-012, C-005 : une seconde prise échoue tant que la première tient.
    #[test]
    fn une_seconde_prise_echoue() {
        let repertoire = tempfile::tempdir().expect("répertoire temporaire");
        let _premier = VaultLock::acquire(repertoire.path()).expect("verrouillable");
        assert!(matches!(
            VaultLock::acquire(repertoire.path()),
            Err(Error::AlreadyInUse)
        ));
    }

    /// Le verrou est rendu à la libération, y compris quand elle résulte d'un
    /// abandon par panique — c'est le déroulement de pile qui la déclenche.
    #[test]
    fn le_verrou_est_rendu_a_la_liberation() {
        let repertoire = tempfile::tempdir().expect("répertoire temporaire");

        {
            let _verrou = VaultLock::acquire(repertoire.path()).expect("verrouillable");
        }
        let _reprise = VaultLock::acquire(repertoire.path()).expect("reverrouillable");
    }

    #[test]
    fn un_repertoire_inexistant_remonte_une_erreur() {
        let repertoire = tempfile::tempdir().expect("répertoire temporaire");
        assert!(matches!(
            VaultLock::acquire(&repertoire.path().join("absent")),
            Err(Error::Io(_))
        ));
    }

    /// Le fichier support préexistant est réutilisé sans être vidé : il ne
    /// contient rien, mais le tronquer serait une écriture inutile à chaque
    /// ouverture.
    #[test]
    fn un_fichier_support_preexistant_est_reutilise() {
        let repertoire = tempfile::tempdir().expect("répertoire temporaire");
        std::fs::write(repertoire.path().join(LOCK_FILE), b"").expect("créable");
        let _verrou = VaultLock::acquire(repertoire.path()).expect("verrouillable");
    }
}
