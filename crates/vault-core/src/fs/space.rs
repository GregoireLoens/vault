//! Vérification de l'espace disponible — T028, FR-029.
//!
//! C-015 : l'extraction vérifie l'espace **avant** d'écrire quoi que ce soit.
//! Sans cela, un disque plein produit une sortie partielle, que l'utilisateur
//! peut prendre pour ses données restituées — exactement le genre de « presque
//! réussi » que la constitution refuse.
//!
//! La bibliothèque standard n'expose aucun moyen d'interroger l'espace libre :
//! il faut passer par `statvfs` sous Unix et `GetDiskFreeSpaceExW` sous
//! Windows. `fs4` enveloppe les deux sans que `vault-core` ait à contenir la
//! moindre ligne de code non sûr — le crate est ajouté pour cette seule
//! fonction, et n'apporte aucune dépendance réseau.
//!
//! La vérification reste **indicative** : entre l'interrogation et l'écriture,
//! un autre processus peut consommer l'espace. Elle transforme le cas courant
//! — « il manque manifestement de la place » — en refus net et immédiat, sans
//! prétendre à une garantie que le système de fichiers ne donne pas.
//!
//! # Un chemin absent ne se comporte pas partout pareil
//!
//! `statvfs` échoue sur un chemin qui n'existe pas ; `GetDiskFreeSpaceExW`
//! remonte jusqu'au volume et **réussit**. Ces fonctions ne sont donc pas un
//! moyen fiable de savoir si un répertoire existe, et aucun appelant ne doit
//! s'en servir ainsi : [`crate::UnlockedVault::extract`] vérifie l'existence de
//! sa destination explicitement, avant d'arriver ici.

use std::path::Path;

use crate::error::{Error, Result};

/// Espace disponible, en octets, sur le support qui porte `path`.
///
/// # Errors
///
/// [`Error::Io`] si le chemin ne peut pas être interrogé.
pub(crate) fn available(path: &Path) -> Result<u64> {
    Ok(fs4::available_space(path)?)
}

/// Vérifie que `needed` octets peuvent être écrits sous `path`.
///
/// # Errors
///
/// - [`Error::InsufficientSpace`] si l'espace disponible est inférieur ;
/// - [`Error::Io`] si le chemin ne peut pas être interrogé.
pub(crate) fn ensure(path: &Path, needed: u64) -> Result<()> {
    let available = available(path)?;
    if available < needed {
        return Err(Error::InsufficientSpace { needed, available });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l_espace_disponible_se_lit() {
        let repertoire = tempfile::tempdir().expect("répertoire temporaire");
        assert!(available(repertoire.path()).expect("interrogeable") > 0);
    }

    #[test]
    fn un_besoin_modeste_passe() {
        let repertoire = tempfile::tempdir().expect("répertoire temporaire");
        ensure(repertoire.path(), 0).expect("aucun besoin");
        ensure(repertoire.path(), 1024).expect("un kibioctet doit tenir");
    }

    /// FR-029, C-015 : un besoin manifestement hors d'atteinte est refusé, et
    /// l'erreur porte les deux nombres qui permettent à l'appelant de
    /// l'expliquer.
    #[test]
    fn un_besoin_hors_d_atteinte_est_refuse() {
        let repertoire = tempfile::tempdir().expect("répertoire temporaire");
        let erreur = ensure(repertoire.path(), u64::MAX).expect_err("aurait dû refuser");
        assert!(matches!(
            erreur,
            Error::InsufficientSpace { needed, available }
                if needed == u64::MAX && available < u64::MAX
        ));
    }

    /// Sous Unix, interroger un chemin absent échoue, et l'erreur remonte.
    ///
    /// Ce test est réservé aux systèmes POSIX : `GetDiskFreeSpaceExW` remonte
    /// jusqu'au volume et réussirait — voir la note de module. Aucun appelant
    /// ne s'appuie sur cette différence, l'existence de la destination étant
    /// vérifiée en amont.
    #[cfg(unix)]
    #[test]
    fn un_chemin_inexistant_remonte_une_erreur() {
        let repertoire = tempfile::tempdir().expect("répertoire temporaire");
        let absent = repertoire.path().join("absent");
        assert!(matches!(available(&absent), Err(Error::Io(_))));
        assert!(matches!(ensure(&absent, 1), Err(Error::Io(_))));
    }
}
