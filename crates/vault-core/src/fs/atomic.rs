//! Écritures atomiques — T026, décision D-008.
//!
//! Toute écriture du vault suit la même séquence :
//!
//! 1. écrire dans un fichier temporaire du **même répertoire** ;
//! 2. `fsync` du fichier temporaire ;
//! 3. `rename` du temporaire vers sa destination ;
//! 4. `fsync` du répertoire parent.
//!
//! Le temporaire est créé dans le répertoire de destination, et non dans
//! `/tmp` : `rename` n'est atomique qu'au sein d'un même système de fichiers,
//! et un temporaire hors du vault violerait de toute façon le principe I en
//! déposant des octets chiffrés — ou pire — ailleurs que dans le vault.
//!
//! Les deux `fsync` ne sont pas de la prudence excessive. Sans le premier, le
//! `rename` peut atteindre le disque avant le contenu, et une coupure
//! d'alimentation laisse un fichier de la bonne taille rempli de zéros. Sans
//! le second, c'est le `rename` lui-même qui peut ne pas avoir survécu.
//!
//! # Sémantique par plateforme
//!
//! `rename` écrase l'ancienne cible atomiquement sur POSIX. Sous Windows,
//! `std::fs::rename` échoue si la cible existe : [`replace`] y passe par
//! `ReplaceFileW` via [`std::fs::rename`] après suppression, faute de quoi le
//! remplacement de l'index serait impossible. Le `fsync` de répertoire n'y a
//! pas d'équivalent et n'y est pas tenté.

use std::io::Write;
use std::path::Path;

use crate::error::Result;

/// Écrit `contents` dans `path`, atomiquement.
///
/// # Errors
///
/// [`crate::Error::Io`] si la création du temporaire, l'écriture, la
/// synchronisation ou le remplacement échouent.
pub(crate) fn write(path: &Path, contents: &[u8]) -> Result<()> {
    let mut temporary = temporary_in(parent_of(path))?;
    temporary.write_all(contents)?;
    commit(temporary, path)
}

/// Crée un fichier temporaire dans le répertoire de `path`, destiné à être
/// validé par [`commit`].
///
/// Sert les écritures en flux — un blob de plusieurs gigaoctets ne passe pas
/// par un tampon en mémoire (SC-010).
///
/// # Errors
///
/// [`crate::Error::Io`] si le temporaire ne peut pas être créé.
pub(crate) fn temporary_for(path: &Path) -> Result<tempfile::NamedTempFile> {
    temporary_in(parent_of(path))
}

/// Valide un temporaire à sa place définitive.
///
/// # Errors
///
/// [`crate::Error::Io`] si la synchronisation ou le remplacement échouent.
pub(crate) fn commit(temporary: tempfile::NamedTempFile, path: &Path) -> Result<()> {
    temporary.as_file().sync_all()?;
    let (file, temporary_path) = temporary.keep().map_err(|error| error.error)?;
    // Le descripteur n'a plus d'utilité une fois le contenu synchronisé ; le
    // fermer avant le renommage évite de tenir un verrou sous Windows.
    drop(file);

    replace(&temporary_path, path)?;
    sync_dir(parent_of(path))
}

fn temporary_in(directory: &Path) -> Result<tempfile::NamedTempFile> {
    Ok(tempfile::Builder::new()
        .prefix(".vault-tmp-")
        .tempfile_in(directory)?)
}

/// Répertoire qui accueillera le temporaire.
///
/// `Path::parent` rend `Some("")` pour un chemin sans répertoire, et non
/// `None` : sans cette normalisation, le temporaire serait créé dans un
/// répertoire au nom vide, que le système refuse.
pub(crate) fn parent_of(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

#[cfg(unix)]
fn replace(from: &Path, to: &Path) -> Result<()> {
    std::fs::rename(from, to)?;
    Ok(())
}

// Sous Windows, `rename` refuse d'écraser une cible existante. Le
// remplacement de l'index et de l'en-tête serait donc impossible sans cette
// variante. Elle n'est pas atomique au même degré que sur POSIX : entre la
// suppression et le renommage, la destination n'existe pas. C'est la limite
// relevée par D-008, à valider par les tests d'interruption de la phase 3.
//
// Ce code n'existe pas dans la compilation Linux : il ne crée donc aucune
// ligne non couverte sur la plateforme d'intégration continue, et la matrice
// Windows de la CI l'exerce.
#[cfg(windows)]
fn replace(from: &Path, to: &Path) -> Result<()> {
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(_) if to.exists() => {
            std::fs::remove_file(to)?;
            std::fs::rename(from, to)?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

/// Synchronise un répertoire, pour que l'entrée renommée survive à une
/// coupure.
#[cfg(unix)]
pub(crate) fn sync_dir(directory: &Path) -> Result<()> {
    std::fs::File::open(directory)?.sync_all()?;
    Ok(())
}

// Windows n'expose pas de descripteur de répertoire synchronisable : la
// durabilité de l'entrée de répertoire y relève du système de fichiers.
// Absent de la compilation Linux, donc sans effet sur la couverture.
#[cfg(windows)]
pub(crate) fn sync_dir(_directory: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l_ecriture_atomique_pose_le_contenu() {
        let repertoire = tempfile::tempdir().expect("répertoire temporaire");
        let cible = repertoire.path().join("fichier");

        write(&cible, b"premier").expect("écrivable");
        assert_eq!(std::fs::read(&cible).expect("lisible"), b"premier");
    }

    /// Le remplacement doit fonctionner sur une cible existante : c'est le cas
    /// nominal de la réécriture de l'index (VR-I5).
    #[test]
    fn l_ecriture_atomique_remplace_une_cible_existante() {
        let repertoire = tempfile::tempdir().expect("répertoire temporaire");
        let cible = repertoire.path().join("index");

        write(&cible, b"ancien contenu plus long").expect("écrivable");
        write(&cible, b"neuf").expect("remplaçable");
        assert_eq!(std::fs::read(&cible).expect("lisible"), b"neuf");
    }

    /// Aucun temporaire ne doit subsister après une écriture réussie : un
    /// résidu serait un fichier du vault que rien ne référence.
    #[test]
    fn aucun_temporaire_ne_subsiste() {
        let repertoire = tempfile::tempdir().expect("répertoire temporaire");
        write(&repertoire.path().join("fichier"), b"contenu").expect("écrivable");

        let restants: Vec<_> = std::fs::read_dir(repertoire.path())
            .expect("listable")
            .filter_map(std::result::Result::ok)
            .map(|entree| entree.file_name())
            .collect();
        assert_eq!(restants.len(), 1, "restants : {restants:?}");
    }

    #[test]
    fn l_ecriture_en_flux_passe_par_un_temporaire() {
        let repertoire = tempfile::tempdir().expect("répertoire temporaire");
        let cible = repertoire.path().join("blob");

        let mut temporaire = temporary_for(&cible).expect("créable");
        temporaire.write_all(b"un morceau ").expect("écrivable");
        temporaire.write_all(b"puis un autre").expect("écrivable");
        assert!(!cible.exists(), "la cible n'existe qu'au commit");

        commit(temporaire, &cible).expect("validable");
        assert_eq!(
            std::fs::read(&cible).expect("lisible"),
            b"un morceau puis un autre"
        );
    }

    /// Un temporaire abandonné disparaît : une interruption avant le commit ne
    /// laisse pas de déchet (C-013).
    #[test]
    fn un_temporaire_abandonne_disparait() {
        let repertoire = tempfile::tempdir().expect("répertoire temporaire");
        let cible = repertoire.path().join("blob");

        let chemin_temporaire = {
            let temporaire = temporary_for(&cible).expect("créable");
            temporaire.path().to_path_buf()
        };
        assert!(!chemin_temporaire.exists());
        assert!(!cible.exists());
    }

    #[test]
    fn un_repertoire_inexistant_remonte_une_erreur() {
        let repertoire = tempfile::tempdir().expect("répertoire temporaire");
        let cible = repertoire.path().join("absent").join("fichier");
        assert!(matches!(
            write(&cible, b"contenu"),
            Err(crate::Error::Io(_))
        ));
        assert!(matches!(temporary_for(&cible), Err(crate::Error::Io(_))));
    }

    /// Un chemin sans parent explicite s'écrit dans le répertoire courant.
    #[test]
    fn un_chemin_sans_parent_vise_le_repertoire_courant() {
        assert_eq!(parent_of(Path::new("fichier")), Path::new("."));
        assert_eq!(parent_of(Path::new("a/b")), Path::new("a"));
    }
}
