//! Effacement de l'original après déplacement — T041.
//!
//! FR-018 à FR-020. En mode déplacement, l'original est supprimé **après**
//! écriture et vérification complètes du blob (C-010) : un échec de l'ajout ne
//! doit jamais coûter les données d'origine.
//!
//! # Ce que l'écrasement garantit, et ce qu'il ne garantit pas
//!
//! Réécrire un fichier avant de le supprimer efface son contenu **là où le
//! système de fichiers a bien voulu réécrire**. Sur du matériel et des systèmes
//! de fichiers modernes, ce n'est presque jamais l'emplacement d'origine :
//!
//! - un SSD répartit l'usure et remappe les blocs, si bien que la réécriture
//!   atterrit ailleurs et laisse l'ancien bloc intact jusqu'au ramasse-miettes
//!   du contrôleur ;
//! - un système de fichiers à copie sur écriture — Btrfs, ZFS, APFS — écrit par
//!   principe ailleurs ;
//! - un système journalisé peut avoir recopié les données dans son journal ;
//! - un instantané, une sauvegarde ou un cache peuvent en détenir une copie que
//!   ce processus ne voit même pas.
//!
//! La constitution demande de documenter ces limites plutôt que de les masquer.
//! C'est le rôle de [`shred_capability`], que la ligne de commande consulte
//! pour avertir l'utilisateur (CLI-005) : **cette version ne renvoie jamais
//! [`ShredCapability::Guaranteed`]**, parce qu'il n'existe aucun moyen portable
//! d'établir la garantie. Prétendre le contraire serait pire que de ne rien
//! promettre.
//!
//! L'écrasement est tout de même effectué. Il ne garantit rien, mais il élève
//! le coût d'une récupération opportuniste, et il ne coûte qu'une écriture.

use std::io::Write;
use std::path::Path;

use crate::crypto::random;
use crate::error::Result;

/// Taille des blocs d'écrasement.
const OVERWRITE_CHUNK: usize = 64 * 1024;

/// Ce que l'effacement peut promettre sur un support donné.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ShredCapability {
    /// L'écrasement rend le contenu irrécupérable.
    ///
    /// **Jamais renvoyé par cette version.** Le variant existe pour que le
    /// contrat n'ait pas à changer le jour où une plateforme permettra
    /// d'établir la garantie — chiffrement de support avec destruction de clé,
    /// par exemple.
    Guaranteed,
    /// L'original est supprimé et son contenu écrasé, mais des traces peuvent
    /// subsister sur le support.
    BestEffort,
}

/// Ce que l'effacement peut promettre pour un chemin donné.
///
/// Voir la note de module : cette version renvoie toujours
/// [`ShredCapability::BestEffort`].
#[must_use]
pub fn shred_capability(_path: &Path) -> ShredCapability {
    ShredCapability::BestEffort
}

/// Écrase puis supprime un fichier.
///
/// # Errors
///
/// [`crate::Error::Io`] si le fichier ne peut pas être ouvert, réécrit,
/// synchronisé ou supprimé.
pub(crate) fn shred(path: &Path) -> Result<()> {
    let mut reste = std::fs::metadata(path)?.len();
    let mut fichier = std::fs::OpenOptions::new().write(true).open(path)?;

    let mut bloc = vec![0u8; OVERWRITE_CHUNK];
    while reste > 0 {
        let taille = usize::try_from(reste)
            .unwrap_or(OVERWRITE_CHUNK)
            .min(OVERWRITE_CHUNK);
        random::fill(&mut bloc[..taille]);
        fichier.write_all(&bloc[..taille])?;
        reste -= taille as u64;
    }
    // Sans synchronisation, l'écrasement peut n'avoir jamais quitté le cache
    // du système avant la suppression, et n'avoir donc servi à rien.
    fichier.sync_all()?;
    drop(fichier);

    std::fs::remove_file(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l_effacement_supprime_le_fichier() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let fichier = atelier.path().join("secret.bin");
        std::fs::write(&fichier, b"contenu a effacer").expect("écrivable");

        shred(&fichier).expect("effaçable");
        assert!(!fichier.exists());
    }

    /// L'écrasement porte sur toute la longueur, y compris au-delà d'un bloc.
    #[test]
    fn l_effacement_couvre_les_gros_fichiers() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let fichier = atelier.path().join("gros.bin");
        std::fs::write(&fichier, vec![0x42; OVERWRITE_CHUNK * 2 + 500]).expect("écrivable");

        shred(&fichier).expect("effaçable");
        assert!(!fichier.exists());
    }

    #[test]
    fn un_fichier_vide_s_efface_aussi() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let fichier = atelier.path().join("vide.bin");
        std::fs::write(&fichier, b"").expect("écrivable");

        shred(&fichier).expect("effaçable");
        assert!(!fichier.exists());
    }

    #[test]
    fn un_fichier_absent_remonte_une_erreur() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        assert!(matches!(
            shred(&atelier.path().join("jamais-cree")),
            Err(crate::Error::Io(_))
        ));
    }

    /// C-011, FR-020 : la capacité est annoncée honnêtement. Aucun support
    /// n'obtient la garantie dans cette version — voir la note de module.
    #[test]
    fn la_capacite_annoncee_est_honnete() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let capacite = shred_capability(atelier.path());

        assert_eq!(capacite, ShredCapability::BestEffort);
        assert_ne!(capacite, ShredCapability::Guaranteed);
        assert!(format!("{capacite:?}").contains("BestEffort"));
    }
}
