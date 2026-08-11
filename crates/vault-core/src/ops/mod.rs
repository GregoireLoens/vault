//! Opérations du vault — phase 3, T035 et suivantes.
//!
//! Ce module assemble le format, la cryptographie et la couche système en
//! opérations utilisables. Il ne contient aucune primitive : tout ce qui touche
//! au chiffrement vit dans [`crate::crypto`], et tout ce qui touche au disque
//! dans [`crate::fs`].
//!
//! Les `impl` de [`crate::Vault`] et [`crate::UnlockedVault`] sont répartis
//! entre les fichiers de ce module plutôt que rassemblés dans `lib.rs` : chaque
//! opération reste lisible à côté de la règle qu'elle sert.

pub(crate) mod add;
pub(crate) mod create;
pub(crate) mod export;
pub(crate) mod extract;
pub(crate) mod import;
pub(crate) mod list;
pub(crate) mod rekey;
pub(crate) mod remove;
pub(crate) mod unlock;

use std::path::{Path, PathBuf};

use crate::UnlockedVault;
use crate::error::{Error, Result};
use crate::format::blob::BlobId;
use crate::format::path::VaultPath;
use crate::fs::atomic;

/// Nom du fichier d'en-tête, dans le répertoire du vault.
pub(crate) const HEADER_FILE: &str = "header";

/// Nom du fichier d'index.
pub(crate) const INDEX_FILE: &str = "index";

/// Nom du répertoire des blobs.
pub(crate) const OBJECTS_DIR: &str = "objects";

/// Emplacement d'un blob dans un vault.
pub(crate) fn blob_path(vault_dir: &Path, blob_id: &BlobId) -> PathBuf {
    vault_dir.join(OBJECTS_DIR).join(blob_id.to_hex())
}

/// Écriture de l'index et déliaison des blobs — la plomberie que l'ajout et la
/// suppression partagent.
///
/// Elle vit ici plutôt que dans l'une des deux opérations parce que **l'ordre
/// dans lequel ces deux gestes s'enchaînent est la garantie elle-même**
/// (D-008, C-013, C-020). L'ajout écrit les blobs puis l'index ; la suppression
/// écrit l'index puis délie les blobs. Dans les deux cas l'index est le point
/// d'engagement, et une interruption ne laisse jamais qu'un déchet inerte.
impl UnlockedVault {
    /// Réécrit l'index sur le disque, intégralement et atomiquement (VR-I5).
    pub(crate) fn commit_index(&self) -> Result<()> {
        atomic::write(
            &self.path.join(INDEX_FILE),
            &self.index.encrypt(&self.master_key)?,
        )
    }

    /// Retire des blobs du disque.
    ///
    /// Les échecs sont ignorés : un blob qui résiste reste un orphelin, donc un
    /// déchet que le déverrouillage suivant balaiera, et jamais une incohérence.
    pub(crate) fn unlink_blobs(&self, blobs: &[BlobId]) {
        for blob_id in blobs {
            drop(std::fs::remove_file(blob_path(&self.path, blob_id)));
        }
    }
}

/// Retire de `path` les `strip.depth()` premiers composants.
///
/// Sert à décider où une entrée atterrit à l'extraction : extraire
/// `photos/été/plage.jpg` vers `sortie/` produit `sortie/plage.jpg`, tandis
/// qu'extraire `photos` produit `sortie/photos/été/plage.jpg`.
///
/// # Errors
///
/// [`Error::InvalidPath`] si le résultat viole VR-I4, ce qui supposerait un
/// index forgé ayant passé ses invariants.
pub(crate) fn strip_prefix(path: &VaultPath, strip: &VaultPath) -> Result<VaultPath> {
    if !path.starts_with(strip) {
        return Err(Error::InvalidPath);
    }
    VaultPath::from_components(path.components().skip(strip.depth()).map(<[u8]>::to_vec))
}

#[cfg(test)]
pub(crate) mod serie {
    //! Sérialisation des tests qui déplacent le **répertoire courant**.
    //!
    //! `std::env::set_current_dir` est global au processus : deux tests qui
    //! l'emploient en parallèle se marchent dessus, et l'un des deux crée son
    //! vault dans le répertoire de l'autre. Le symptôme est un échec
    //! **intermittent**, qui dépend de l'ordonnancement des fils — donc de la
    //! plateforme, ce qui est la pire forme de flottement : vert ici, rouge
    //! ailleurs, et pour une raison qui n'a rien à voir avec ce qui est
    //! éprouvé.
    //!
    //! Tout test qui déplace le répertoire courant prend donc ce verrou, et le
    //! garde jusqu'à l'avoir rétabli.

    use std::sync::{Mutex, MutexGuard, PoisonError};

    static VERROU: Mutex<()> = Mutex::new(());

    /// Prend le verrou du répertoire courant.
    ///
    /// Un verrou empoisonné par un test qui a paniqué ailleurs ne doit pas
    /// faire échouer les suivants : ce verrou ne protège aucune donnée, il
    /// ordonne des effets de bord.
    pub(crate) fn repertoire_courant() -> MutexGuard<'static, ()> {
        VERROU.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chemin(composants: &[&[u8]]) -> VaultPath {
        VaultPath::from_components(composants.iter().map(|c| c.to_vec())).expect("chemin valide")
    }

    #[test]
    fn le_chemin_d_un_blob_est_son_identifiant_hexadecimal() {
        let blob_id = BlobId::generate();
        let chemin = blob_path(Path::new("/coffre"), &blob_id);
        assert_eq!(
            chemin,
            PathBuf::from("/coffre")
                .join("objects")
                .join(blob_id.to_hex())
        );
    }

    #[test]
    fn le_prefixe_retire_est_celui_demande() {
        let complet = chemin(&[b"photos", b"ete", b"plage.jpg"]);

        assert_eq!(
            strip_prefix(&complet, &chemin(&[b"photos", b"ete"])).expect("valide"),
            chemin(&[b"plage.jpg"])
        );
        assert_eq!(
            strip_prefix(&complet, &chemin(&[b"photos"])).expect("valide"),
            chemin(&[b"ete", b"plage.jpg"])
        );
        assert_eq!(
            strip_prefix(&complet, &VaultPath::root()).expect("valide"),
            complet
        );
        assert!(strip_prefix(&complet, &complet).expect("valide").is_root());
    }

    #[test]
    fn un_prefixe_etranger_est_refuse() {
        assert!(matches!(
            strip_prefix(&chemin(&[b"a"]), &chemin(&[b"b"])),
            Err(Error::InvalidPath)
        ));
    }
}
