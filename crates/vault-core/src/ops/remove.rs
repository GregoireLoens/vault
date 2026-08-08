//! Suppression — T059.
//!
//! FR-031, FR-032. Une seule décision gouverne cette opération, et elle tient
//! dans l'ordre de deux gestes.
//!
//! **C-020, VR-B6 : l'index est réécrit d'abord, les blobs sont déliés
//! ensuite.** L'ordre inverse paraîtrait plus naturel — libérer la place, puis
//! enregistrer — et il serait faux. Une interruption entre les deux laisserait
//! un index désignant un blob absent, c'est-à-dire un vault cassé, dont une
//! entrée listable ne s'extrairait plus. Dans le bon ordre, la même
//! interruption ne laisse que des blobs que plus personne ne référence : des
//! déchets inertes, que le déverrouillage suivant balaie (VR-I6).
//!
//! C'est la même règle que pour l'ajout, appliquée dans l'autre sens : l'index
//! est le **point d'engagement** du vault (D-008), et ce qu'il ne mentionne pas
//! n'existe pas.
//!
//! **C-019 : aucune confirmation n'est demandée ici.** La bibliothèque ne parle
//! pas à l'utilisateur ; le rappel qu'il n'existe ni corbeille ni annulation
//! incombe à l'appelant, et le contrat de la ligne de commande l'exige
//! (CLI-014).

use crate::UnlockedVault;
use crate::error::Result;
use crate::format::blob::BlobId;
use crate::format::path::VaultPath;

impl UnlockedVault {
    /// Retire une entrée du vault, et sa descendance si `recursive`.
    ///
    /// Rend le nombre d'entrées retirées — dossiers compris, qui n'occupent
    /// aucun blob mais disparaissent tout de même de l'index.
    ///
    /// Ne demande **aucune** confirmation (C-019).
    ///
    /// # Errors
    ///
    /// - [`crate::Error::NotFound`] si aucune entrée n'occupe ce chemin ;
    /// - [`crate::Error::DirectoryNotEmpty`] si l'entrée a une descendance et
    ///   que `recursive` est faux — un dossier peuplé ne part pas par mégarde ;
    /// - [`crate::Error::Io`] si l'index ne peut pas être réécrit. Dans ce cas
    ///   **aucun blob n'a été délié** et l'index en mémoire est restauré : le
    ///   vault est exactement dans l'état où il était.
    pub fn remove(&mut self, path: &VaultPath, recursive: bool) -> Result<usize> {
        // `Index::remove` refuse avant de modifier quoi que ce soit ;
        // l'instantané ne sert donc qu'à l'échec de la réécriture.
        let instantane = self.index.clone();
        let retirees = self.index.remove(path, recursive)?;

        if let Err(erreur) = self.commit_index() {
            self.index = instantane;
            return Err(erreur);
        }

        // À partir d'ici, l'index sur le disque ne référence plus ces blobs :
        // ce ne sont déjà plus que des déchets.
        let blobs: Vec<BlobId> = retirees
            .iter()
            .filter_map(|entree| entree.blob_id)
            .collect();
        self.unlink_blobs(&blobs);

        Ok(retirees.len())
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use secrecy::SecretString;

    use super::*;
    use crate::crypto::kdf::KdfParams;
    use crate::error::Error;
    use crate::{AddMode, OnConflict, Vault};

    fn params() -> KdfParams {
        KdfParams::new(64, 1, 1).expect("paramètres valides")
    }

    fn passphrase() -> SecretString {
        SecretString::from("passphrase de test bien assez longue".to_owned())
    }

    fn chemin(composants: &[&[u8]]) -> VaultPath {
        VaultPath::from_components(composants.iter().map(|c| c.to_vec())).expect("chemin valide")
    }

    /// Un vault contenant `note.txt` et `photos/plage.jpg`.
    fn atelier(racine: &Path) -> (UnlockedVault, PathBuf) {
        let source = racine.join("source");
        std::fs::create_dir_all(source.join("photos")).expect("créable");
        std::fs::write(source.join("note.txt"), b"une note").expect("écrivable");
        std::fs::write(source.join("photos/plage.jpg"), vec![0x7e; 3000]).expect("écrivable");

        let coffre = racine.join("coffre");
        let mut vault = Vault::create(&coffre, passphrase(), params()).expect("créable");
        vault
            .add_dir(
                &source,
                &VaultPath::root(),
                AddMode::Copy,
                OnConflict::Fail,
                &mut |_| {},
            )
            .expect("ajoutable");
        (vault, coffre)
    }

    #[test]
    fn retirer_une_feuille_delie_son_blob() {
        let racine = tempfile::tempdir().expect("répertoire temporaire");
        let (mut vault, coffre) = atelier(racine.path());
        let (blob_id, _) = vault
            .blob_of(&chemin(&[b"note.txt"]))
            .expect("présente")
            .expect("un blob");
        let blob = crate::ops::blob_path(&coffre, &blob_id);

        assert_eq!(vault.remove(&chemin(&[b"note.txt"]), false).expect("ok"), 1);
        assert!(!blob.exists());
        assert!(matches!(
            vault.stat(&chemin(&[b"note.txt"])),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn retirer_un_dossier_peuple_exige_la_recursion() {
        let racine = tempfile::tempdir().expect("répertoire temporaire");
        let (mut vault, _) = atelier(racine.path());

        assert!(matches!(
            vault.remove(&chemin(&[b"photos"]), false),
            Err(Error::DirectoryNotEmpty)
        ));
        assert_eq!(
            vault.remove(&chemin(&[b"photos"]), true).expect("ok"),
            2,
            "le dossier et son fichier"
        );
        assert!(vault.stat(&chemin(&[b"photos"])).is_err());
    }

    #[test]
    fn retirer_une_entree_absente_est_introuvable() {
        let racine = tempfile::tempdir().expect("répertoire temporaire");
        let (mut vault, _) = atelier(racine.path());

        assert!(matches!(
            vault.remove(&chemin(&[b"absente"]), false),
            Err(Error::NotFound)
        ));
    }

    /// C-020 : la réécriture de l'index échoue, donc rien n'est délié et
    /// l'index en mémoire est celui d'avant.
    #[cfg(unix)]
    #[test]
    fn un_echec_de_reecriture_restaure_l_index_et_ne_delie_rien() {
        use std::os::unix::fs::PermissionsExt;

        let racine = tempfile::tempdir().expect("répertoire temporaire");
        let (mut vault, coffre) = atelier(racine.path());
        let (blob_id, _) = vault
            .blob_of(&chemin(&[b"note.txt"]))
            .expect("présente")
            .expect("un blob");
        let blob = crate::ops::blob_path(&coffre, &blob_id);
        let avant = vault.index_version();

        let initiales = std::fs::metadata(&coffre).expect("lisible").permissions();
        let mut verrouillees = initiales.clone();
        verrouillees.set_mode(0o500);
        std::fs::set_permissions(&coffre, verrouillees).expect("modifiable");

        let resultat = vault.remove(&chemin(&[b"note.txt"]), false);

        std::fs::set_permissions(&coffre, initiales).expect("modifiable");

        assert!(matches!(resultat, Err(Error::Io(_))), "{resultat:?}");
        assert!(blob.exists(), "aucun blob délié avant la réécriture");
        assert_eq!(vault.index_version(), avant);
        assert!(vault.stat(&chemin(&[b"note.txt"])).is_ok());
    }
}
