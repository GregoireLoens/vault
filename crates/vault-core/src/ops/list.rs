//! Consultation du contenu — T042.
//!
//! FR-024, FR-025. **C-014 : ces opérations ne produisent aucune écriture sur
//! disque, pas même un temporaire.** L'index déchiffré est déjà en mémoire
//! depuis le déverrouillage ; consulter le vault, c'est le parcourir, rien de
//! plus. Un cache de listing, une miniature ou un fichier de tri seraient
//! autant de fuites en clair (principe I).

use crate::error::{Error, Result};
use crate::format::path::VaultPath;
use crate::{Entry, UnlockedVault};

impl UnlockedVault {
    /// Les entrées situées sous `under`, ou toutes depuis la racine.
    ///
    /// Le résultat est trié par chemin, dans l'ordre de l'index : les parents
    /// précèdent leurs enfants, ce qui permet à l'appelant de l'afficher en
    /// arborescence sans retrier.
    #[must_use]
    pub fn list(&self, under: Option<&VaultPath>) -> Vec<Entry> {
        let racine = VaultPath::root();
        self.index
            .list(under.unwrap_or(&racine))
            .into_iter()
            .map(Entry::from_index)
            .collect()
    }

    /// L'entrée située à ce chemin.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] si aucune entrée n'occupe ce chemin.
    pub fn stat(&self, path: &VaultPath) -> Result<Entry> {
        self.index
            .get(path)
            .map(Entry::from_index)
            .ok_or(Error::NotFound)
    }

    /// Identifiant du blob et taille après remplissage d'une entrée.
    ///
    /// Sert le mode de diagnostic de la ligne de commande (CLI-010). Ces deux
    /// valeurs sont déjà observables par quiconque inspecte le répertoire du
    /// vault : les afficher ne révèle rien de plus.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] si aucune entrée n'occupe ce chemin.
    pub fn blob_of(&self, path: &VaultPath) -> Result<Option<(crate::BlobId, u64)>> {
        let entree = self.index.get(path).ok_or(Error::NotFound)?;
        Ok(entree.blob_id.zip(entree.blob_padded_size))
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;
    use crate::crypto::kdf::KdfParams;
    use crate::{AddMode, EntryKind, OnConflict, Vault};

    fn params() -> KdfParams {
        KdfParams::new(64, 1, 1).expect("paramètres valides")
    }

    fn passphrase() -> SecretString {
        SecretString::from("passphrase de test bien assez longue".to_owned())
    }

    fn chemin(composants: &[&[u8]]) -> VaultPath {
        VaultPath::from_components(composants.iter().map(|c| c.to_vec())).expect("chemin valide")
    }

    #[test]
    fn la_consultation_n_ecrit_rien_sur_le_disque() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let source = atelier.path().join("arbre");
        std::fs::create_dir_all(source.join("photos")).expect("créable");
        std::fs::write(source.join("photos/plage.jpg"), b"image").expect("écrivable");
        std::fs::write(source.join("note.txt"), b"texte").expect("écrivable");

        let mut vault =
            Vault::create(&atelier.path().join("coffre"), passphrase(), params()).expect("créable");
        vault
            .add_dir(
                &source,
                &VaultPath::root(),
                AddMode::Copy,
                OnConflict::Fail,
                &mut |_| {},
            )
            .expect("ajoutable");

        let empreinte = |racine: &std::path::Path| {
            let mut fichiers: Vec<(std::path::PathBuf, u64)> = walkdir::WalkDir::new(racine)
                .into_iter()
                .filter_map(std::result::Result::ok)
                .map(|entree| {
                    (
                        entree.path().to_path_buf(),
                        entree.metadata().map(|m| m.len()).unwrap_or_default(),
                    )
                })
                .collect();
            fichiers.sort();
            fichiers
        };

        let avant = empreinte(vault.path());

        assert_eq!(vault.list(None).len(), 3);
        assert_eq!(vault.list(Some(&chemin(&[b"photos"]))).len(), 2);
        assert!(vault.stat(&chemin(&[b"note.txt"])).is_ok());

        assert_eq!(
            empreinte(vault.path()),
            avant,
            "C-014 : la consultation ne doit rien écrire"
        );
    }

    #[test]
    fn les_entrees_sont_ordonnees_parents_avant_enfants() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let source = atelier.path().join("arbre");
        std::fs::create_dir_all(source.join("a/b")).expect("créable");
        std::fs::write(source.join("a/b/feuille.txt"), b"feuille").expect("écrivable");

        let mut vault =
            Vault::create(&atelier.path().join("coffre"), passphrase(), params()).expect("créable");
        vault
            .add_dir(
                &source,
                &VaultPath::root(),
                AddMode::Copy,
                OnConflict::Fail,
                &mut |_| {},
            )
            .expect("ajoutable");

        let chemins: Vec<VaultPath> = vault.list(None).into_iter().map(|e| e.path).collect();
        assert_eq!(
            chemins,
            vec![
                chemin(&[b"a"]),
                chemin(&[b"a", b"b"]),
                chemin(&[b"a", b"b", b"feuille.txt"])
            ]
        );
    }

    #[test]
    fn une_entree_absente_est_introuvable() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let vault =
            Vault::create(&atelier.path().join("coffre"), passphrase(), params()).expect("créable");

        assert!(matches!(
            vault.stat(&chemin(&[b"absent"])),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            vault.blob_of(&chemin(&[b"absent"])),
            Err(Error::NotFound)
        ));
        assert!(vault.list(Some(&chemin(&[b"absent"]))).is_empty());
    }

    /// CLI-010 : le diagnostic expose l'identifiant de blob et la taille après
    /// remplissage — deux informations qu'une inspection du répertoire donne
    /// déjà. Un dossier n'en a aucune.
    #[test]
    fn le_diagnostic_expose_le_blob_d_un_fichier() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let source = atelier.path().join("arbre");
        std::fs::create_dir_all(source.join("dossier")).expect("créable");
        std::fs::write(source.join("dossier/fichier.bin"), vec![0x11; 100]).expect("écrivable");

        let mut vault =
            Vault::create(&atelier.path().join("coffre"), passphrase(), params()).expect("créable");
        vault
            .add_dir(
                &source,
                &VaultPath::root(),
                AddMode::Copy,
                OnConflict::Fail,
                &mut |_| {},
            )
            .expect("ajoutable");

        let (blob_id, rempli) = vault
            .blob_of(&chemin(&[b"dossier", b"fichier.bin"]))
            .expect("présente")
            .expect("un fichier a un blob");
        assert_eq!(rempli, 4096);
        assert!(
            vault
                .path()
                .join("objects")
                .join(blob_id.to_hex())
                .is_file()
        );

        assert_eq!(
            vault.blob_of(&chemin(&[b"dossier"])).expect("présente"),
            None,
            "un dossier n'occupe aucun blob"
        );

        let entree = vault
            .stat(&chemin(&[b"dossier", b"fichier.bin"]))
            .expect("présente");
        assert_eq!(entree.kind, EntryKind::File);
        assert_eq!(entree.size, Some(100));
    }
}
