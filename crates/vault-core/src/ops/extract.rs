//! Extraction vers le disque — T043.
//!
//! FR-026 à FR-030. Trois exigences la gouvernent :
//!
//! - **C-015, FR-029** : l'espace disponible est vérifié **avant** d'écrire
//!   quoi que ce soit. Un disque plein en cours d'extraction produirait une
//!   sortie partielle que l'utilisateur pourrait prendre pour ses données.
//! - **C-016, FR-030, FR-039** : chaque morceau est authentifié **avant**
//!   d'être écrit. Une altération interrompt l'extraction et la sortie
//!   partielle disparaît — elle n'a jamais quitté son fichier temporaire.
//! - **C-018, FR-028** : rien n'est écrasé sans instruction explicite.
//!
//! L'écriture passe par un temporaire du répertoire de destination, validé par
//! un `rename`. Ce n'est pas seulement une garantie d'atomicité : c'est ce qui
//! fait qu'un échec de déchiffrement ne laisse **aucun** octet de clair
//! partiel sur le disque, le temporaire étant supprimé à sa libération.

use std::path::{Path, PathBuf};

use crate::crypto::stream;
use crate::error::{Error, Result};
use crate::format::blob;
use crate::format::index::{EntryKind, IndexEntry};
use crate::format::path::VaultPath;
use crate::fs::{atomic, space};
use crate::ops::{blob_path, strip_prefix};
use crate::{OnConflict, UnlockedVault};

/// Nombre maximal de renommages tentés à destination.
const MAX_RENAME_ATTEMPTS: u32 = 1000;

impl UnlockedVault {
    /// Extrait une entrée et sa descendance vers `dest`.
    ///
    /// Extraire `photos/plage.jpg` vers `sortie/` produit `sortie/plage.jpg` ;
    /// extraire `photos` produit `sortie/photos/…`. Autrement dit, c'est le
    /// parent du chemin demandé qui sert de point de référence.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] si le chemin n'existe pas dans le vault ;
    /// - [`Error::Io`] de type `NotFound` si le répertoire de destination
    ///   n'existe pas ;
    /// - [`Error::InsufficientSpace`] si la place manque, **avant** écriture
    ///   (FR-029, C-015) ;
    /// - [`Error::AlreadyExists`] si la destination est occupée et que
    ///   `on_conflict` vaut [`OnConflict::Fail`] (FR-028, C-018) ;
    /// - [`Error::Authentication`] si un morceau ne s'authentifie pas, ou
    ///   [`Error::Corrupted`] si un blob est tronqué ou absent (FR-030) ;
    /// - [`Error::Io`] si l'écriture échoue.
    pub fn extract(&self, path: &VaultPath, dest: &Path, on_conflict: OnConflict) -> Result<()> {
        let entrees: Vec<IndexEntry> = self.index.list(path).into_iter().cloned().collect();
        if entrees.is_empty() {
            return Err(Error::NotFound);
        }

        // La destination doit exister, et c'est vérifié explicitement.
        //
        // S'en remettre à la vérification d'espace ne suffit pas : sous Unix,
        // interroger un chemin absent échoue, mais `GetDiskFreeSpaceExW`
        // remonte jusqu'au volume et réussit. L'extraction poursuivait alors
        // sous Windows et créait l'arborescence de destination au premier
        // `create_dir_all` — un chemin mal tapé produisait une extraction
        // silencieuse au lieu d'un refus. Créer la destination est une décision
        // qui appartient à l'appelant, pas une conséquence de la plateforme.
        if !dest.is_dir() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "le répertoire de destination n'existe pas",
            )));
        }

        // La somme des tailles réelles, et non des tailles remplies : c'est le
        // clair qui sera écrit à destination.
        let besoin: u64 = entrees.iter().filter_map(|entree| entree.size).sum();
        space::ensure(dest, besoin)?;

        let reference = path.parent().unwrap_or_else(VaultPath::root);
        for entree in &entrees {
            let relatif = strip_prefix(&entree.path, &reference)?;
            let cible = dest.join(relatif.to_os_path()?);

            match entree.kind {
                EntryKind::Directory => std::fs::create_dir_all(&cible)?,
                EntryKind::File => self.extract_file(entree, &cible, on_conflict)?,
            }
        }
        Ok(())
    }

    /// Extrait un fichier unique vers `cible`.
    fn extract_file(
        &self,
        entree: &IndexEntry,
        cible: &Path,
        on_conflict: OnConflict,
    ) -> Result<()> {
        std::fs::create_dir_all(cible.parent().ok_or(Error::InvalidPath)?)?;
        let cible = resolve_destination(cible, on_conflict)?;

        let (Some(blob_id), Some(taille)) = (entree.blob_id, entree.size) else {
            // Un fichier sans blob viole les invariants vérifiés au
            // déchiffrement de l'index : y arriver signale une corruption.
            return Err(Error::Corrupted);
        };

        let cle = self.master_key.blob_key(blob_id.as_bytes());
        let aad = blob::blob_aad(&blob_id);

        let mut source =
            std::fs::File::open(blob_path(&self.path, &blob_id)).map_err(|_| Error::Corrupted)?;
        let mut nonce = [0u8; stream::STREAM_NONCE_LEN];
        std::io::Read::read_exact(&mut source, &mut nonce).map_err(|_| Error::Corrupted)?;

        // Le clair transite par un temporaire : un échec de déchiffrement le
        // fait disparaître sans qu'un seul octet ait atteint la destination.
        let mut temporaire = atomic::temporary_for(&cible)?;
        stream::decrypt(&cle, &nonce, &aad, source, temporaire.as_file_mut(), taille)?;

        // FR-027 : la date d'origine est restituée. Elle est posée sur le
        // temporaire, donc avant que le fichier n'apparaisse à destination.
        temporaire
            .as_file()
            .set_modified(crate::unix_seconds_to_time(entree.modified))?;
        atomic::commit(temporaire, &cible)
    }
}

/// Décide où écrire, selon la politique de collision.
fn resolve_destination(cible: &Path, on_conflict: OnConflict) -> Result<PathBuf> {
    if !cible.exists() {
        return Ok(cible.to_path_buf());
    }
    match on_conflict {
        OnConflict::Fail => Err(Error::AlreadyExists),
        OnConflict::Replace => Ok(cible.to_path_buf()),
        OnConflict::Rename => free_name(cible),
    }
}

/// Trouve un nom libre à destination, sur le modèle `nom (2).ext`.
fn free_name(cible: &Path) -> Result<PathBuf> {
    let parent = cible.parent().ok_or(Error::AlreadyExists)?;
    let nom = cible.file_name().ok_or(Error::AlreadyExists)?;
    let nom = nom.to_string_lossy().into_owned();
    let (tronc, extension) = match nom.rfind('.') {
        Some(position) if position > 0 => nom.split_at(position),
        _ => (nom.as_str(), ""),
    };

    for numero in 2..=MAX_RENAME_ATTEMPTS {
        let candidat = parent.join(format!("{tronc} ({numero}){extension}"));
        if !candidat.exists() {
            return Ok(candidat);
        }
    }
    Err(Error::AlreadyExists)
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;
    use crate::crypto::kdf::KdfParams;
    use crate::{AddMode, Vault};

    fn params() -> KdfParams {
        KdfParams::new(64, 1, 1).expect("paramètres valides")
    }

    fn passphrase() -> SecretString {
        SecretString::from("passphrase de test bien assez longue".to_owned())
    }

    fn chemin(composants: &[&[u8]]) -> VaultPath {
        VaultPath::from_components(composants.iter().map(|c| c.to_vec())).expect("chemin valide")
    }

    struct Atelier {
        _racine: tempfile::TempDir,
        chemin: PathBuf,
        sortie: PathBuf,
        vault: UnlockedVault,
    }

    /// Prépare un vault contenant `photos/plage.jpg` et `note.txt`.
    fn atelier() -> Atelier {
        let racine = tempfile::tempdir().expect("répertoire temporaire");
        let chemin = racine.path().to_path_buf();

        let source = chemin.join("source");
        std::fs::create_dir_all(source.join("photos")).expect("créable");
        std::fs::write(source.join("photos/plage.jpg"), vec![0x7e; 70_000]).expect("écrivable");
        std::fs::write(source.join("note.txt"), b"une note").expect("écrivable");

        let mut vault =
            Vault::create(&chemin.join("coffre"), passphrase(), params()).expect("créable");
        vault
            .add_dir(
                &source,
                &VaultPath::root(),
                AddMode::Copy,
                OnConflict::Fail,
                &mut |_| {},
            )
            .expect("ajoutable");

        let sortie = chemin.join("sortie");
        std::fs::create_dir(&sortie).expect("créable");
        Atelier {
            _racine: racine,
            chemin,
            sortie,
            vault,
        }
    }

    #[test]
    fn un_fichier_s_extrait_a_la_racine_de_la_destination() {
        let atelier = atelier();
        atelier
            .vault
            .extract(&chemin(&[b"note.txt"]), &atelier.sortie, OnConflict::Fail)
            .expect("extractible");

        assert_eq!(
            std::fs::read(atelier.sortie.join("note.txt")).expect("lisible"),
            b"une note"
        );
        assert!(!atelier.sortie.join("photos").exists());
    }

    #[test]
    fn un_dossier_s_extrait_avec_son_arborescence() {
        let atelier = atelier();
        atelier
            .vault
            .extract(&chemin(&[b"photos"]), &atelier.sortie, OnConflict::Fail)
            .expect("extractible");

        assert_eq!(
            std::fs::read(atelier.sortie.join("photos/plage.jpg")).expect("lisible"),
            vec![0x7e; 70_000]
        );
    }

    #[test]
    fn la_racine_extrait_tout() {
        let atelier = atelier();
        atelier
            .vault
            .extract(&VaultPath::root(), &atelier.sortie, OnConflict::Fail)
            .expect("extractible");

        assert!(atelier.sortie.join("note.txt").is_file());
        assert!(atelier.sortie.join("photos/plage.jpg").is_file());
    }

    #[test]
    fn une_entree_absente_est_introuvable() {
        let atelier = atelier();
        assert!(matches!(
            atelier
                .vault
                .extract(&chemin(&[b"absent"]), &atelier.sortie, OnConflict::Fail),
            Err(Error::NotFound)
        ));
    }

    /// FR-028, C-018 : rien n'est écrasé sans instruction explicite.
    #[test]
    fn les_collisions_a_destination_se_resolvent_selon_l_instruction() {
        let atelier = atelier();
        let cible = atelier.sortie.join("note.txt");
        std::fs::write(&cible, b"contenu preexistant").expect("écrivable");

        assert!(matches!(
            atelier
                .vault
                .extract(&chemin(&[b"note.txt"]), &atelier.sortie, OnConflict::Fail),
            Err(Error::AlreadyExists)
        ));
        assert_eq!(
            std::fs::read(&cible).expect("lisible"),
            b"contenu preexistant"
        );

        atelier
            .vault
            .extract(&chemin(&[b"note.txt"]), &atelier.sortie, OnConflict::Rename)
            .expect("extractible");
        assert_eq!(
            std::fs::read(atelier.sortie.join("note (2).txt")).expect("lisible"),
            b"une note"
        );
        assert_eq!(
            std::fs::read(&cible).expect("lisible"),
            b"contenu preexistant"
        );

        atelier
            .vault
            .extract(
                &chemin(&[b"note.txt"]),
                &atelier.sortie,
                OnConflict::Replace,
            )
            .expect("extractible");
        assert_eq!(std::fs::read(&cible).expect("lisible"), b"une note");
    }

    #[test]
    fn le_renommage_a_destination_gere_les_noms_sans_extension() {
        let atelier = atelier();
        let sans_extension = atelier.sortie.join("sans");
        std::fs::write(&sans_extension, b"occupe").expect("écrivable");

        assert_eq!(
            free_name(&sans_extension).expect("nom libre"),
            atelier.sortie.join("sans (2)")
        );

        let cache = atelier.sortie.join(".cache");
        std::fs::write(&cache, b"occupe").expect("écrivable");
        assert_eq!(
            free_name(&cache).expect("nom libre"),
            atelier.sortie.join(".cache (2)")
        );
    }

    #[test]
    fn le_renommage_a_destination_abandonne_apres_mille_tentatives() {
        let atelier = atelier();
        let occupe = atelier.sortie.join("plein.txt");
        std::fs::write(&occupe, b"occupe").expect("écrivable");
        for numero in 2..=MAX_RENAME_ATTEMPTS {
            std::fs::write(
                atelier.sortie.join(format!("plein ({numero}).txt")),
                b"occupe",
            )
            .expect("écrivable");
        }

        assert!(matches!(free_name(&occupe), Err(Error::AlreadyExists)));
    }

    /// FR-029, C-015 : l'espace est vérifié avant toute écriture.
    #[test]
    fn l_espace_insuffisant_est_refuse_avant_ecriture() {
        let atelier = atelier();
        let mut vault_saboté = atelier.vault;

        // L'entrée annonce une taille hors d'atteinte : la vérification
        // d'espace doit refuser avant d'ouvrir le moindre blob.
        vault_saboté.index.replace(IndexEntry {
            path: chemin(&[b"enorme.bin"]),
            kind: EntryKind::File,
            size: Some(u64::MAX),
            modified: 0,
            blob_id: Some(crate::BlobId::generate()),
            blob_padded_size: Some(4096),
        });

        assert!(matches!(
            vault_saboté.extract(&chemin(&[b"enorme.bin"]), &atelier.sortie, OnConflict::Fail),
            Err(Error::InsufficientSpace { .. })
        ));
        assert_eq!(
            std::fs::read_dir(&atelier.sortie)
                .expect("listable")
                .count(),
            0,
            "rien ne doit avoir été écrit"
        );
    }

    /// FR-030, FR-039, C-016 : une altération interrompt l'extraction et ne
    /// laisse aucune sortie partielle.
    #[test]
    fn une_alteration_interrompt_sans_laisser_de_sortie_partielle() {
        let atelier = atelier();
        let (blob_id, _) = atelier
            .vault
            .blob_of(&chemin(&[b"photos", b"plage.jpg"]))
            .expect("présente")
            .expect("un blob");

        let chemin_blob = atelier.vault.path().join("objects").join(blob_id.to_hex());
        let mut octets = std::fs::read(&chemin_blob).expect("lisible");
        // Un octet du deuxième morceau : le premier s'authentifie, si bien que
        // l'écriture aurait commencé sans la protection du temporaire.
        octets[70_000] ^= 0x01;
        std::fs::write(&chemin_blob, &octets).expect("écrivable");

        assert!(matches!(
            atelier
                .vault
                .extract(&chemin(&[b"photos"]), &atelier.sortie, OnConflict::Fail),
            Err(Error::Authentication)
        ));

        assert!(
            !atelier.sortie.join("photos/plage.jpg").exists(),
            "aucun octet de clair non vérifié ne doit atteindre la destination"
        );
    }

    #[test]
    fn un_blob_absent_ou_tronque_est_signale() {
        let atelier = atelier();
        let (blob_id, _) = atelier
            .vault
            .blob_of(&chemin(&[b"note.txt"]))
            .expect("présente")
            .expect("un blob");
        let chemin_blob = atelier.vault.path().join("objects").join(blob_id.to_hex());

        std::fs::write(&chemin_blob, b"trop court").expect("écrivable");
        assert!(matches!(
            atelier
                .vault
                .extract(&chemin(&[b"note.txt"]), &atelier.sortie, OnConflict::Fail),
            Err(Error::Corrupted)
        ));

        std::fs::remove_file(&chemin_blob).expect("supprimable");
        assert!(matches!(
            atelier
                .vault
                .extract(&chemin(&[b"note.txt"]), &atelier.sortie, OnConflict::Fail),
            Err(Error::Corrupted)
        ));
    }

    /// Une entrée de type fichier privée de son blob dans l'index en mémoire
    /// est une corruption, et non une extraction silencieusement vide.
    #[test]
    fn une_entree_de_fichier_sans_blob_est_une_corruption() {
        let atelier = atelier();
        let mut vault = atelier.vault;
        vault.index.replace(IndexEntry {
            path: chemin(&[b"sans-blob.txt"]),
            kind: EntryKind::File,
            size: None,
            modified: 0,
            blob_id: None,
            blob_padded_size: None,
        });

        assert!(matches!(
            vault.extract(
                &chemin(&[b"sans-blob.txt"]),
                &atelier.sortie,
                OnConflict::Fail
            ),
            Err(Error::Corrupted)
        ));
    }

    /// La destination absente est refusée sur **toutes** les plateformes, et
    /// rien n'est créé : c'est ce que la vérification explicite garantit.
    #[test]
    fn une_destination_inexistante_est_signalee() {
        let atelier = atelier();
        let absente = atelier.chemin.join("nulle-part");

        let erreur = atelier
            .vault
            .extract(&chemin(&[b"note.txt"]), &absente, OnConflict::Fail)
            .expect_err("la destination n'existe pas");
        assert!(matches!(
            erreur,
            Error::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound
        ));
        assert!(!absente.exists(), "rien ne doit avoir été créé");

        // Un fichier ordinaire n'est pas davantage un répertoire de destination.
        let fichier = atelier.chemin.join("pas-un-dossier");
        std::fs::write(&fichier, b"occupe").expect("écrivable");
        assert!(matches!(
            atelier
                .vault
                .extract(&chemin(&[b"note.txt"]), &fichier, OnConflict::Fail),
            Err(Error::Io(_))
        ));
    }
}
