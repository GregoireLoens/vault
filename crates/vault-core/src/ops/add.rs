//! Ajout de fichiers et de dossiers — T038, T039, T040.
//!
//! FR-013 à FR-023. Trois invariants structurent cette opération.
//!
//! **Le traitement est en flux** (C-008). Le contenu passe par des morceaux de
//! 64 KiB, jamais par un tampon de la taille du fichier : SC-010 exige qu'un
//! fichier de 4 Go se traite sur une machine de 2 Go.
//!
//! **L'index est le point d'engagement** (D-008, C-013). Les blobs sont écrits
//! d'abord, l'index ensuite. Une interruption entre les deux laisse des blobs
//! orphelins — des déchets inertes que le déverrouillage suivant balaiera — et
//! jamais un index cassé. En cas d'échec, l'index en mémoire est restauré
//! depuis un instantané pris avant l'opération, et les blobs déjà écrits sont
//! retirés.
//!
//! **L'original n'est supprimé qu'en dernier** (C-010, FR-019, SC-011). En mode
//! déplacement, l'effacement vient après le remplacement de l'index, donc après
//! que le vault détient réellement les données. Un échec laisse l'original
//! intact.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::crypto::stream;
use crate::error::{Error, Result};
use crate::format::blob::{self, BlobId, MAX_FILE_SIZE};
use crate::format::index::{EntryKind, Index, IndexEntry};
use crate::format::path::VaultPath;
use crate::fs::{atomic, shred};
use crate::ops::blob_path;
use crate::{AddMode, Entry, OnConflict, UnlockedVault};

/// Nombre maximal de renommages tentés pour éviter une collision.
///
/// Au-delà, l'appelant a manifestement un problème plus intéressant que la
/// résolution de noms, et une boucle sans borne serait un point de blocage.
const MAX_RENAME_ATTEMPTS: u32 = 1000;

impl UnlockedVault {
    /// Ajoute un fichier ordinaire au vault.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] si la source est absente ou illisible ;
    /// - [`Error::UnsupportedEntry`] si la source n'est pas un fichier
    ///   ordinaire — lien symbolique, fichier spécial (C-012) ;
    /// - [`Error::FileTooLarge`] au-delà de [`MAX_FILE_SIZE`], **avant** toute
    ///   écriture (FR-023, C-009) ;
    /// - [`Error::AlreadyExists`] si le chemin est occupé et que
    ///   `on_conflict` vaut [`OnConflict::Fail`] (FR-016, VR-I3).
    pub fn add_file(
        &mut self,
        source: &Path,
        dest: &VaultPath,
        mode: AddMode,
        on_conflict: OnConflict,
    ) -> Result<Entry> {
        let metadata = regular_file_metadata(source)?;
        ensure_within_limit(metadata.len())?;

        let (chemin, evincee) = self.resolve_conflict(dest, on_conflict)?;
        let instantane = self.index.clone();

        let entree = self.store_file(source, chemin, &metadata)?;
        let blob_ecrit = entree.blob_id;
        self.index.replace(entree.clone());

        if let Err(erreur) = self.commit_index() {
            self.rollback(instantane, blob_ecrit.as_slice());
            return Err(erreur);
        }

        // À partir d'ici le vault détient les données : les blobs évincés et
        // l'original peuvent disparaître.
        self.unlink_blobs(evincee.as_slice());
        if mode == AddMode::Move {
            shred::shred(source)?;
        }
        Ok(Entry::from_index(&entree))
    }

    /// Ajoute récursivement un dossier, en préservant l'arborescence, les noms
    /// exacts et les dates (FR-014, FR-015).
    ///
    /// `progress` est appelé pour chaque fichier avant son traitement.
    ///
    /// L'opération est atomique dans son ensemble : un seul remplacement
    /// d'index, à la fin. Un échec en cours de route laisse le vault dans son
    /// état antérieur.
    ///
    /// # Errors
    ///
    /// Celles de [`UnlockedVault::add_file`], plus [`Error::UnsupportedEntry`]
    /// si `source` n'est pas un dossier ou si l'arborescence contient une
    /// entrée non ordinaire.
    pub fn add_dir(
        &mut self,
        source: &Path,
        dest: &VaultPath,
        mode: AddMode,
        on_conflict: OnConflict,
        progress: &mut dyn FnMut(&Path),
    ) -> Result<Vec<Entry>> {
        if !std::fs::symlink_metadata(source)?.is_dir() {
            return Err(Error::UnsupportedEntry);
        }

        let instantane = self.index.clone();
        let mut ecrits: Vec<BlobId> = Vec::new();
        let mut evincees: Vec<BlobId> = Vec::new();
        let mut ajoutees: Vec<IndexEntry> = Vec::new();
        let mut originaux: Vec<PathBuf> = Vec::new();

        let resultat = self.collect_dir(
            source,
            dest,
            on_conflict,
            progress,
            &mut ecrits,
            &mut evincees,
            &mut ajoutees,
            &mut originaux,
        );
        if let Err(erreur) = resultat {
            self.rollback(instantane, &ecrits);
            return Err(erreur);
        }

        for entree in &ajoutees {
            self.index.replace(entree.clone());
        }
        if let Err(erreur) = self.commit_index() {
            self.rollback(instantane, &ecrits);
            return Err(erreur);
        }

        self.unlink_blobs(&evincees);
        if mode == AddMode::Move {
            // Les fichiers d'abord, les dossiers ensuite : un dossier ne se
            // retire qu'une fois vidé. `originaux` est en ordre de parcours,
            // donc parents avant enfants — l'inverse convient ici.
            for original in &originaux {
                shred::shred(original)?;
            }
            remove_empty_dirs(source);
        }

        Ok(ajoutees.iter().map(Entry::from_index).collect())
    }

    /// Parcourt l'arborescence et écrit les blobs, sans toucher à l'index.
    #[allow(clippy::too_many_arguments)]
    fn collect_dir(
        &self,
        source: &Path,
        dest: &VaultPath,
        on_conflict: OnConflict,
        progress: &mut dyn FnMut(&Path),
        ecrits: &mut Vec<BlobId>,
        evincees: &mut Vec<BlobId>,
        ajoutees: &mut Vec<IndexEntry>,
        originaux: &mut Vec<PathBuf>,
    ) -> Result<()> {
        // Le dossier de destination est lui-même une entrée, sauf s'il s'agit
        // de la racine du vault, qui existe toujours. Sans cela, `depot`
        // n'apparaîtrait pas à la consultation alors que son contenu, si.
        if !dest.is_root() {
            self.plan_directory(dest.clone(), &std::fs::symlink_metadata(source)?, ajoutees);
        }

        // Le tri par nom rend l'ordre d'ajout reproductible : sans lui, l'ordre
        // dépendrait de celui du système de fichiers, et deux ajouts du même
        // dossier produiraient des index différents.
        for entree in walkdir::WalkDir::new(source).sort_by_file_name() {
            let entree = entree.map_err(std::io::Error::from)?;
            if entree.path() == source {
                continue;
            }

            let relatif = entree
                .path()
                .strip_prefix(source)
                .map_err(|_| Error::Corrupted)?;
            let mut chemin = dest.clone();
            for composant in VaultPath::from_os_path(relatif)?.components() {
                chemin.push(composant.to_vec())?;
            }

            let metadata = entree.metadata().map_err(std::io::Error::from)?;
            if metadata.is_dir() {
                self.plan_directory(chemin, &metadata, ajoutees);
                continue;
            }
            if !metadata.is_file() {
                // Lien symbolique, socket, périphérique : refus explicite
                // plutôt qu'un traitement à moitié (C-012).
                return Err(Error::UnsupportedEntry);
            }
            ensure_within_limit(metadata.len())?;

            progress(entree.path());

            let (chemin, evincee) =
                self.resolve_conflict_against(&chemin, on_conflict, ajoutees)?;
            let stockee = self.store_file(entree.path(), chemin, &metadata)?;
            ecrits.extend(stockee.blob_id);
            evincees.extend(evincee);
            ajoutees.push(stockee);
            originaux.push(entree.path().to_path_buf());
        }
        Ok(())
    }

    /// Prépare l'entrée d'un dossier, sauf s'il en existe déjà une.
    ///
    /// Un dossier n'a pas de contenu propre : rencontrer un dossier déjà connu
    /// n'est pas une collision, c'est la situation normale d'un second ajout
    /// dans la même arborescence.
    fn plan_directory(
        &self,
        chemin: VaultPath,
        metadata: &std::fs::Metadata,
        ajoutees: &mut Vec<IndexEntry>,
    ) {
        let connue = self
            .index
            .get(&chemin)
            .is_some_and(|entree| entree.kind == EntryKind::Directory)
            || ajoutees.iter().any(|entree| entree.path == chemin);
        if connue {
            return;
        }
        ajoutees.push(IndexEntry {
            path: chemin,
            kind: EntryKind::Directory,
            size: None,
            modified: modified_seconds(metadata),
            blob_id: None,
            blob_padded_size: None,
        });
    }

    /// Écrit le blob d'un fichier et construit son entrée d'index.
    ///
    /// N'écrit rien dans l'index : l'appelant décide du moment de
    /// l'engagement.
    fn store_file(
        &self,
        source: &Path,
        chemin: VaultPath,
        metadata: &std::fs::Metadata,
    ) -> Result<IndexEntry> {
        let blob_id = BlobId::generate();
        let cle = self.master_key.blob_key(blob_id.as_bytes());
        let nonce = stream::random_nonce();
        let aad = blob::blob_aad(&blob_id);

        let destination = blob_path(&self.path, &blob_id);
        let mut temporaire = atomic::temporary_for(&destination)?;
        temporaire.write_all(&nonce)?;

        let lu = std::fs::File::open(source)?;
        let sortie = temporaire.as_file_mut();
        let taille = stream::encrypt(&cle, &nonce, &aad, lu, sortie, MAX_FILE_SIZE)?;

        let ecrit = stream::STREAM_NONCE_LEN as u64 + stream::ciphertext_len(taille);
        let rempli = blob::blob_size(taille);
        temporaire.write_all(&blob::padding(ecrit, rempli))?;

        // VR-B5 : la date est posée sur le temporaire, donc avant que le blob
        // n'apparaisse dans `objects/`. Il n'y existe à aucun moment avec la
        // date que l'hôte lui aurait donnée.
        temporaire.as_file().set_modified(blob::NORMALIZED_MTIME)?;
        atomic::commit(temporaire, &destination)?;

        Ok(IndexEntry {
            path: chemin,
            kind: EntryKind::File,
            size: Some(taille),
            modified: modified_seconds(metadata),
            blob_id: Some(blob_id),
            blob_padded_size: Some(rempli),
        })
    }

    /// Résout une collision contre l'index seul.
    fn resolve_conflict(
        &self,
        dest: &VaultPath,
        on_conflict: OnConflict,
    ) -> Result<(VaultPath, Option<BlobId>)> {
        self.resolve_conflict_against(dest, on_conflict, &[])
    }

    /// Résout une collision contre l'index **et** les entrées déjà planifiées.
    ///
    /// Sans le second terme, un ajout récursif pourrait planifier deux entrées
    /// au même chemin et n'en garder qu'une.
    fn resolve_conflict_against(
        &self,
        dest: &VaultPath,
        on_conflict: OnConflict,
        planifiees: &[IndexEntry],
    ) -> Result<(VaultPath, Option<BlobId>)> {
        let occupe = |chemin: &VaultPath| {
            self.index.get(chemin).is_some() || planifiees.iter().any(|e| &e.path == chemin)
        };
        if !occupe(dest) {
            return Ok((dest.clone(), None));
        }

        match on_conflict {
            OnConflict::Fail => Err(Error::AlreadyExists),
            OnConflict::Replace => {
                let evincee = self.index.get(dest).and_then(|entree| entree.blob_id);
                Ok((dest.clone(), evincee))
            }
            OnConflict::Rename => {
                let base = dest.file_name().ok_or(Error::AlreadyExists)?.to_vec();
                let parent = dest.parent().unwrap_or_else(VaultPath::root);
                let (tronc, extension) = split_extension(&base);

                for numero in 2..=MAX_RENAME_ATTEMPTS {
                    let mut candidat = tronc.to_vec();
                    candidat.extend_from_slice(format!(" ({numero})").as_bytes());
                    candidat.extend_from_slice(extension);
                    let chemin = parent.join(candidat)?;
                    if !occupe(&chemin) {
                        return Ok((chemin, None));
                    }
                }
                Err(Error::AlreadyExists)
            }
        }
    }

    /// Réécrit l'index intégralement et le remplace atomiquement (VR-I5).
    /// Restaure l'index en mémoire et retire les blobs devenus inutiles.
    ///
    /// L'échec de la suppression d'un blob est ignoré : il ne resterait alors
    /// qu'un orphelin, c'est-à-dire un déchet, et masquer l'erreur d'origine
    /// derrière celle du nettoyage rendrait le diagnostic plus difficile.
    fn rollback(&mut self, instantane: Index, ecrits: &[BlobId]) {
        self.index = instantane;
        self.unlink_blobs(ecrits);
    }
}

/// Refuse un contenu au-delà de la limite du format (FR-022, FR-023).
///
/// C-009 exige que le refus arrive **avant** toute écriture : la garde ne prend
/// donc que la taille annoncée par les métadonnées, ce qui la rend vérifiable
/// sans fabriquer un fichier de quatre gigaoctets.
fn ensure_within_limit(taille: u64) -> Result<()> {
    if taille > MAX_FILE_SIZE {
        return Err(Error::FileTooLarge {
            limit: MAX_FILE_SIZE,
        });
    }
    Ok(())
}

/// Métadonnées d'un fichier ordinaire.
///
/// `symlink_metadata` et non `metadata` : un lien symbolique doit être refusé,
/// et non suivi jusqu'à sa cible. Suivre le lien ferait entrer dans le vault un
/// fichier que l'utilisateur n'a pas désigné.
fn regular_file_metadata(source: &Path) -> Result<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(source)?;
    if !metadata.is_file() {
        return Err(Error::UnsupportedEntry);
    }
    Ok(metadata)
}

/// Date de modification, en secondes Unix.
///
/// Une date indisponible vaut l'époque : la restitution d'une date est un
/// confort (FR-027), pas une garantie de sécurité, et refuser l'ajout d'un
/// fichier parce que son horodatage est illisible serait disproportionné.
fn modified_seconds(metadata: &std::fs::Metadata) -> i64 {
    let modified = metadata.modified().unwrap_or(UNIX_EPOCH);
    match modified.duration_since(UNIX_EPOCH) {
        Ok(depuis) => i64::try_from(depuis.as_secs()).unwrap_or(i64::MAX),
        Err(avant) => -i64::try_from(avant.duration().as_secs()).unwrap_or(i64::MAX),
    }
}

/// Sépare un nom en tronc et extension, en octets bruts.
///
/// Le point initial d'un fichier caché n'est pas un séparateur d'extension :
/// `.bashrc` a pour tronc `.bashrc` et non une extension `bashrc`.
fn split_extension(nom: &[u8]) -> (&[u8], &[u8]) {
    match nom.iter().rposition(|octet| *octet == b'.') {
        Some(position) if position > 0 => nom.split_at(position),
        _ => (nom, &[]),
    }
}

/// Retire les dossiers devenus vides après un déplacement, de bas en haut.
///
/// Un dossier encore peuplé — parce qu'il contenait une entrée que le vault a
/// refusée — est laissé en place plutôt que supprimé de force.
fn remove_empty_dirs(racine: &Path) {
    let mut dossiers: Vec<PathBuf> = walkdir::WalkDir::new(racine)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entree| entree.file_type().is_dir())
        .map(|entree| entree.path().to_path_buf())
        .collect();
    // Du plus profond au moins profond : un parent ne peut se vider qu'après
    // ses enfants.
    dossiers.sort_by_key(|chemin| std::cmp::Reverse(chemin.components().count()));

    for dossier in dossiers {
        drop(std::fs::remove_dir(&dossier));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Vault;
    use crate::crypto::kdf::KdfParams;
    use secrecy::SecretString;

    fn params() -> KdfParams {
        KdfParams::new(64, 1, 1).expect("paramètres valides")
    }

    fn passphrase() -> SecretString {
        SecretString::from("passphrase de test bien assez longue".to_owned())
    }

    /// Fonction de progression neutre, nommée plutôt qu'anonyme : une
    /// fermeture vide écrite dans un test où l'ajout échoue avant tout fichier
    /// resterait non exécutée, donc non couverte.
    fn sans_progression(_: &Path) {}

    fn chemin(nom: &str) -> VaultPath {
        VaultPath::from_components([nom.as_bytes().to_vec()]).expect("chemin valide")
    }

    struct Atelier {
        _racine: tempfile::TempDir,
        chemin: PathBuf,
        vault: UnlockedVault,
    }

    fn atelier() -> Atelier {
        let racine = tempfile::tempdir().expect("répertoire temporaire");
        let chemin = racine.path().to_path_buf();
        let vault =
            Vault::create(&chemin.join("coffre"), passphrase(), params()).expect("vault créable");
        Atelier {
            _racine: racine,
            chemin,
            vault,
        }
    }

    fn fichier(atelier: &Atelier, nom: &str, contenu: &[u8]) -> PathBuf {
        let chemin = atelier.chemin.join(nom);
        std::fs::write(&chemin, contenu).expect("écrivable");
        chemin
    }

    #[test]
    fn un_fichier_ajoute_apparait_dans_l_index() {
        let mut atelier = atelier();
        let source = fichier(&atelier, "note.txt", b"contenu");

        let entree = atelier
            .vault
            .add_file(
                &source,
                &chemin("note.txt"),
                AddMode::Copy,
                OnConflict::Fail,
            )
            .expect("ajoutable");

        assert_eq!(entree.kind, EntryKind::File);
        assert_eq!(entree.size, Some(7));
        assert_eq!(atelier.vault.list(None).len(), 1);
        assert!(source.exists(), "le mode copie conserve l'original");
    }

    /// VR-B5 : les blobs portent tous la même date, quel que soit le moment de
    /// leur ajout. Sans cela, trier `objects/` par date reconstituerait la
    /// chronologie du vault.
    #[test]
    fn les_blobs_ne_trahissent_pas_la_chronologie_des_ajouts() {
        let mut atelier = atelier();
        let objets = atelier.vault.path().join(crate::ops::OBJECTS_DIR);

        for nom in ["premier.txt", "second.txt", "troisieme.txt"] {
            let source = fichier(&atelier, nom, nom.as_bytes());
            atelier
                .vault
                .add_file(&source, &chemin(nom), AddMode::Copy, OnConflict::Fail)
                .expect("ajoutable");
        }

        let dates: Vec<std::time::SystemTime> = std::fs::read_dir(&objets)
            .expect("listable")
            .filter_map(std::result::Result::ok)
            .map(|entree| {
                entree
                    .metadata()
                    .expect("lisible")
                    .modified()
                    .expect("date disponible")
            })
            .collect();

        assert_eq!(dates.len(), 3);
        assert_eq!(dates, vec![blob::NORMALIZED_MTIME; 3], "{dates:?}");
    }

    /// FR-022, FR-023 : la garde de taille, vérifiée sur ses bornes exactes.
    #[test]
    fn la_limite_de_taille_est_celle_du_format() {
        assert!(ensure_within_limit(0).is_ok());
        assert!(ensure_within_limit(MAX_FILE_SIZE).is_ok());
        assert!(matches!(
            ensure_within_limit(MAX_FILE_SIZE + 1),
            Err(Error::FileTooLarge { limit }) if limit == MAX_FILE_SIZE
        ));
        assert!(matches!(
            ensure_within_limit(u64::MAX),
            Err(Error::FileTooLarge { .. })
        ));
    }

    /// C-009 : le refus arrive avant qu'un seul blob ne soit écrit.
    ///
    /// Le fichier est créé creux. Ce test est réservé à Linux : sur NTFS,
    /// `set_len` réserve réellement les quatre gigaoctets, et trois tests de ce
    /// genre exécutés en parallèle remplissaient le disque de l'exécuteur
    /// d'intégration continue. La garde elle-même est vérifiée sur toutes les
    /// plateformes par le test ci-dessus.
    #[cfg(target_os = "linux")]
    #[test]
    fn un_fichier_trop_volumineux_est_refuse_sans_rien_ecrire() {
        let mut atelier = atelier();
        let source = atelier.chemin.join("enorme.bin");
        std::fs::File::create(&source)
            .expect("créable")
            .set_len(MAX_FILE_SIZE + 1)
            .expect("taille réservable");

        assert!(matches!(
            atelier.vault.add_file(
                &source,
                &chemin("enorme.bin"),
                AddMode::Copy,
                OnConflict::Fail
            ),
            Err(Error::FileTooLarge { limit }) if limit == MAX_FILE_SIZE
        ));
        assert_eq!(
            std::fs::read_dir(atelier.vault.path().join("objects"))
                .expect("listable")
                .count(),
            0,
            "aucun blob ne doit avoir été écrit"
        );
    }

    /// FR-016, VR-I3 : les trois résolutions de collision.
    #[test]
    fn les_collisions_se_resolvent_selon_l_instruction() {
        let mut atelier = atelier();
        let premier = fichier(&atelier, "a.txt", b"premier");
        let second = fichier(&atelier, "b.txt", b"second");

        atelier
            .vault
            .add_file(
                &premier,
                &chemin("doc.txt"),
                AddMode::Copy,
                OnConflict::Fail,
            )
            .expect("ajoutable");

        assert!(matches!(
            atelier
                .vault
                .add_file(&second, &chemin("doc.txt"), AddMode::Copy, OnConflict::Fail),
            Err(Error::AlreadyExists)
        ));

        let renommee = atelier
            .vault
            .add_file(
                &second,
                &chemin("doc.txt"),
                AddMode::Copy,
                OnConflict::Rename,
            )
            .expect("ajoutable");
        assert_eq!(renommee.path, chemin("doc (2).txt"));

        let remplacante = atelier
            .vault
            .add_file(
                &second,
                &chemin("doc.txt"),
                AddMode::Copy,
                OnConflict::Replace,
            )
            .expect("ajoutable");
        assert_eq!(remplacante.size, Some(6));
        assert_eq!(atelier.vault.list(None).len(), 2);

        // Le blob évincé a bien été délié : deux entrées, deux blobs.
        assert_eq!(
            std::fs::read_dir(atelier.vault.path().join("objects"))
                .expect("listable")
                .count(),
            2
        );
    }

    #[test]
    fn le_renommage_gere_les_noms_sans_extension_et_les_fichiers_caches() {
        assert_eq!(split_extension(b"doc.txt"), (&b"doc"[..], &b".txt"[..]));
        assert_eq!(
            split_extension(b"sans-extension"),
            (&b"sans-extension"[..], &b""[..])
        );
        assert_eq!(split_extension(b".bashrc"), (&b".bashrc"[..], &b""[..]));
        assert_eq!(split_extension(b"a.b.c"), (&b"a.b"[..], &b".c"[..]));
        assert_eq!(split_extension(b""), (&b""[..], &b""[..]));
    }

    /// La borne de renommage existe pour qu'aucune boucle ne parte à l'infini.
    /// Le test la pousse jusqu'au bout en peuplant l'index directement, sans
    /// écrire mille blobs.
    #[test]
    fn le_renommage_abandonne_apres_mille_tentatives() {
        let mut atelier = atelier();
        for numero in 0..=MAX_RENAME_ATTEMPTS {
            let nom = if numero == 0 {
                "doc.txt".to_owned()
            } else {
                format!("doc ({}).txt", numero + 1)
            };
            atelier.vault.index.replace(IndexEntry {
                path: chemin(&nom),
                kind: EntryKind::Directory,
                size: None,
                modified: 0,
                blob_id: None,
                blob_padded_size: None,
            });
        }

        let source = fichier(&atelier, "source.txt", b"contenu");
        assert!(matches!(
            atelier.vault.add_file(
                &source,
                &chemin("doc.txt"),
                AddMode::Copy,
                OnConflict::Rename
            ),
            Err(Error::AlreadyExists)
        ));
    }

    /// Une collision à la racine ne peut pas être renommée : la racine n'a pas
    /// de nom.
    #[test]
    fn une_collision_a_la_racine_ne_se_renomme_pas() {
        let mut atelier = atelier();
        atelier.vault.index.replace(IndexEntry {
            path: VaultPath::root(),
            kind: EntryKind::Directory,
            size: None,
            modified: 0,
            blob_id: None,
            blob_padded_size: None,
        });

        let source = fichier(&atelier, "source.txt", b"contenu");
        assert!(matches!(
            atelier.vault.add_file(
                &source,
                &VaultPath::root(),
                AddMode::Copy,
                OnConflict::Rename
            ),
            Err(Error::AlreadyExists)
        ));
    }

    #[test]
    fn une_entree_non_ordinaire_est_refusee() {
        let mut atelier = atelier();
        let dossier = atelier.chemin.join("un-dossier");
        std::fs::create_dir(&dossier).expect("créable");

        assert!(matches!(
            atelier
                .vault
                .add_file(&dossier, &chemin("x"), AddMode::Copy, OnConflict::Fail),
            Err(Error::UnsupportedEntry)
        ));

        let source = fichier(&atelier, "ordinaire.txt", b"contenu");
        assert!(matches!(
            atelier.vault.add_dir(
                &source,
                &VaultPath::root(),
                AddMode::Copy,
                OnConflict::Fail,
                &mut sans_progression
            ),
            Err(Error::UnsupportedEntry)
        ));
    }

    #[test]
    fn un_ajout_recursif_preserve_l_arborescence() {
        let mut atelier = atelier();
        let source = atelier.chemin.join("arbre");
        std::fs::create_dir_all(source.join("a/b")).expect("créable");
        std::fs::write(source.join("racine.txt"), b"racine").expect("écrivable");
        std::fs::write(source.join("a/b/feuille.txt"), b"feuille").expect("écrivable");

        let mut vus = Vec::new();
        let ajoutees = atelier
            .vault
            .add_dir(
                &source,
                &chemin("depot"),
                AddMode::Copy,
                OnConflict::Fail,
                &mut |chemin| vus.push(chemin.to_path_buf()),
            )
            .expect("ajoutable");

        assert_eq!(vus.len(), 2, "un appel de progression par fichier");
        // `depot`, `depot/a`, `depot/a/b`, et les deux fichiers.
        assert_eq!(ajoutees.len(), 5, "{ajoutees:?}");
        assert!(atelier.vault.stat(&chemin("depot")).is_ok());
        assert!(
            atelier
                .vault
                .stat(&chemin("depot").join(b"a".to_vec()).expect("valide"))
                .is_ok()
        );
    }

    /// Un second ajout du même dossier ne considère pas les dossiers déjà
    /// connus comme des collisions.
    #[test]
    fn un_dossier_deja_connu_n_est_pas_une_collision() {
        let mut atelier = atelier();
        let source = atelier.chemin.join("arbre");
        std::fs::create_dir_all(source.join("commun")).expect("créable");
        std::fs::write(source.join("commun/premier.txt"), b"premier").expect("écrivable");

        atelier
            .vault
            .add_dir(
                &source,
                &VaultPath::root(),
                AddMode::Copy,
                OnConflict::Fail,
                &mut sans_progression,
            )
            .expect("ajoutable");

        std::fs::remove_file(source.join("commun/premier.txt")).expect("supprimable");
        std::fs::write(source.join("commun/second.txt"), b"second").expect("écrivable");

        atelier
            .vault
            .add_dir(
                &source,
                &VaultPath::root(),
                AddMode::Copy,
                OnConflict::Fail,
                &mut sans_progression,
            )
            .expect("le dossier commun ne doit pas être une collision");

        assert_eq!(atelier.vault.list(None).len(), 3);
    }

    /// FR-018 : en mode déplacement, l'arborescence source disparaît une fois
    /// le vault engagé.
    #[test]
    fn un_ajout_recursif_en_deplacement_vide_la_source() {
        let mut atelier = atelier();
        let source = atelier.chemin.join("arbre");
        std::fs::create_dir_all(source.join("a")).expect("créable");
        std::fs::write(source.join("a/feuille.txt"), b"feuille").expect("écrivable");

        atelier
            .vault
            .add_dir(
                &source,
                &VaultPath::root(),
                AddMode::Move,
                OnConflict::Fail,
                &mut sans_progression,
            )
            .expect("ajoutable");

        assert!(!source.exists(), "la source doit avoir disparu");
    }

    /// Une source qui n'existe pas remonte une erreur d'entrée-sortie, sans
    /// toucher au vault.
    #[test]
    fn une_source_absente_est_signalee() {
        let mut atelier = atelier();
        let absente = atelier.chemin.join("jamais-creee");

        assert!(matches!(
            atelier
                .vault
                .add_file(&absente, &chemin("x"), AddMode::Copy, OnConflict::Fail),
            Err(Error::Io(_))
        ));
        assert!(matches!(
            atelier.vault.add_dir(
                &absente,
                &VaultPath::root(),
                AddMode::Copy,
                OnConflict::Fail,
                &mut sans_progression
            ),
            Err(Error::Io(_))
        ));
        assert!(atelier.vault.list(None).is_empty());
    }

    /// FR-018, C-010 : en mode déplacement, l'original disparaît une fois le
    /// vault engagé, et pas avant.
    #[test]
    fn un_fichier_deplace_disparait_de_la_source() {
        let mut atelier = atelier();
        let source = fichier(&atelier, "a-deplacer.txt", b"contenu confie");

        atelier
            .vault
            .add_file(
                &source,
                &chemin("a-deplacer.txt"),
                AddMode::Move,
                OnConflict::Fail,
            )
            .expect("ajoutable");

        assert!(!source.exists(), "l'original doit avoir été retiré");
        assert_eq!(atelier.vault.list(None).len(), 1);
    }

    /// C-013 : l'échec du remplacement de l'index annule l'ajout d'un fichier
    /// isolé — index restauré, blob retiré.
    #[cfg(unix)]
    #[test]
    fn un_echec_de_remplacement_de_l_index_annule_l_ajout_d_un_fichier() {
        use std::os::unix::fs::PermissionsExt;

        let mut atelier = atelier();
        let source = fichier(&atelier, "nouveau.txt", b"contenu");
        let coffre = atelier.vault.path().to_path_buf();

        let mut permissions = std::fs::metadata(&coffre).expect("lisible").permissions();
        permissions.set_mode(0o500);
        std::fs::set_permissions(&coffre, permissions).expect("modifiable");

        let echec = atelier.vault.add_file(
            &source,
            &chemin("nouveau.txt"),
            AddMode::Move,
            OnConflict::Fail,
        );

        let mut permissions = std::fs::metadata(&coffre).expect("lisible").permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&coffre, permissions).expect("modifiable");

        assert!(matches!(echec, Err(Error::Io(_))), "obtenu : {echec:?}");
        assert!(atelier.vault.list(None).is_empty());
        assert!(source.exists(), "SC-011 : l'original survit à l'échec");
        assert_eq!(
            std::fs::read_dir(coffre.join("objects"))
                .expect("listable")
                .count(),
            0,
            "le blob écrit doit avoir été retiré"
        );
    }

    /// C-013 : un refus en cours de parcours restaure l'index et retire les
    /// blobs déjà écrits. Le lien symbolique arrive après un fichier ordinaire
    /// dans l'ordre alphabétique, donc un blob a bien été écrit avant le refus.
    #[cfg(unix)]
    #[test]
    fn un_refus_en_cours_de_parcours_annule_tout() {
        let mut atelier = atelier();
        let source = atelier.chemin.join("arbre");
        std::fs::create_dir(&source).expect("créable");
        std::fs::write(source.join("a-ordinaire.txt"), b"contenu").expect("écrivable");
        std::os::unix::fs::symlink(source.join("a-ordinaire.txt"), source.join("z-lien"))
            .expect("lien créable");

        assert!(matches!(
            atelier.vault.add_dir(
                &source,
                &VaultPath::root(),
                AddMode::Copy,
                OnConflict::Fail,
                &mut sans_progression,
            ),
            Err(Error::UnsupportedEntry)
        ));

        assert!(
            atelier.vault.list(None).is_empty(),
            "l'index doit être restauré"
        );
        assert_eq!(
            std::fs::read_dir(atelier.vault.path().join("objects"))
                .expect("listable")
                .count(),
            0,
            "les blobs déjà écrits doivent avoir été retirés"
        );
        assert!(
            source.join("a-ordinaire.txt").exists(),
            "aucun original ne doit avoir été touché"
        );
    }

    /// C-013 : l'échec du remplacement de l'index annule l'ajout récursif tout
    /// entier. Le retrait du droit d'écriture n'a de sens que sur un système à
    /// permissions POSIX.
    #[cfg(unix)]
    #[test]
    fn un_echec_de_remplacement_de_l_index_annule_l_ajout_recursif() {
        use std::os::unix::fs::PermissionsExt;

        let mut atelier = atelier();
        let source = atelier.chemin.join("arbre");
        std::fs::create_dir(&source).expect("créable");
        std::fs::write(source.join("fichier.txt"), b"contenu").expect("écrivable");

        let coffre = atelier.vault.path().to_path_buf();
        let mut permissions = std::fs::metadata(&coffre).expect("lisible").permissions();
        permissions.set_mode(0o500);
        std::fs::set_permissions(&coffre, permissions).expect("modifiable");

        let echec = atelier.vault.add_dir(
            &source,
            &VaultPath::root(),
            AddMode::Copy,
            OnConflict::Fail,
            &mut sans_progression,
        );

        let mut permissions = std::fs::metadata(&coffre).expect("lisible").permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&coffre, permissions).expect("modifiable");

        assert!(matches!(echec, Err(Error::Io(_))), "obtenu : {echec:?}");
        assert!(atelier.vault.list(None).is_empty());
    }

    /// FR-027 : une date antérieure à 1970 est représentable et conservée.
    #[test]
    fn une_date_anterieure_a_l_epoque_est_conservee() {
        let mut atelier = atelier();
        let source = fichier(&atelier, "ancien.txt", b"vieux contenu");
        let avant_epoque = UNIX_EPOCH - std::time::Duration::from_hours(24);
        std::fs::File::options()
            .write(true)
            .open(&source)
            .expect("ouvrable")
            .set_modified(avant_epoque)
            .expect("date modifiable");

        let entree = atelier
            .vault
            .add_file(
                &source,
                &chemin("ancien.txt"),
                AddMode::Copy,
                OnConflict::Fail,
            )
            .expect("ajoutable");
        assert_eq!(entree.modified, avant_epoque);
    }
}
