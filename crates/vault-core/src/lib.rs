//! `vault-core` — format et cryptographie du coffre-fort.
//!
//! Cette bibliothèque porte l'intégralité des garanties de sécurité. La ligne
//! de commande n'en est qu'un habillage : les tests du principe VI attaquent
//! directement ce crate (D-013).
//!
//! # Ce que le système de types garantit
//!
//! **C-007 — un [`Vault`] verrouillé n'expose aucune méthode de lecture.** Ce
//! n'est pas une vérification à l'exécution qu'un chemin de code pourrait
//! contourner : les méthodes de consultation et de modification n'existent que
//! sur [`UnlockedVault`], qu'on n'obtient qu'en passant par la passphrase.
//! FR-011 est donc inviolable par construction.
//!
//! **C-006 — les secrets sont effacés à la libération**, y compris lorsqu'elle
//! résulte d'une erreur ou d'un abandon par panique : c'est le déroulement de
//! pile qui déclenche le [`Drop`], et non un chemin de code nominal qu'une
//! erreur pourrait court-circuiter.
//!
//! # État d'avancement
//!
//! Phase 2 livrée : format, cryptographie et couche système. Les opérations —
//! création, ajout, consultation, extraction, suppression — arrivent avec la
//! phase 3.

mod crypto;
mod error;
mod format;
mod fs;
mod ops;

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use secrecy::SecretString;

pub use crate::crypto::kdf::KdfParams;
pub use crate::error::{Error, Result};
pub use crate::format::blob::{BLOB_ID_LEN, BlobId, MAX_FILE_SIZE};
pub use crate::format::index::EntryKind;
pub use crate::format::path::VaultPath;
pub use crate::format::version::FORMAT_VERSION;
pub use crate::fs::shred::{ShredCapability, shred_capability};

use crate::crypto::keys::MasterKey;
use crate::format::header::Header;
use crate::format::index::{Index, IndexEntry};
use crate::fs::lock::VaultLock;

/// Longueur minimale d'une passphrase, en caractères (FR-005, C-001).
pub const MIN_PASSPHRASE_LEN: usize = 12;

/// Mode d'ajout d'un fichier au vault (FR-018).
///
/// `Move` est le défaut côté ligne de commande : déposer un fichier dans un
/// coffre-fort tout en en laissant l'original en clair à côté est rarement ce
/// que l'utilisateur veut.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddMode {
    /// L'original est conservé.
    Copy,
    /// L'original est supprimé, mais seulement après écriture et vérification
    /// complètes du blob (C-010, FR-019).
    Move,
}

/// Résolution d'une collision de noms (FR-016).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnConflict {
    /// Échouer sans rien écrire. C'est le défaut : on n'écrase jamais sans
    /// instruction explicite (C-018).
    Fail,
    /// Remplacer l'entrée existante.
    Replace,
    /// Conserver les deux, en renommant la nouvelle.
    Rename,
}

/// Une entrée du vault, telle qu'elle est présentée à l'appelant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Chemin dans le vault.
    pub path: VaultPath,
    /// Fichier ou dossier.
    pub kind: EntryKind,
    /// Taille **réelle** du contenu. Absente pour un dossier (VR-I2).
    pub size: Option<u64>,
    /// Date de modification d'origine.
    pub modified: SystemTime,
}

impl Entry {
    fn from_index(entry: &IndexEntry) -> Self {
        Self {
            path: entry.path.clone(),
            kind: entry.kind,
            size: entry.size,
            modified: unix_seconds_to_time(entry.modified),
        }
    }
}

/// Convertit des secondes Unix en [`SystemTime`], y compris négatives.
pub(crate) fn unix_seconds_to_time(seconds: i64) -> SystemTime {
    if seconds >= 0 {
        UNIX_EPOCH + Duration::from_secs(seconds.unsigned_abs())
    } else {
        UNIX_EPOCH - Duration::from_secs(seconds.unsigned_abs())
    }
}

/// Un vault verrouillé, identifié par son emplacement.
///
/// Ne détient **aucun** secret : ni clé, ni index déchiffré, ni passphrase.
/// C-007 : aucune méthode de lecture du contenu n'existe sur ce type.
#[derive(Debug)]
pub struct Vault {
    path: PathBuf,
    header: Header,
}

impl Vault {
    /// Construit un vault verrouillé depuis son en-tête déjà lu.
    ///
    /// L'ouverture depuis le disque arrive avec la phase 3 : elle relève des
    /// opérations, qui ont aussi à charge le balayage des blobs orphelins
    /// (VR-I6).
    pub(crate) fn new(path: PathBuf, header: Header) -> Self {
        Self { path, header }
    }

    /// Emplacement du vault sur le disque.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Version du format de ce vault.
    #[must_use]
    pub fn format_version(&self) -> u32 {
        self.header.format_version()
    }

    /// Paramètres de dérivation de ce vault.
    ///
    /// Publiés parce qu'ils sont publics par conception (VR-H2) : les lire ne
    /// renseigne en rien sur le contenu, et l'appelant peut vouloir prévenir
    /// qu'un vault ancien mériterait des paramètres relevés.
    #[must_use]
    pub fn kdf_params(&self) -> KdfParams {
        self.header.kdf_params()
    }
}

/// Une session déverrouillée.
///
/// Détient la clé maîtresse, l'index déchiffré et le verrou exclusif. Efface
/// ses secrets à sa libération (C-006).
#[derive(Debug)]
pub struct UnlockedVault {
    path: PathBuf,
    header: Header,
    master_key: MasterKey,
    index: Index,
    // Le verrou n'est jamais relu : il est tenu pour la durée de la session
    // (VR-S4) et rendu par sa libération.
    _lock: VaultLock,
    idle_timeout: Option<Duration>,
}

impl UnlockedVault {
    pub(crate) fn new(
        path: PathBuf,
        header: Header,
        master_key: MasterKey,
        index: Index,
        lock: VaultLock,
    ) -> Self {
        Self {
            path,
            header,
            master_key,
            index,
            _lock: lock,
            idle_timeout: None,
        }
    }

    /// Emplacement du vault sur le disque.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Version du format de ce vault.
    #[must_use]
    pub fn format_version(&self) -> u32 {
        self.header.format_version()
    }

    /// Paramètres de dérivation de ce vault.
    #[must_use]
    pub fn kdf_params(&self) -> KdfParams {
        self.header.kdf_params()
    }

    /// Numéro de révision de l'index, incrémenté à chaque modification.
    #[must_use]
    pub fn index_version(&self) -> u64 {
        self.index.index_version()
    }

    /// Délai d'inactivité avant verrouillage automatique.
    ///
    /// **FR-010 est différé** (VR-S3) : la valeur est conservée mais ne
    /// déclenche rien. Sans session persistante, une session ne survit pas à la
    /// fin du processus et ne peut donc pas expirer. L'accesseur figure au
    /// contrat dès maintenant pour éviter une rupture d'interface le jour où
    /// un mode interactif existera (C-003 bis).
    #[must_use]
    pub fn idle_timeout(&self) -> Option<Duration> {
        self.idle_timeout
    }

    /// Fixe le délai d'inactivité. Voir [`UnlockedVault::idle_timeout`].
    pub fn set_idle_timeout(&mut self, timeout: Option<Duration>) {
        self.idle_timeout = timeout;
    }

    /// Verrouille la session : efface les secrets et libère le verrou.
    ///
    /// Consomme la session, ce qui rend le type incapable de représenter un
    /// vault déverrouillé dont les secrets auraient été effacés.
    pub fn lock(self) {
        drop(self);
    }
}

/// C-006, VR-S1, VR-S2 : le passage à l'état verrouillé efface les secrets,
/// **y compris lorsqu'il résulte d'une erreur ou d'une panique**.
///
/// La clé maîtresse s'efface d'elle-même — elle est enveloppée dans
/// `Zeroizing`. L'index, lui, contient les noms réels et l'arborescence : le
/// laisser au ramassage ordinaire de la mémoire laisserait ces octets en clair
/// dans le tas jusqu'à réutilisation.
impl Drop for UnlockedVault {
    fn drop(&mut self) {
        self.index.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;
    use crate::format::index::IndexEntry;

    fn params() -> KdfParams {
        KdfParams::new(64, 1, 1).expect("paramètres valides")
    }

    fn passphrase() -> SecretString {
        SecretString::from("une passphrase suffisamment longue".to_owned())
    }

    fn chemin(composants: &[&[u8]]) -> VaultPath {
        VaultPath::from_components(composants.iter().map(|c| c.to_vec())).expect("chemin valide")
    }

    fn index_peuple() -> Index {
        let mut index = Index::new();
        index.replace(IndexEntry {
            path: chemin(&[b"photos"]),
            kind: EntryKind::Directory,
            size: None,
            modified: 1_700_000_000,
            blob_id: None,
            blob_padded_size: None,
        });
        index.replace(IndexEntry {
            path: chemin(&[b"photos", b"plage.jpg"]),
            kind: EntryKind::File,
            size: Some(4242),
            modified: -1,
            blob_id: Some(BlobId::generate()),
            blob_padded_size: Some(4096),
        });
        index
    }

    /// Construit une session déverrouillée sur un répertoire jetable. Les
    /// opérations d'ouverture arrivent en phase 3 ; ce montage permet de
    /// vérifier dès maintenant les garanties de type et d'effacement.
    fn session(repertoire: &std::path::Path) -> UnlockedVault {
        let (header, master_key) = Header::create(&passphrase(), params()).expect("créable");
        let lock = VaultLock::acquire(repertoire).expect("verrouillable");
        UnlockedVault::new(
            repertoire.to_path_buf(),
            header,
            master_key,
            index_peuple(),
            lock,
        )
    }

    #[test]
    fn un_vault_verrouille_expose_ses_parametres_publics() {
        let (header, _) = Header::create(&passphrase(), params()).expect("créable");
        let vault = Vault::new(PathBuf::from("/tmp/mon-vault"), header);

        assert_eq!(vault.path(), std::path::Path::new("/tmp/mon-vault"));
        assert_eq!(vault.format_version(), FORMAT_VERSION);
        assert_eq!(vault.kdf_params(), params());
        assert!(format!("{vault:?}").contains("Vault"));
    }

    #[test]
    fn une_session_expose_le_contenu() {
        let repertoire = tempfile::tempdir().expect("répertoire temporaire");
        let session = session(repertoire.path());

        assert_eq!(session.path(), repertoire.path());
        assert_eq!(session.format_version(), FORMAT_VERSION);
        assert_eq!(session.kdf_params(), params());
        assert_eq!(session.index_version(), 2);

        assert_eq!(session.list(None).len(), 2);
        assert_eq!(session.list(Some(&chemin(&[b"photos"]))).len(), 2);
        assert!(session.list(Some(&chemin(&[b"absent"]))).is_empty());

        let entree = session
            .stat(&chemin(&[b"photos", b"plage.jpg"]))
            .expect("présente");
        assert_eq!(entree.kind, EntryKind::File);
        assert_eq!(entree.size, Some(4242));
        assert_eq!(entree.modified, UNIX_EPOCH - Duration::from_secs(1));
        assert!(format!("{entree:?}").contains("Entry"));

        let dossier = session.stat(&chemin(&[b"photos"])).expect("présent");
        assert_eq!(dossier.kind, EntryKind::Directory);
        assert_eq!(dossier.size, None);
        assert_eq!(
            dossier.modified,
            UNIX_EPOCH + Duration::from_secs(1_700_000_000)
        );

        assert!(matches!(
            session.stat(&chemin(&[b"absent"])),
            Err(Error::NotFound)
        ));
        assert!(format!("{session:?}").contains("UnlockedVault"));
    }

    /// C-003 bis : l'accesseur existe et conserve la valeur, sans rien
    /// déclencher — FR-010 est différé (VR-S3).
    #[test]
    fn le_delai_d_inactivite_est_conserve_sans_effet() {
        let repertoire = tempfile::tempdir().expect("répertoire temporaire");
        let mut session = session(repertoire.path());

        assert_eq!(session.idle_timeout(), None);
        session.set_idle_timeout(Some(Duration::from_mins(5)));
        assert_eq!(session.idle_timeout(), Some(Duration::from_mins(5)));

        // Aucun verrouillage ne survient : la session reste exploitable.
        assert_eq!(session.list(None).len(), 2);
    }

    /// VR-S4 : le verrou est tenu pour toute la session, et rendu au
    /// verrouillage.
    #[test]
    fn le_verrou_est_tenu_puis_rendu() {
        let repertoire = tempfile::tempdir().expect("répertoire temporaire");
        let session = session(repertoire.path());

        assert!(matches!(
            VaultLock::acquire(repertoire.path()),
            Err(Error::AlreadyInUse)
        ));

        session.lock();
        let _reprise = VaultLock::acquire(repertoire.path()).expect("reverrouillable");
    }

    /// C-006, VR-S2 : l'effacement a lieu même quand la libération résulte
    /// d'une panique. Le test la déclenche et vérifie que le verrou a bien été
    /// rendu — preuve observable que le `Drop` s'est exécuté pendant le
    /// déroulement de pile.
    #[test]
    fn les_secrets_sont_effaces_meme_en_cas_de_panique() {
        let repertoire = tempfile::tempdir().expect("répertoire temporaire");
        let chemin_repertoire = repertoire.path().to_path_buf();

        let abandon = std::panic::catch_unwind(move || {
            let _session = session(&chemin_repertoire);
            panic!("abandon en cours d'opération");
        });
        assert!(abandon.is_err());

        let _reprise = VaultLock::acquire(repertoire.path()).expect("le verrou a été rendu");
    }

    #[test]
    fn les_enumerations_du_contrat_existent() {
        assert_ne!(AddMode::Copy, AddMode::Move);
        assert_eq!(AddMode::Move, AddMode::Move);
        assert!(format!("{:?}", AddMode::Move).contains("Move"));

        assert_ne!(OnConflict::Fail, OnConflict::Replace);
        assert_ne!(OnConflict::Replace, OnConflict::Rename);
        assert!(format!("{:?}", OnConflict::Fail).contains("Fail"));

        assert_eq!(MIN_PASSPHRASE_LEN, 12);
        assert_eq!(BLOB_ID_LEN, 32);
        assert_eq!(MAX_FILE_SIZE, 4_000_000_000);
    }
}
