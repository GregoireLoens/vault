//! Import d'un conteneur vers un vault — T025 à T033.
//!
//! FR-011 à FR-018. La séquence est celle de D-208, et **l'ordre dans lequel
//! ses étapes s'enchaînent est la garantie elle-même** :
//!
//! ```text
//! 1. écrire            <dest>.vault-entrant-<aléa>/     header, index, objects/…
//! 2. fsync             des fichiers, puis du répertoire
//! 3. vérifier          sceau, longueurs, cohérence structurelle
//! 4. si remplacement   rename <dest> → <dest>.vault-remplace-<horodatage>
//! 5.                   rename <dest>.vault-entrant-<aléa> → <dest>
//! 6. fsync             du répertoire parent
//! ```
//!
//! Une interruption avant l'étape 5 laisse la destination **intacte** et un
//! répertoire d'attente identifiable ; une interruption après laisse le vault
//! complet. C'est exactement FR-015.
//!
//! **La fenêtre entre 4 et 5 est le seul instant où la destination n'existe
//! pas.** Elle sépare deux `rename` du même répertoire parent, soit quelques
//! microsecondes, et son issue reste conforme : rien d'ouvrable à la
//! destination, l'ancien vault intact sous son nom de remplacement.
//!
//! **FR-018 : l'import n'exige pas la passphrase.** Le conteneur est transposé
//! sans être ouvert. Ce qu'il vérifie — la complétude — s'établit sur le
//! **cadrage public** ; l'authenticité du contenu, elle, ne s'établit qu'au
//! déverrouillage, avec la passphrase, et [`UnlockedVault::verify_content`] la
//! rend disponible sur demande explicite.
//!
//! # Ce qu'un répertoire d'attente laissé sur place n'est pas
//!
//! **Ce n'est pas un vault** : il n'a pas été vérifié, et son nom dit qu'il est
//! en cours de réception. FR-035 est honoré par ce nom — le supprimer est sans
//! conséquence, et rien d'autre ne le désigne. Sur un chemin d'erreur *propre*,
//! il est retiré séance tenante : laisser quatre cents gigaoctets derrière soi
//! parce qu'un sceau a divergé serait une punition sans rapport avec la faute.
//! Il ne survit donc qu'à une interruption — le cas que D-208 décrit, et le
//! seul où il y a quelque chose à identifier.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::format::blob;
use crate::format::container::{ContainerReader, MemberKind};
use crate::format::index::EntryKind;
use crate::format::path::VaultPath;
use crate::fs::{atomic, space};
use crate::ops::{HEADER_FILE, INDEX_FILE, OBJECTS_DIR, blob_path};
use crate::{UnlockedVault, Vault};

/// Nombre maximal de noms de remplacement essayés dans la même seconde.
///
/// Cent, et non mille. Le suffixe numéraire n'existe que pour départager deux
/// restaurations tombées dans la **même seconde** ; or une restauration écrit
/// un vault entier, fsync compris. Cent en une seconde n'est pas un scénario
/// improbable, c'est un scénario impossible — et si la borne était malgré tout
/// atteinte, l'échec est explicite et la seconde suivante rouvre cent noms.
///
/// Mille rendait par ailleurs cette borne **inéprouvable** : saturer une
/// seconde demandait mille créations de fichiers, ce qui dépasse la seconde sur
/// NTFS. Le test visait alors une seconde libre et la borne n'était jamais
/// atteinte. Une garantie qu'on ne peut pas éprouver n'en est pas une.
const MAX_REPLACE_ATTEMPTS: u32 = 100;

/// Ce que l'import fait d'une destination déjà occupée par un vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportPolicy {
    /// Échouer sans rien écrire. C'est le défaut : on n'écrase jamais un
    /// coffre-fort sans instruction explicite (FR-013).
    Refuse,
    /// Remplacer, pour restaurer une sauvegarde. Le vault remplacé est
    /// **déplacé**, jamais supprimé (FR-013a, FR-013b).
    Replace,
}

/// Ce qu'un import a produit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportSummary {
    /// Nombre de blobs reçus.
    pub blob_count: u64,
    /// Volume annoncé par l'en-tête du conteneur, en octets.
    pub payload_bytes: u64,
    /// Où le vault remplacé a été déplacé, s'il y en avait un.
    ///
    /// FR-013b exige que vault annonce cet emplacement : c'est par cette valeur
    /// que l'appelant l'apprend.
    pub replaced: Option<PathBuf>,
}

impl Vault {
    /// Reconstitue un vault à `destination` depuis le conteneur lu dans
    /// `source`.
    ///
    /// # Errors
    ///
    /// - [`Error::Corrupted`] si le flux n'est pas un conteneur lisible, s'il
    ///   est tronqué, altéré, désordonné ou suivi d'octets ;
    /// - [`Error::UnsupportedFormatVersion`] si la version de conteneur ou celle
    ///   du vault transporté dépasse ce que cette version sait lire, **avant**
    ///   toute écriture (FR-016) ;
    /// - [`Error::DestinationOccupied`] si un vault occupe la destination et que
    ///   `policy` vaut [`ImportPolicy::Refuse`] (FR-013) ;
    /// - [`Error::AlreadyExists`] si la destination existe **sans** être un
    ///   vault — un fichier ordinaire, un répertoire quelconque. Le refus est
    ///   alors sans appel, `policy` n'y change rien (FR-013c) ;
    /// - [`Error::InsufficientSpace`] si la place manque, **avant** la première
    ///   écriture (XFR-019) ;
    /// - [`Error::Io`] si le répertoire parent n'existe pas, ou si l'écriture
    ///   échoue.
    pub fn import(
        source: &mut dyn Read,
        destination: &Path,
        policy: ImportPolicy,
    ) -> Result<ImportSummary> {
        // L'en-tête est lu et validé avant tout : une version inconnue est
        // refusée sans qu'un octet n'ait atteint la destination (FR-016).
        let mut reader = ContainerReader::open(source)?;
        let payload_bytes = reader.header().payload_bytes;

        let occupe_par_vault = verifier_destination(destination, policy)?;

        let parent = atomic::parent_of(destination);
        if !parent.is_dir() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "le répertoire parent de la destination n'existe pas",
            )));
        }
        // XFR-019 : contrôlé contre le volume annoncé, avant la première
        // écriture. Sans cela, une réception sur un disque trop petit
        // s'arrêterait à mi-course.
        space::ensure(parent, payload_bytes)?;

        // Le répertoire d'attente est voisin de la destination, donc sur le
        // même système de fichiers : c'est la condition pour que le `rename`
        // final soit atomique. Sa libération le supprime — ce qui nettoie tous
        // les chemins d'erreur de cette fonction sans un seul appel explicite.
        let attente = tempfile::Builder::new()
            .prefix(&format!("{}.vault-entrant-", nom_de(destination)))
            .tempdir_in(parent)?;

        let blob_count = recevoir(&mut reader, attente.path())?;
        // Le sceau et tous les invariants sont contrôlés **avant** la bascule.
        reader.finish()?;
        atomic::sync_dir(attente.path())?;

        let attente = attente.keep();
        let replaced = if occupe_par_vault {
            let ecarte = nom_de_remplacement(destination)?;
            // À partir d'ici, l'échec ne peut plus laisser la destination dans
            // un état incohérent : ou l'ancien vault est encore en place, ou il
            // est sous son nom de remplacement, intact dans les deux cas.
            std::fs::rename(destination, &ecarte)?;
            Some(ecarte)
        } else {
            None
        };

        std::fs::rename(&attente, destination)?;
        atomic::sync_dir(parent)?;

        Ok(ImportSummary {
            blob_count,
            payload_bytes,
            replaced,
        })
    }
}

impl Vault {
    /// Dit si `destination` peut recevoir un vault, **sans rien écrire**.
    ///
    /// C'est le verdict que rend le mode de sondage, et c'est tout ce qu'il
    /// rend : un oui ou un non, sans un octet sur la sortie standard (D-205,
    /// FR-029a).
    ///
    /// # Errors
    ///
    /// Celles de [`verifier_destination`] : [`Error::AlreadyExists`] si la
    /// destination existe sans être un vault, [`Error::DestinationOccupied`] si
    /// un vault l'occupe et que le remplacement n'a pas été demandé.
    pub fn check_destination(destination: &Path, policy: ImportPolicy) -> Result<()> {
        verifier_destination(destination, policy).map(drop)
    }
}

/// Décide si une destination peut recevoir un vault, et dit si elle en porte
/// déjà un.
///
/// Vit à part parce qu'un **rapatriement** doit pouvoir prononcer ce refus
/// **avant** d'ouvrir la moindre session ssh : la destination y est locale, et
/// rien n'oblige à traverser le réseau pour découvrir qu'elle est occupée
/// (FR-028).
///
/// # Errors
///
/// - [`Error::AlreadyExists`] si la destination existe **sans** être un vault.
///   Le refus est sans appel : `policy` n'y change rien, car le remplacement ne
///   vaut que pour un vault reconnu comme tel (FR-013c) ;
/// - [`Error::DestinationOccupied`] si un vault l'occupe et que `policy` vaut
///   [`ImportPolicy::Refuse`] (FR-013).
pub(crate) fn verifier_destination(destination: &Path, policy: ImportPolicy) -> Result<bool> {
    let occupe_par_vault = destination.join(HEADER_FILE).is_file();
    if destination.exists() && !occupe_par_vault {
        return Err(Error::AlreadyExists);
    }
    if occupe_par_vault && policy == ImportPolicy::Refuse {
        return Err(Error::DestinationOccupied);
    }
    Ok(occupe_par_vault)
}

/// Écrit les membres du conteneur dans le répertoire d'attente, et rend le
/// nombre de blobs reçus.
fn recevoir<R: Read>(reader: &mut ContainerReader<R>, attente: &Path) -> Result<u64> {
    std::fs::create_dir(attente.join(OBJECTS_DIR))?;

    let mut blob_count = 0;
    while let Some(frame) = reader.next_frame()? {
        let cible = match frame.kind {
            MemberKind::Header => attente.join(HEADER_FILE),
            MemberKind::Index => attente.join(INDEX_FILE),
            MemberKind::Blob => {
                blob_count += 1;
                // `next_frame` a déjà établi qu'un membre `blob` porte un
                // identifiant ; le redire ici évite une panique si cet
                // invariant venait à bouger.
                let blob_id = frame.id.ok_or(Error::Corrupted)?;
                attente.join(OBJECTS_DIR).join(blob_id.to_hex())
            }
        };

        let mut fichier = std::fs::File::create(&cible)?;
        reader.copy_payload(&frame, &mut fichier)?;
        fichier.sync_all()?;

        if frame.kind == MemberKind::Blob {
            // `docs/format.md` §6.4 : la date de modification d'un blob est
            // ramenée à l'époque Unix. Elle ne dit rien du contenu, et la
            // laisser suivre l'instant de réception en ferait une métadonnée
            // sur l'utilisateur.
            //
            // **L'ordre compte, et il n'est pas indifférent à la plateforme.**
            // NTFS met à jour la date de dernière écriture au moment où les
            // données atteignent le disque : la poser avant le `sync_all` la
            // ferait écraser par l'instant de la synchronisation. Elle est donc
            // posée **après**, en dernier geste sur ce fichier.
            fichier.set_modified(std::time::UNIX_EPOCH)?;
        }
    }
    Ok(blob_count)
}

/// Nom de fichier de la destination, pour préfixer les répertoires voisins.
fn nom_de(destination: &Path) -> String {
    destination
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("vault"))
        .to_string_lossy()
        .into_owned()
}

/// Trouve un nom libre pour le vault que le remplacement écarte.
///
/// L'horodatage n'est pas décoratif : sans lui, une seconde restauration
/// écraserait la sauvegarde de la première, et le seul filet de sécurité de
/// l'opération disparaîtrait au moment où l'on s'en sert le plus. Le suffixe
/// numéraire couvre le cas où deux restaurations tombent dans la même seconde.
fn nom_de_remplacement(destination: &Path) -> Result<PathBuf> {
    let secondes = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let base = format!("{}.vault-remplace-{secondes}", nom_de(destination));
    let parent = atomic::parent_of(destination);

    let candidat = parent.join(&base);
    if !candidat.exists() {
        return Ok(candidat);
    }
    for rang in 1..MAX_REPLACE_ATTEMPTS {
        let candidat = parent.join(format!("{base}-{rang}"));
        if !candidat.exists() {
            return Ok(candidat);
        }
    }
    Err(Error::AlreadyExists)
}

impl UnlockedVault {
    /// Contrôle les tags AEAD de **tout** le contenu, et rend le nombre de
    /// fichiers vérifiés.
    ///
    /// XFR-010 : c'est la vérification que l'import ne fait pas, et ne peut pas
    /// faire — elle exige la passphrase, dont il ne dispose pas (FR-018). Le
    /// sceau du conteneur établit la **complétude** de ce qui est arrivé ;
    /// celle-ci établit l'**authenticité** du contenu. Les deux portées sont
    /// distinctes, et il faut les deux.
    ///
    /// Le clair n'atteint jamais le disque : chaque morceau est déchiffré vers
    /// un puits.
    ///
    /// # Errors
    ///
    /// - [`Error::Authentication`] si un morceau ne s'authentifie pas ;
    /// - [`Error::Corrupted`] si un blob est absent, tronqué, ou si une entrée
    ///   de l'index viole ses invariants.
    pub fn verify_content(&self) -> Result<u64> {
        let mut verifies = 0;
        for entree in self.index.list(&VaultPath::root()) {
            if entree.kind != EntryKind::File {
                continue;
            }
            let (Some(blob_id), Some(taille)) = (entree.blob_id, entree.size) else {
                return Err(Error::Corrupted);
            };

            let cle = self.master_key.blob_key(blob_id.as_bytes());
            let aad = blob::blob_aad(&blob_id);
            let mut source = std::fs::File::open(blob_path(&self.path, &blob_id))
                .map_err(|_| Error::Corrupted)?;
            let mut nonce = [0u8; crate::crypto::stream::STREAM_NONCE_LEN];
            source
                .read_exact(&mut nonce)
                .map_err(|_| Error::Corrupted)?;

            crate::crypto::stream::decrypt(
                &cle,
                &nonce,
                &aad,
                source,
                &mut std::io::sink(),
                taille,
            )?;
            verifies += 1;
        }
        Ok(verifies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::KdfParams;
    use crate::ops::export::ExportEnvelope;
    use crate::{AddMode, OnConflict, SecretString};

    const PASSPHRASE: &str = "une passphrase bien assez longue";

    fn params() -> KdfParams {
        KdfParams::new(64, 1, 1).expect("paramètres valides")
    }

    fn passphrase() -> SecretString {
        SecretString::from(PASSPHRASE.to_owned())
    }

    /// Un vault peuplé, refermé, et le conteneur qu'il produit.
    fn coffre_et_conteneur(atelier: &Path) -> (PathBuf, Vec<u8>) {
        let coffre = atelier.join("coffre");
        let mut vault = Vault::create(&coffre, passphrase(), params()).expect("créable");
        for (nom, contenu) in [("note.txt", &b"une note"[..]), ("gros.bin", &[0x2a; 9000])] {
            let source = atelier.join(nom);
            std::fs::write(&source, contenu).expect("écrivable");
            vault
                .add_file(
                    &source,
                    &VaultPath::from_components([nom.as_bytes().to_vec()]).expect("valide"),
                    AddMode::Copy,
                    OnConflict::Fail,
                )
                .expect("ajoutable");
        }
        vault.lock();

        let mut conteneur = Vec::new();
        Vault::export(&coffre, ExportEnvelope::Source, &mut conteneur).expect("exportable");
        (coffre, conteneur)
    }

    fn importer(
        conteneur: &[u8],
        destination: &Path,
        policy: ImportPolicy,
    ) -> Result<ImportSummary> {
        Vault::import(&mut &conteneur[..], destination, policy)
    }

    #[test]
    fn un_import_reconstitue_un_vault_ouvrable() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let (_, conteneur) = coffre_et_conteneur(atelier.path());
        let restaure = atelier.path().join("restaure");

        let resume = importer(&conteneur, &restaure, ImportPolicy::Refuse).expect("importable");
        assert_eq!(resume.blob_count, 2);
        assert_eq!(resume.replaced, None);
        assert!(resume.payload_bytes > 0);

        // FR-012 : le vault reconstitué s'ouvre avec la passphrase du vault
        // source, et il est utilisable par les commandes existantes.
        let session = Vault::open(&restaure)
            .expect("ouvrable")
            .unlock(passphrase())
            .expect("déverrouillable");
        assert_eq!(session.list(None).len(), 2);
        assert_eq!(session.verify_content().expect("vérifiable"), 2);
    }

    /// FR-013, XFR-012 : une destination occupée par un vault est refusée sans
    /// rien écrire, et l'erreur est **distincte** de celle d'une destination
    /// qui n'est pas un vault.
    #[test]
    fn une_destination_occupee_est_refusee() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let (coffre, conteneur) = coffre_et_conteneur(atelier.path());
        let avant = std::fs::read(coffre.join(HEADER_FILE)).expect("lisible");

        assert!(matches!(
            importer(&conteneur, &coffre, ImportPolicy::Refuse),
            Err(Error::DestinationOccupied)
        ));
        assert_eq!(
            std::fs::read(coffre.join(HEADER_FILE)).expect("lisible"),
            avant
        );
        assert_eq!(residus(atelier.path()), Vec::<String>::new());
    }

    /// FR-013c, XFR-014 : une destination qui existe sans être un vault est
    /// refusée, **avec ou sans** demande de remplacement.
    #[test]
    fn une_destination_qui_n_est_pas_un_vault_est_refusee_sans_appel() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let (_, conteneur) = coffre_et_conteneur(atelier.path());

        let fichier = atelier.path().join("fichier-ordinaire");
        std::fs::write(&fichier, b"contenu etranger").expect("écrivable");
        let repertoire = atelier.path().join("repertoire-quelconque");
        std::fs::create_dir(&repertoire).expect("créable");

        let mut verdicts = Vec::new();
        for cible in [&fichier, &repertoire] {
            for policy in [ImportPolicy::Refuse, ImportPolicy::Replace] {
                verdicts.push(matches!(
                    importer(&conteneur, cible, policy),
                    Err(Error::AlreadyExists)
                ));
            }
        }
        assert_eq!(
            verdicts,
            vec![true; 4],
            "fichier et répertoire, sans et avec --replace"
        );
        assert_eq!(
            std::fs::read(&fichier).expect("lisible"),
            b"contenu etranger"
        );
    }

    /// FR-013a, FR-013b, XFR-013 : le remplacement déplace l'ancien vault sous
    /// un nom qui dit ce qu'il est, **ne le supprime jamais**, et annonce où il
    /// se trouve. L'ancien reste un vault ouvrable.
    #[test]
    fn un_remplacement_deplace_l_ancien_vault_sans_le_detruire() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let (coffre, conteneur) = coffre_et_conteneur(atelier.path());

        // L'ancien vault reçoit une entrée de plus, pour qu'on puisse le
        // reconnaître après le remplacement.
        let source = atelier.path().join("marqueur.txt");
        std::fs::write(&source, b"marqueur").expect("écrivable");
        let mut session = Vault::open(&coffre)
            .expect("ouvrable")
            .unlock(passphrase())
            .expect("déverrouillable");
        session
            .add_file(
                &source,
                &VaultPath::from_components([b"marqueur.txt".to_vec()]).expect("valide"),
                AddMode::Copy,
                OnConflict::Fail,
            )
            .expect("ajoutable");
        session.lock();

        let resume = importer(&conteneur, &coffre, ImportPolicy::Replace).expect("remplaçable");
        let ecarte = resume.replaced.expect("l'ancien vault a été déplacé");

        assert!(
            ecarte
                .file_name()
                .expect("un nom")
                .to_string_lossy()
                .contains(".vault-remplace-"),
            "{ecarte:?}"
        );
        assert!(ecarte.is_dir(), "l'ancien vault est encore là");

        // L'ancien est un vault complet et ouvrable, avec ses trois entrées.
        let ancien = Vault::open(&ecarte)
            .expect("ouvrable")
            .unlock(passphrase())
            .expect("déverrouillable");
        assert_eq!(ancien.list(None).len(), 3);
        ancien.lock();

        // Le nouveau est celui du conteneur, avec ses deux entrées.
        let neuf = Vault::open(&coffre)
            .expect("ouvrable")
            .unlock(passphrase())
            .expect("déverrouillable");
        assert_eq!(neuf.list(None).len(), 2);
    }

    /// Deux restaurations dans la même seconde ne doivent pas se marcher
    /// dessus : la sauvegarde de la première survit à la seconde.
    #[test]
    fn deux_remplacements_rapproches_conservent_les_deux_sauvegardes() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let (coffre, conteneur) = coffre_et_conteneur(atelier.path());

        let premier = importer(&conteneur, &coffre, ImportPolicy::Replace)
            .expect("remplaçable")
            .replaced
            .expect("déplacé");
        let second = importer(&conteneur, &coffre, ImportPolicy::Replace)
            .expect("remplaçable")
            .replaced
            .expect("déplacé");

        assert_ne!(premier, second);
        assert!(premier.is_dir() && second.is_dir(), "les deux survivent");
    }

    /// FR-014, FR-015, XFR-017 : un conteneur tronqué ou altéré fait échouer
    /// l'import **sans laisser de vault**, et sans résidu sur un chemin d'erreur
    /// propre.
    #[test]
    fn un_conteneur_altere_ne_laisse_aucun_vault() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let (_, conteneur) = coffre_et_conteneur(atelier.path());
        let cible = atelier.path().join("restaure");

        let tronque = &conteneur[..conteneur.len() - 10];
        assert!(matches!(
            importer(tronque, &cible, ImportPolicy::Refuse),
            Err(Error::Corrupted)
        ));
        assert!(!cible.exists(), "aucun vault ne doit apparaître");

        let mut altere = conteneur.clone();
        let milieu = altere.len() / 2;
        altere[milieu] ^= 0x01;
        assert!(matches!(
            importer(&altere, &cible, ImportPolicy::Refuse),
            Err(Error::Corrupted)
        ));
        assert!(!cible.exists());

        let mut suivi = conteneur.clone();
        suivi.push(0x00);
        assert!(matches!(
            importer(&suivi, &cible, ImportPolicy::Refuse),
            Err(Error::Corrupted)
        ));
        assert!(!cible.exists());

        // Aucun répertoire d'attente ne subsiste : ces échecs sont propres.
        assert_eq!(residus(atelier.path()), Vec::<String>::new());
    }

    /// Répertoires d'attente ou de remplacement laissés dans `atelier`.
    fn residus(atelier: &Path) -> Vec<String> {
        let mut noms: Vec<String> = std::fs::read_dir(atelier)
            .expect("listable")
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|nom| nom.contains(".vault-entrant-") || nom.contains(".vault-remplace-"))
            .collect();
        noms.sort_unstable();
        noms
    }

    /// FR-016, XFR-016 : une version de conteneur inconnue est refusée en
    /// nommant la version rencontrée, **avant** la moindre écriture.
    #[test]
    fn une_version_de_conteneur_inconnue_est_refusee_avant_ecriture() {
        // Le champ `container_version` de l'en-tête CBOR vaut 1 ; le porter à 2
        // suffit, l'en-tête n'étant protégé par rien d'autre que le sceau — que
        // la version fait refuser avant qu'il ne soit lu. Le champ est repéré
        // par sa clé, précédée de son en-tête de texte CBOR `0x71` (17 octets),
        // et non par une suite d'octets qui pourrait figurer ailleurs.
        const CLE: &[u8] = b"\x71container_version";

        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let (_, conteneur) = coffre_et_conteneur(atelier.path());
        let cible = atelier.path().join("restaure");

        let mut futur = conteneur.clone();
        let position = futur
            .windows(CLE.len())
            .position(|fenetre| fenetre == CLE)
            .expect("le champ figure dans l'en-tête")
            + CLE.len();
        assert_eq!(futur[position], 0x01, "la version courante est 1");
        futur[position] = 0x02;

        assert!(matches!(
            importer(&futur, &cible, ImportPolicy::Refuse),
            Err(Error::UnsupportedFormatVersion {
                found: 2,
                supported: 1
            })
        ));
        assert!(!cible.exists());
    }

    /// XFR-019 : l'espace est contrôlé contre le volume annoncé, avant la
    /// première écriture. Le test l'éprouve par l'absurde, en annonçant un
    /// volume que rien ne peut satisfaire.
    #[test]
    fn l_espace_est_controle_avant_la_premiere_ecriture() {
        use crate::format::container::{ContainerWriter, MemberKind};

        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let cible = atelier.path().join("restaure");

        let mut conteneur = Vec::new();
        let mut writer = ContainerWriter::begin(&mut conteneur, 1, 2, u64::MAX).expect("ouvrable");
        writer
            .member(MemberKind::Header, None, 1, &mut &b"h"[..])
            .expect("écrivable");
        writer
            .member(MemberKind::Index, None, 1, &mut &b"i"[..])
            .expect("écrivable");
        writer.finish().expect("scellable");

        assert!(matches!(
            importer(&conteneur, &cible, ImportPolicy::Refuse),
            Err(Error::InsufficientSpace { .. })
        ));
        assert!(!cible.exists());
    }

    #[test]
    fn un_parent_inexistant_est_signale() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let (_, conteneur) = coffre_et_conteneur(atelier.path());

        assert!(matches!(
            importer(
                &conteneur,
                &atelier.path().join("absent").join("restaure"),
                ImportPolicy::Refuse
            ),
            Err(Error::Io(_))
        ));
    }

    /// Un flux qui n'est pas un conteneur est refusé sans que la destination
    /// soit seulement regardée.
    #[test]
    fn un_flux_etranger_est_refuse() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        assert!(matches!(
            importer(
                b"ceci n'est pas un conteneur",
                &atelier.path().join("restaure"),
                ImportPolicy::Refuse
            ),
            Err(Error::Corrupted)
        ));
    }

    /// FR-018, XFR-010 : la vérification cryptographique complète est
    /// **optionnelle**, et elle voit ce que le sceau ne voit pas — un blob
    /// altéré après réception.
    #[test]
    fn la_verification_de_contenu_voit_ce_que_le_sceau_ne_voit_pas() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let (_, conteneur) = coffre_et_conteneur(atelier.path());
        let restaure = atelier.path().join("restaure");
        importer(&conteneur, &restaure, ImportPolicy::Refuse).expect("importable");

        let session = Vault::open(&restaure)
            .expect("ouvrable")
            .unlock(passphrase())
            .expect("déverrouillable");
        let (blob_id, _) = session
            .blob_of(&VaultPath::from_components([b"note.txt".to_vec()]).expect("valide"))
            .expect("présente")
            .expect("un blob");
        let chemin = blob_path(&restaure, &blob_id);
        let original = std::fs::read(&chemin).expect("lisible");

        // Le vault reste structurellement valide : le sceau du conteneur, qui
        // a déjà rendu son verdict, ne verrait rien de ceci.
        let mut altere = original.clone();
        altere[crate::crypto::stream::STREAM_NONCE_LEN] ^= 0x01;
        std::fs::write(&chemin, &altere).expect("écrivable");
        assert!(matches!(
            session.verify_content(),
            Err(Error::Authentication)
        ));

        // **Et ce que la vérification ne voit pas non plus** : le remplissage
        // n'est ni déchiffré ni interprété (VR-B3). Altérer le dernier octet
        // d'un blob rempli ne change donc rien, et il vaut mieux que cette
        // limite soit écrite ici qu'espérée ailleurs.
        let mut rembourrage = original.clone();
        let dernier = rembourrage.len() - 1;
        rembourrage[dernier] ^= 0x01;
        std::fs::write(&chemin, &rembourrage).expect("écrivable");
        assert_eq!(session.verify_content().expect("vérifiable"), 2);
    }

    /// La vérification **passe les dossiers** : ils n'ont pas de blob à
    /// authentifier, et le compte rendu ne porte que sur des fichiers.
    #[test]
    fn la_verification_de_contenu_ignore_les_dossiers() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        let mut vault = Vault::create(&coffre, passphrase(), params()).expect("créable");

        let source = atelier.path().join("arbre");
        std::fs::create_dir_all(source.join("photos")).expect("créable");
        std::fs::write(source.join("photos").join("plage.jpg"), b"contenu").expect("écrivable");
        std::fs::create_dir(source.join("dossier-vide")).expect("créable");
        vault
            .add_dir(
                &source,
                &VaultPath::root(),
                AddMode::Copy,
                OnConflict::Fail,
                &mut |_| {},
            )
            .expect("ajoutable");
        vault.lock();

        let session = Vault::open(&coffre)
            .expect("ouvrable")
            .unlock(passphrase())
            .expect("déverrouillable");
        assert!(session.list(None).len() > 1, "des dossiers sont présents");
        assert_eq!(
            session.verify_content().expect("vérifiable"),
            1,
            "un seul fichier, deux dossiers"
        );
    }

    /// Une entrée de fichier sans blob viole les invariants vérifiés au
    /// déchiffrement de l'index : y arriver signale une corruption, et non un
    /// défaut d'authentification.
    #[test]
    fn la_verification_de_contenu_signale_une_entree_sans_blob() {
        use crate::format::index::IndexEntry;

        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        let mut vault = Vault::create(&coffre, passphrase(), params()).expect("créable");

        vault.index.replace(IndexEntry {
            path: VaultPath::from_components([b"sans-blob.txt".to_vec()]).expect("valide"),
            kind: EntryKind::File,
            size: None,
            modified: 0,
            blob_id: None,
            blob_padded_size: None,
        });

        assert!(matches!(vault.verify_content(), Err(Error::Corrupted)));
    }

    /// Un blob absent est une corruption, pas un défaut d'authentification.
    #[test]
    fn la_verification_de_contenu_signale_un_blob_absent() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let (_, conteneur) = coffre_et_conteneur(atelier.path());
        let restaure = atelier.path().join("restaure");
        importer(&conteneur, &restaure, ImportPolicy::Refuse).expect("importable");

        let session = Vault::open(&restaure)
            .expect("ouvrable")
            .unlock(passphrase())
            .expect("déverrouillable");
        let (blob_id, _) = session
            .blob_of(&VaultPath::from_components([b"note.txt".to_vec()]).expect("valide"))
            .expect("présente")
            .expect("un blob");
        std::fs::remove_file(blob_path(&restaure, &blob_id)).expect("supprimable");

        assert!(matches!(session.verify_content(), Err(Error::Corrupted)));
    }

    /// `docs/format.md` §6.4 : la date de modification des blobs reçus est
    /// ramenée à l'époque Unix, et ne suit donc pas l'instant de réception.
    #[test]
    fn les_dates_des_blobs_recus_sont_a_l_epoque() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let (_, conteneur) = coffre_et_conteneur(atelier.path());
        let restaure = atelier.path().join("restaure");
        importer(&conteneur, &restaure, ImportPolicy::Refuse).expect("importable");

        for entree in std::fs::read_dir(restaure.join(OBJECTS_DIR)).expect("listable") {
            let entree = entree.expect("lisible");
            assert_eq!(
                entree
                    .metadata()
                    .expect("lisible")
                    .modified()
                    .expect("datée"),
                std::time::UNIX_EPOCH
            );
        }
    }

    /// Un vault vide fait l'aller-retour : c'est licite, et l'import redonne un
    /// vault vide et ouvrable.
    #[test]
    fn un_vault_vide_fait_l_aller_retour() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        Vault::create(&coffre, passphrase(), params())
            .expect("créable")
            .lock();
        let mut conteneur = Vec::new();
        Vault::export(&coffre, ExportEnvelope::Source, &mut conteneur).expect("exportable");

        let restaure = atelier.path().join("restaure");
        let resume = importer(&conteneur, &restaure, ImportPolicy::Refuse).expect("importable");
        assert_eq!(resume.blob_count, 0);

        let session = Vault::open(&restaure)
            .expect("ouvrable")
            .unlock(passphrase())
            .expect("déverrouillable");
        assert!(session.list(None).is_empty());
        assert_eq!(session.verify_content().expect("vérifiable"), 0);
    }

    /// La destination peut être un chemin relatif sans répertoire explicite :
    /// le répertoire d'attente atterrit alors dans le répertoire courant.
    #[test]
    fn une_destination_sans_parent_explicite_est_acceptee() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let (_, conteneur) = coffre_et_conteneur(atelier.path());

        // Même verrou que le test jumeau de `ops::create` : le répertoire
        // courant est global au processus (voir `ops::serie`).
        let _serie = crate::ops::serie::repertoire_courant();
        let ancien = std::env::current_dir().expect("répertoire courant");
        std::env::set_current_dir(atelier.path()).expect("déplaçable");
        let resultat = importer(&conteneur, Path::new("relatif"), ImportPolicy::Refuse);
        std::env::set_current_dir(&ancien).expect("rétablissable");

        assert!(resultat.is_ok(), "{resultat:?}");
        assert!(atelier.path().join("relatif").join(HEADER_FILE).is_file());
    }

    #[test]
    fn les_types_du_contrat_ont_un_debug() {
        let resume = ImportSummary {
            blob_count: 1,
            payload_bytes: 2,
            replaced: None,
        };
        assert!(format!("{resume:?}").contains("ImportSummary"));
        assert_eq!(resume, resume.clone());
        assert!(format!("{:?}", ImportPolicy::Replace).contains("Replace"));
        assert_ne!(ImportPolicy::Refuse, ImportPolicy::Replace);
        assert_eq!(nom_de(Path::new("/a/b/coffre")), "coffre");
        assert_eq!(nom_de(Path::new("/")), "vault");
    }

    /// FR-013b : deux restaurations dans la **même seconde** ne se marchent pas
    /// dessus. Le suffixe numéraire est ce qui l'assure, et il est éprouvé
    /// directement plutôt que par une course entre deux imports rapides — qui
    /// tomberait tantôt dans la même seconde, tantôt non.
    #[test]
    fn le_nommage_ajoute_un_suffixe_quand_la_seconde_est_prise() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let destination = atelier.path().join("coffre");
        let secondes = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Le nom de base est pris pour la seconde courante et les deux
        // suivantes : le test reste valable si l'horloge avance pendant son
        // exécution. Un seul nom par seconde suffit ici — c'est le **premier**
        // suffixe qu'on veut voir apparaître, pas la borne.
        for seconde in [secondes, secondes + 1, secondes + 2] {
            std::fs::write(
                atelier
                    .path()
                    .join(format!("coffre.vault-remplace-{seconde}")),
                b"",
            )
            .expect("écrivable");
        }

        let choisi = nom_de_remplacement(&destination).expect("un nom libre");
        assert!(
            choisi
                .file_name()
                .expect("un nom")
                .to_string_lossy()
                .ends_with("-1"),
            "{choisi:?}"
        );
        assert!(!choisi.exists());
    }

    /// Le repli du nommage : mille noms pris dans la même seconde font échouer
    /// la recherche plutôt que d'écraser une sauvegarde.
    #[test]
    fn un_nommage_sature_echoue_plutot_que_d_ecraser() {
        /// Reprises accordées à la saturation avant de renoncer.
        const REPRISES: u32 = 8;

        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let destination = atelier.path().join("coffre");

        // **La saturation doit s'achever dans la seconde qu'elle sature**,
        // sinon la recherche vise la seconde suivante — encore libre — et la
        // borne n'est jamais atteinte. C'est exactement ce qui rendait ce test
        // vert sur ext4 et rouge sur NTFS.
        //
        // Plutôt que de tabler sur une marge devinée, on constate : si la
        // création a traversé une frontière de seconde, on recommence. Avec
        // cent noms, la première tentative suffit sauf à démarrer à la toute
        // fin d'une seconde.
        let saturee = (0..REPRISES).any(|_| {
            let seconde = secondes_unix();
            saturer(atelier.path(), seconde);
            secondes_unix() == seconde
        });

        assert!(
            saturee,
            "la saturation n'a jamais tenu dans une seule seconde"
        );
        assert!(matches!(
            nom_de_remplacement(&destination),
            Err(Error::AlreadyExists)
        ));
    }

    /// L'instant présent, en secondes Unix — le même que celui dont
    /// [`nom_de_remplacement`] tire son suffixe.
    fn secondes_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Prend **tous** les noms de remplacement possibles pour cette seconde.
    fn saturer(atelier: &Path, seconde: u64) {
        let base = format!("coffre.vault-remplace-{seconde}");
        std::fs::write(atelier.join(&base), b"").expect("écrivable");
        for rang in 1..MAX_REPLACE_ATTEMPTS {
            std::fs::write(atelier.join(format!("{base}-{rang}")), b"").expect("écrivable");
        }
    }
}
