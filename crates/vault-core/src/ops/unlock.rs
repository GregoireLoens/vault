//! Ouverture, déverrouillage et verrouillage — T036, T037.
//!
//! FR-007 à FR-012. La séparation entre [`Vault::open`] et [`Vault::unlock`]
//! n'est pas cosmétique : elle permet de lire les paramètres publics d'un vault
//! — version de format, coûts de dérivation — **sans** demander la passphrase,
//! ce qu'exige `vault info` (CLI-018), tout en garantissant par le système de
//! types qu'un vault verrouillé n'expose aucune méthode de lecture du contenu
//! (C-007, FR-011).
//!
//! Le verrou exclusif est pris **avant** la dérivation de la clé (C-005) : sans
//! cela, deux instances lancées ensemble paieraient chacune une dérivation
//! Argon2id de plusieurs centaines de millisecondes avant que la seconde
//! n'apprenne qu'elle n'aurait pas dû.

use std::path::Path;

use secrecy::SecretString;

use crate::error::{Error, Result};
use crate::format::blob::BlobId;
use crate::format::header::Header;
use crate::format::index::Index;
use crate::fs::lock::VaultLock;
use crate::ops::{HEADER_FILE, INDEX_FILE, OBJECTS_DIR};
use crate::{UnlockedVault, Vault};

impl Vault {
    /// Ouvre un vault sans le déverrouiller.
    ///
    /// Ne lit que l'en-tête, qui est public par conception. Aucun secret n'est
    /// manipulé, aucune passphrase n'est demandée.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] s'il n'y a pas de vault à cet emplacement ;
    /// - [`Error::Corrupted`] si l'en-tête est illisible ;
    /// - [`Error::UnsupportedFormatVersion`] si le format dépasse ce que cette
    ///   version sait lire (VR-H1) ;
    /// - [`Error::Io`] pour toute autre défaillance de lecture.
    pub fn open(path: &Path) -> Result<Self> {
        let bytes = match std::fs::read(path.join(HEADER_FILE)) {
            Ok(bytes) => bytes,
            Err(erreur) if erreur.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::NotFound);
            }
            Err(erreur) => return Err(erreur.into()),
        };
        Ok(Self::new(path.to_path_buf(), Header::decode(&bytes)?))
    }

    /// Déverrouille le vault et ouvre une session.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyInUse`] si une autre instance détient le verrou
    ///   (FR-012, C-005) ;
    /// - [`Error::Authentication`] si la passphrase est erronée, l'en-tête
    ///   altéré ou la clé maîtresse corrompue — **sans distinction possible**
    ///   (FR-008, C-004) ;
    /// - [`Error::Corrupted`] si l'index est illisible ;
    /// - [`Error::Io`] si l'index ne peut pas être lu.
    // Par valeur délibérément : voir la note de `Vault::create`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn unlock(self, passphrase: SecretString) -> Result<UnlockedVault> {
        let Self { path, header } = self;

        let lock = VaultLock::acquire(&path)?;
        let master_key = header.unlock(&passphrase)?;
        let index = Index::decrypt(&master_key, &std::fs::read(path.join(INDEX_FILE))?)?;

        sweep_orphans(&path, &index);

        Ok(UnlockedVault::new(path, header, master_key, index, lock))
    }

    /// Vérifie qu'aucune autre instance ne détient ce vault (FR-012).
    ///
    /// Sert à prononcer le refus **avant** de réclamer la passphrase : sans
    /// cela, l'utilisateur d'une seconde instance saisirait son secret pour
    /// apprendre ensuite qu'elle ne pouvait pas ouvrir.
    ///
    /// La vérification qui fait foi reste celle de [`Vault::unlock`], qui prend
    /// le verrou et le garde. Celle-ci le relâche aussitôt, et une autre
    /// instance peut donc s'en emparer dans l'intervalle — auquel cas c'est
    /// `unlock` qui refusera, avec la même erreur. Ce n'est pas une course
    /// dangereuse : les deux issues sont un refus correct, et aucune ne donne
    /// l'accès à deux instances à la fois.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyInUse`] si une autre instance détient le verrou ;
    /// - [`Error::Io`] si le fichier support du verrou est inaccessible.
    pub fn check_available(&self) -> Result<()> {
        VaultLock::acquire(self.path()).map(drop)
    }
}

/// Supprime les blobs que l'index ne référence pas (VR-I6).
///
/// L'index est le **point d'engagement** du vault (D-008) : un blob écrit puis
/// abandonné par une opération interrompue n'existe pas de son point de vue.
/// C'est un déchet inerte, et non une corruption — d'où le silence, exigé par
/// VR-I6. Le signaler laisserait croire à une atteinte à l'intégrité là où le
/// format a fonctionné comme prévu.
///
/// Trois choses ne sont **pas** faites ici, chacune délibérément :
///
/// - un balayage impossible — répertoire illisible, support en lecture seule —
///   ne fait pas échouer l'ouverture. Refuser d'ouvrir un vault par ailleurs
///   intact parce qu'on ne peut pas en retirer un déchet serait une punition
///   sans rapport avec la faute ;
/// - un fichier dont le nom n'est pas un identifiant de blob est laissé en
///   place. Ce n'est pas un blob, donc pas un déchet du vault : ce répertoire
///   n'est pas à nous seuls, et supprimer ce qu'on ne reconnaît pas serait
///   dépasser le mandat ;
/// - l'échec d'une suppression n'interrompt pas le balayage. Le déchet restant
///   sera repris au déverrouillage suivant.
fn sweep_orphans(vault_dir: &Path, index: &Index) {
    let Ok(entries) = std::fs::read_dir(vault_dir.join(OBJECTS_DIR)) else {
        return;
    };
    let referenced = index.referenced_blobs();

    for entry in entries.flatten() {
        // Un nom non représentable en UTF-8 ne peut pas être un identifiant de
        // blob, qui est fait de soixante-quatre chiffres hexadécimaux : la
        // conversion avec perte le fera refuser par `from_hex`.
        let Ok(blob_id) = BlobId::from_hex(&entry.file_name().to_string_lossy()) else {
            continue;
        };
        if !referenced.contains(&blob_id) {
            drop(std::fs::remove_file(entry.path()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::KdfParams;

    fn params() -> KdfParams {
        KdfParams::new(64, 1, 1).expect("paramètres valides")
    }

    fn passphrase() -> SecretString {
        SecretString::from("passphrase de test bien assez longue".to_owned())
    }

    fn coffre_neuf(atelier: &Path) -> std::path::PathBuf {
        let coffre = atelier.join("coffre");
        Vault::create(&coffre, passphrase(), params())
            .expect("créable")
            .lock();
        coffre
    }

    #[test]
    fn un_vault_se_referme_et_se_rouvre() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());

        let verrouille = Vault::open(&coffre).expect("ouvrable");
        assert_eq!(verrouille.format_version(), crate::FORMAT_VERSION);
        assert_eq!(verrouille.kdf_params(), params());

        let session = verrouille.unlock(passphrase()).expect("déverrouillable");
        assert!(session.list(None).is_empty());
        assert_eq!(session.index_version(), 0);
    }

    #[test]
    fn un_emplacement_sans_vault_est_introuvable() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        assert!(matches!(Vault::open(atelier.path()), Err(Error::NotFound)));
        assert!(matches!(
            Vault::open(&atelier.path().join("nulle-part")),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn un_en_tete_illisible_est_signale() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());
        std::fs::write(coffre.join(HEADER_FILE), b"ceci n'est pas un en-tete").expect("écrivable");

        assert!(matches!(Vault::open(&coffre), Err(Error::Corrupted)));
    }

    /// Une défaillance de lecture qui n'est pas une absence remonte telle
    /// quelle, et non déguisée en `NotFound` : dire « il n'y a pas de vault ici »
    /// alors qu'il y en a un mais illisible enverrait l'utilisateur chercher au
    /// mauvais endroit.
    #[cfg(unix)]
    #[test]
    fn un_en_tete_illisible_par_permission_remonte_l_erreur() {
        use std::os::unix::fs::PermissionsExt;

        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());
        let en_tete = coffre.join(HEADER_FILE);

        let mut permissions = std::fs::metadata(&en_tete).expect("lisible").permissions();
        permissions.set_mode(0o000);
        std::fs::set_permissions(&en_tete, permissions).expect("modifiable");

        let resultat = Vault::open(&coffre);

        let mut permissions = std::fs::metadata(&en_tete).expect("lisible").permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&en_tete, permissions).expect("modifiable");

        assert!(
            matches!(resultat, Err(Error::Io(_))),
            "obtenu : {resultat:?}"
        );
    }

    /// C-004, FR-008 : une passphrase erronée renvoie `Authentication`, le même
    /// variant qu'un en-tête altéré.
    #[test]
    fn une_passphrase_erronee_est_refusee() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());

        let fausse = SecretString::from("une passphrase parfaitement fausse".to_owned());
        assert!(matches!(
            Vault::open(&coffre).expect("ouvrable").unlock(fausse),
            Err(Error::Authentication)
        ));
    }

    /// FR-012, C-005 : une seconde session sur le même vault est refusée.
    #[test]
    fn une_seconde_session_est_refusee() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        let premiere = Vault::create(&coffre, passphrase(), params()).expect("créable");

        assert!(matches!(
            Vault::open(&coffre).expect("ouvrable").unlock(passphrase()),
            Err(Error::AlreadyInUse)
        ));

        premiere.lock();
        assert!(
            Vault::open(&coffre)
                .expect("ouvrable")
                .unlock(passphrase())
                .is_ok()
        );
    }

    #[test]
    fn un_index_absent_ou_altere_est_signale() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());

        let index = std::fs::read(coffre.join(INDEX_FILE)).expect("lisible");
        let mut altere = index.clone();
        let dernier = altere.len() - 1;
        altere[dernier] ^= 0x01;
        std::fs::write(coffre.join(INDEX_FILE), &altere).expect("écrivable");
        assert!(matches!(
            Vault::open(&coffre).expect("ouvrable").unlock(passphrase()),
            Err(Error::Authentication)
        ));

        std::fs::remove_file(coffre.join(INDEX_FILE)).expect("supprimable");
        assert!(matches!(
            Vault::open(&coffre).expect("ouvrable").unlock(passphrase()),
            Err(Error::Io(_))
        ));
    }

    /// VR-I6 : un blob que l'index ne référence pas est un déchet, retiré
    /// silencieusement au déverrouillage. Les blobs référencés, eux, sont
    /// intacts.
    #[test]
    fn les_blobs_orphelins_sont_balayes_au_deverrouillage() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        let source = atelier.path().join("note.txt");
        std::fs::write(&source, b"une note").expect("écrivable");

        let mut vault = Vault::create(&coffre, passphrase(), params()).expect("créable");
        let chemin = crate::VaultPath::from_components([b"note.txt".to_vec()]).expect("valide");
        vault
            .add_file(
                &source,
                &chemin,
                crate::AddMode::Copy,
                crate::OnConflict::Fail,
            )
            .expect("ajoutable");
        let (legitime, _) = vault.blob_of(&chemin).expect("présente").expect("un blob");
        vault.lock();

        // Un blob abandonné par une opération interrompue, et un fichier
        // étranger qui n'est pas un blob.
        let objets = coffre.join(OBJECTS_DIR);
        let orphelin = objets.join(crate::BlobId::generate().to_hex());
        let etranger = objets.join("pas-un-identifiant-de-blob");
        std::fs::write(&orphelin, "déchet inerte").expect("écrivable");
        std::fs::write(&etranger, "fichier étranger").expect("écrivable");

        let session = Vault::open(&coffre)
            .expect("ouvrable")
            .unlock(passphrase())
            .expect("déverrouillable");

        assert!(!orphelin.exists(), "l'orphelin devait être balayé");
        assert!(etranger.exists(), "un fichier étranger n'est pas un déchet");
        assert!(
            objets.join(legitime.to_hex()).exists(),
            "le blob référencé devait survivre"
        );
        // Le contenu reste extractible : le balayage n'a touché à rien d'utile.
        let sortie = atelier.path().join("sortie");
        std::fs::create_dir(&sortie).expect("créable");
        session
            .extract(&chemin, &sortie, crate::OnConflict::Fail)
            .expect("extractible");
    }

    /// Un balayage impossible ne fait pas échouer l'ouverture d'un vault par
    /// ailleurs intact.
    #[test]
    fn un_balayage_impossible_n_empeche_pas_d_ouvrir() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());
        std::fs::remove_dir_all(coffre.join(OBJECTS_DIR)).expect("supprimable");

        let session = Vault::open(&coffre)
            .expect("ouvrable")
            .unlock(passphrase())
            .expect("déverrouillable malgré le balayage impossible");
        assert!(session.list(None).is_empty());
    }

    /// FR-012 : la disponibilité se vérifie sans passphrase, pour refuser avant
    /// de la réclamer. La vérification relâche le verrou aussitôt.
    #[test]
    fn la_disponibilite_se_verifie_sans_passphrase() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        let session = Vault::create(&coffre, passphrase(), params()).expect("créable");

        assert!(matches!(
            Vault::open(&coffre).expect("ouvrable").check_available(),
            Err(Error::AlreadyInUse)
        ));

        session.lock();
        Vault::open(&coffre)
            .expect("ouvrable")
            .check_available()
            .expect("disponible");

        // Le verrou a bien été relâché : le déverrouillage qui suit l'obtient.
        Vault::open(&coffre)
            .expect("ouvrable")
            .unlock(passphrase())
            .expect("déverrouillable");
    }

    /// C-003 bis, VR-S3 : le délai d'inactivité est conservé et ne déclenche
    /// rien. FR-010 est différé.
    #[test]
    fn le_delai_d_inactivite_reste_sans_effet() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let mut session =
            Vault::create(&atelier.path().join("coffre"), passphrase(), params()).expect("créable");

        assert_eq!(session.idle_timeout(), None);
        session.set_idle_timeout(Some(std::time::Duration::from_secs(1)));
        assert_eq!(
            session.idle_timeout(),
            Some(std::time::Duration::from_secs(1))
        );
        assert!(
            session.list(None).is_empty(),
            "la session reste exploitable"
        );
    }
}
