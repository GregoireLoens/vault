//! Suite bloquante — détection d'altération (T051, SC-004, FR-039).
//!
//! SC-004 exige que **toute** altération d'un vault soit détectée. Les tests
//! unitaires du format vérifient déjà qu'une altération donnée est refusée ;
//! cette suite pose la propriété dans l'autre sens, la seule qui vaille pour un
//! coffre-fort : il n'existe **aucun** octet du vault dont la modification
//! passe inaperçue.
//!
//! La méthode est donc systématique plutôt qu'illustrative. Chaque zone est
//! balayée octet par octet, un bit retourné à la fois, et l'on vérifie que
//! l'opération échoue à chaque position. Un seul bit qui passerait suffirait à
//! faire échouer la suite, et signalerait une région du format non
//! authentifiée.
//!
//! Deux exceptions, toutes deux voulues par le format :
//!
//! - le **remplissage** d'un blob n'est jamais déchiffré ni interprété (VR-B3).
//!   L'altérer ne doit rien changer, et cette suite le vérifie explicitement :
//!   c'est la contrepartie de l'exhaustivité affirmée plus haut ;
//! - le fichier `.lock` ne porte aucune donnée.
//!
//! FR-039 ajoute une exigence qui ne se lit pas dans le code de retour : une
//! altération détectée ne doit **jamais** laisser de sortie partielle. Chaque
//! cas d'extraction le vérifie sur le répertoire de destination.

use std::path::{Path, PathBuf};

use vault_core::{AddMode, Error, KdfParams, OnConflict, SecretString, Vault, VaultPath};

/// Disposition d'un blob, telle que `docs/format.md` la fixe.
const NONCE_LEN: usize = 19;
/// Longueur d'un tag d'authentification XChaCha20-Poly1305.
const TAG_LEN: usize = 16;
/// Taille d'un morceau STREAM, en octets.
const CHUNK_SIZE: usize = 64 * 1024;

/// Paramètres minimaux : cette suite mesure la détection d'altération, pas le
/// coût d'une attaque par force brute. Elle déverrouille des centaines de fois.
fn params() -> KdfParams {
    KdfParams::new(64, 1, 1).expect("paramètres valides")
}

fn passphrase() -> SecretString {
    SecretString::from("passphrase de test bien assez longue".to_owned())
}

fn chemin(composants: &[&[u8]]) -> VaultPath {
    VaultPath::from_components(composants.iter().map(|c| c.to_vec())).expect("chemin valide")
}

/// Longueur du chiffré d'un contenu de `taille` octets, tag(s) compris.
fn longueur_chiffre(taille: usize) -> usize {
    let morceaux = taille.div_ceil(CHUNK_SIZE).max(1);
    taille + morceaux * TAG_LEN
}

/// Un vault fermé contenant `note.txt`, et le chemin de son unique blob.
struct Coffre {
    _atelier: tempfile::TempDir,
    chemin: PathBuf,
    sortie: PathBuf,
}

impl Coffre {
    /// Crée un vault refermé contenant un seul fichier de `taille` octets.
    fn neuf(taille: usize) -> Self {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let chemin = atelier.path().join("coffre");

        let source = atelier.path().join("note.txt");
        let contenu: Vec<u8> = (0..taille)
            .map(|index| u8::try_from(index % 251).expect("reste inférieur à 251"))
            .collect();
        std::fs::write(&source, &contenu).expect("écrivable");

        let mut vault = Vault::create(&chemin, passphrase(), params()).expect("créable");
        vault
            .add_file(&source, &chemin_de_note(), AddMode::Copy, OnConflict::Fail)
            .expect("ajoutable");
        vault.lock();

        let sortie = atelier.path().join("sortie");
        std::fs::create_dir(&sortie).expect("créable");

        Self {
            _atelier: atelier,
            chemin,
            sortie,
        }
    }

    fn fichier(&self, nom: &str) -> PathBuf {
        self.chemin.join(nom)
    }

    /// Emplacement du blob de `note.txt`.
    fn blob(&self) -> PathBuf {
        let session = self.ouvrir().expect("déverrouillable");
        let (blob_id, _) = session
            .blob_of(&chemin_de_note())
            .expect("présente")
            .expect("un blob");
        self.chemin.join("objects").join(blob_id.to_hex())
    }

    fn ouvrir(&self) -> vault_core::Result<vault_core::UnlockedVault> {
        Vault::open(&self.chemin)?.unlock(passphrase())
    }

    /// Vrai si le répertoire de destination est vide.
    fn sortie_vide(&self) -> bool {
        std::fs::read_dir(&self.sortie)
            .expect("listable")
            .next()
            .is_none()
    }
}

fn chemin_de_note() -> VaultPath {
    chemin(&[b"note.txt"])
}

/// Retourne le bit de poids faible de l'octet `position` de `fichier`, exécute
/// `essai`, puis rétablit le fichier dans son état d'origine.
fn en_alterant<T>(fichier: &Path, position: usize, essai: impl FnOnce() -> T) -> T {
    let original = std::fs::read(fichier).expect("lisible");
    let mut altere = original.clone();
    altere[position] ^= 0x01;
    std::fs::write(fichier, &altere).expect("écrivable");

    let resultat = essai();

    std::fs::write(fichier, &original).expect("écrivable");
    resultat
}

/// Vrai si l'erreur est un refus explicite, et non un succès ni une
/// défaillance accidentelle.
fn est_un_refus_explicite<T>(resultat: &vault_core::Result<T>) -> bool {
    matches!(
        resultat,
        Err(Error::Authentication | Error::Corrupted | Error::UnsupportedFormatVersion { .. })
    )
}

/// SC-004 : aucun octet de l'en-tête ne peut être modifié sans que le
/// déverrouillage le refuse.
///
/// L'en-tête est en clair — c'est ce que le format prévoit — mais ses champs
/// publics sont les données associées de l'enveloppe de la clé maîtresse
/// (VR-H5). Les toucher fait donc échouer le désenveloppement, exactement
/// comme une passphrase erronée.
#[test]
fn aucune_alteration_de_l_en_tete_ne_passe() {
    let coffre = Coffre::neuf(100);
    let en_tete = coffre.fichier("header");
    let longueur = std::fs::read(&en_tete).expect("lisible").len();

    let verdicts: Vec<bool> = (0..longueur)
        .map(|position| {
            en_alterant(&en_tete, position, || {
                est_un_refus_explicite(&coffre.ouvrir())
            })
        })
        .collect();

    assert_eq!(
        verdicts,
        vec![true; longueur],
        "en-tête de {longueur} octets"
    );
}

/// SC-004 : aucun octet de l'index ne peut être modifié sans que le
/// déverrouillage le refuse.
///
/// L'index est intégralement chiffré, nonce compris : toute position produit
/// donc le **même** refus, `Authentication`. Une position qui donnerait
/// `Corrupted` signalerait une zone lue avant d'être authentifiée.
#[test]
fn aucune_alteration_de_l_index_ne_passe() {
    let coffre = Coffre::neuf(100);
    let index = coffre.fichier("index");
    let longueur = std::fs::read(&index).expect("lisible").len();

    let verdicts: Vec<bool> = (0..longueur)
        .map(|position| {
            en_alterant(&index, position, || {
                matches!(coffre.ouvrir(), Err(Error::Authentication))
            })
        })
        .collect();

    assert_eq!(verdicts, vec![true; longueur], "index de {longueur} octets");
}

/// SC-004, FR-039 : aucun octet du chiffré d'un blob — nonce, morceau ou tag —
/// ne peut être modifié sans que l'extraction le refuse, et sans qu'elle
/// laisse la destination intacte.
#[test]
fn aucune_alteration_du_chiffre_d_un_blob_ne_passe() {
    let coffre = Coffre::neuf(100);
    let blob = coffre.blob();
    let session = coffre.ouvrir().expect("déverrouillable");

    // La zone lue : le nonce, puis le morceau unique et son tag. Au-delà
    // commence le remplissage, que le test suivant traite à part.
    let zone = NONCE_LEN + longueur_chiffre(100);

    let verdicts: Vec<bool> = (0..zone)
        .map(|position| {
            en_alterant(&blob, position, || {
                let resultat = session.extract(&chemin_de_note(), &coffre.sortie, OnConflict::Fail);
                est_un_refus_explicite(&resultat) && coffre.sortie_vide()
            })
        })
        .collect();

    assert_eq!(verdicts, vec![true; zone], "zone chiffrée de {zone} octets");
}

/// VR-B3 : le remplissage n'est ni déchiffré ni interprété. L'altérer ne
/// change donc rien — et c'est la contrepartie assumée de l'exhaustivité du
/// test précédent, non un trou dans l'authentification.
#[test]
fn le_remplissage_d_un_blob_n_est_jamais_interprete() {
    let coffre = Coffre::neuf(100);
    let blob = coffre.blob();
    let session = coffre.ouvrir().expect("déverrouillable");

    let debut = NONCE_LEN + longueur_chiffre(100);
    let taille = std::fs::read(&blob).expect("lisible").len();
    assert!(taille > debut, "un remplissage doit exister");

    let verdicts: Vec<bool> = (debut..taille)
        .map(|position| {
            en_alterant(&blob, position, || {
                let resultat =
                    session.extract(&chemin_de_note(), &coffre.sortie, OnConflict::Replace);
                resultat.is_ok()
            })
        })
        .collect();

    assert_eq!(verdicts, vec![true; taille - debut]);
}

/// FR-039 : une altération du **second** morceau n'est découverte qu'après
/// l'authentification du premier. Sans le fichier temporaire, l'extraction
/// aurait déjà écrit 64 KiB de clair à destination avant de s'interrompre.
#[test]
fn une_alteration_tardive_ne_laisse_aucune_sortie_partielle() {
    let taille = 2 * CHUNK_SIZE + 7;
    let coffre = Coffre::neuf(taille);
    let blob = coffre.blob();
    let session = coffre.ouvrir().expect("déverrouillable");

    // Un octet du deuxième morceau : le premier s'authentifie sans encombre.
    let position = NONCE_LEN + CHUNK_SIZE + TAG_LEN + 10;
    let (refus, sortie_vide) = en_alterant(&blob, position, || {
        let resultat = session.extract(&chemin_de_note(), &coffre.sortie, OnConflict::Fail);
        (
            matches!(resultat, Err(Error::Authentication)),
            coffre.sortie_vide(),
        )
    });

    assert!(refus, "l'altération du second morceau doit être détectée");
    assert!(
        sortie_vide,
        "aucun octet de clair ne doit atteindre le disque"
    );

    // Le blob rétabli, l'extraction aboutit : c'est bien l'altération qui a
    // fait échouer la précédente, et non le montage du test.
    session
        .extract(&chemin_de_note(), &coffre.sortie, OnConflict::Fail)
        .expect("extractible une fois le blob rétabli");
    assert_eq!(
        std::fs::metadata(coffre.sortie.join("note.txt"))
            .expect("lisible")
            .len(),
        taille as u64
    );
}

/// Un blob tronqué, vidé ou absent est une altération comme une autre : elle
/// est signalée, et rien n'est écrit.
#[test]
fn un_blob_tronque_vide_ou_absent_est_signale() {
    let coffre = Coffre::neuf(100);
    let blob = coffre.blob();
    let session = coffre.ouvrir().expect("déverrouillable");
    let original = std::fs::read(&blob).expect("lisible");

    let mut verdicts = Vec::new();
    for mutilation in [&original[..10], &original[..NONCE_LEN + 4], b""] {
        std::fs::write(&blob, mutilation).expect("écrivable");
        let resultat = session.extract(&chemin_de_note(), &coffre.sortie, OnConflict::Fail);
        verdicts.push(est_un_refus_explicite(&resultat) && coffre.sortie_vide());
    }

    std::fs::remove_file(&blob).expect("supprimable");
    let resultat = session.extract(&chemin_de_note(), &coffre.sortie, OnConflict::Fail);
    verdicts.push(est_un_refus_explicite(&resultat) && coffre.sortie_vide());

    assert_eq!(verdicts, vec![true; 4]);
}

/// Échanger deux blobs entre eux est une altération, et elle est détectée.
///
/// C'est le cas que ni le nonce ni le tag ne suffiraient à couvrir : chaque
/// blob est intact, seul son emplacement a changé. Il échoue parce que la clé
/// d'un blob **et** ses données associées dérivent de son identifiant, qui est
/// aussi son nom de fichier.
#[test]
fn deux_blobs_echanges_sont_detectes() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = atelier.path().join("coffre");
    let sortie = atelier.path().join("sortie");
    std::fs::create_dir(&sortie).expect("créable");

    let premier_source = atelier.path().join("premier");
    let second_source = atelier.path().join("second");
    std::fs::write(&premier_source, vec![0xaa; 300]).expect("écrivable");
    std::fs::write(&second_source, vec![0xbb; 300]).expect("écrivable");

    let mut vault = Vault::create(&coffre, passphrase(), params()).expect("créable");
    for (source, nom) in [
        (&premier_source, &b"premier"[..]),
        (&second_source, &b"second"[..]),
    ] {
        vault
            .add_file(source, &chemin(&[nom]), AddMode::Copy, OnConflict::Fail)
            .expect("ajoutable");
    }

    let emplacement = |nom: &[u8]| {
        let (blob_id, _) = vault
            .blob_of(&chemin(&[nom]))
            .expect("présente")
            .expect("un blob");
        coffre.join("objects").join(blob_id.to_hex())
    };
    let (premier, second) = (emplacement(b"premier"), emplacement(b"second"));

    let contenu_premier = std::fs::read(&premier).expect("lisible");
    std::fs::copy(&second, &premier).expect("copiable");
    std::fs::write(&second, &contenu_premier).expect("écrivable");

    let verdicts: Vec<bool> = [&b"premier"[..], &b"second"[..]]
        .iter()
        .map(|nom| {
            let resultat = vault.extract(&chemin(&[nom]), &sortie, OnConflict::Fail);
            matches!(resultat, Err(Error::Authentication))
        })
        .collect();

    assert_eq!(verdicts, vec![true, true]);
    assert_eq!(
        std::fs::read_dir(&sortie).expect("listable").count(),
        0,
        "aucune sortie partielle"
    );
}

// ---------------------------------------------------------------------------
// Le conteneur d'export — T014, principe VI
// ---------------------------------------------------------------------------
//
// La propriété est celle de tout ce fichier, posée dans le sens qui vaut pour
// un coffre-fort : **il n'existe aucun octet du conteneur dont la modification
// passe inaperçue.** Le balayage est donc exhaustif, un bit retourné à la fois,
// et non illustratif.
//
// Ce que le sceau établit ici est cependant plus étroit que ce que les tags
// AEAD établissent ailleurs, et la distinction est écrite plutôt que supposée :
// le sceau détecte une **corruption**, jamais une **falsification** — il n'est
// pas authentifié par une clé, et quiconque réécrit un conteneur peut le
// recalculer. Le dernier test de cette section en fait la démonstration.

/// Un vault peuplé, refermé, et le conteneur qu'il produit.
fn coffre_et_conteneur(atelier: &Path) -> (PathBuf, Vec<u8>) {
    let coffre = atelier.join("coffre");
    let mut vault = Vault::create(&coffre, passphrase(), params()).expect("créable");
    let source = atelier.join("note.txt");
    std::fs::write(&source, b"une note de reference").expect("écrivable");
    vault
        .add_file(
            &source,
            &chemin(&[b"note.txt"]),
            AddMode::Copy,
            OnConflict::Fail,
        )
        .expect("ajoutable");
    vault.lock();

    let mut conteneur = Vec::new();
    Vault::export(&coffre, vault_core::ExportEnvelope::Source, &mut conteneur).expect("exportable");
    (coffre, conteneur)
}

/// **Aucun** octet du conteneur ne peut être retourné sans que l'import le
/// voie, et aucun refus ne laisse de vault à destination.
///
/// Le balayage est exhaustif : chaque position du flux, un bit à la fois.
#[test]
fn aucune_alteration_du_conteneur_ne_passe() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let (_, conteneur) = coffre_et_conteneur(atelier.path());

    let mut passees = Vec::new();
    for position in 0..conteneur.len() {
        let mut altere = conteneur.clone();
        altere[position] ^= 0x01;

        let cible = atelier.path().join("cible");
        let resultat = Vault::import(&mut &altere[..], &cible, vault_core::ImportPolicy::Refuse);

        if resultat.is_ok() {
            passees.push(position);
        }
        assert!(
            !cible.exists() || resultat.is_ok(),
            "un refus a laissé un vault, position {position}"
        );
        drop(std::fs::remove_dir_all(&cible));
    }

    assert!(
        passees.is_empty(),
        "altérations non détectées aux positions {passees:?}"
    );
}

/// La troncature suit la même règle : **aucune** longueur inférieure à celle du
/// conteneur ne produit un vault.
#[test]
fn aucune_troncature_du_conteneur_ne_passe() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let (_, conteneur) = coffre_et_conteneur(atelier.path());

    for coupe in 0..conteneur.len() {
        let cible = atelier.path().join("cible");
        assert!(
            Vault::import(
                &mut &conteneur[..coupe],
                &cible,
                vault_core::ImportPolicy::Refuse
            )
            .is_err(),
            "conteneur tronqué à {coupe} accepté"
        );
        assert!(!cible.exists(), "un vault est apparu, coupé à {coupe}");
    }
}

/// **Ce que le sceau ne détecte pas**, et il faut que ce soit écrit ici plutôt
/// qu'espéré ailleurs : une **falsification**.
///
/// Le sceau est un BLAKE3 nu, sans clé. Quiconque réécrit un conteneur peut le
/// recalculer, et son verdict redevient vert. L'authenticité du contenu vient
/// des tags AEAD, au déverrouillage — ce que le second temps du test établit.
#[test]
fn le_sceau_ne_detecte_pas_une_falsification() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let (coffre, conteneur) = coffre_et_conteneur(atelier.path());

    // La cible est un octet du membre `header`, c'est-à-dire du fichier
    // `header` du vault, recopié tel quel. Viser au hasard ne conviendrait pas :
    // le remplissage d'un blob n'est jamais interprété (VR-B3), et l'altérer ne
    // prouverait rien — c'est exactement le piège que ce fichier documente plus
    // haut.
    let membre_header = std::fs::read(coffre.join("header")).expect("lisible");
    let debut_du_header = conteneur
        .windows(membre_header.len())
        .position(|fenetre| fenetre == membre_header)
        .expect("le membre header figure tel quel dans le conteneur");

    let motif: &[u8] = &[0xa3, 0x63, b'e', b'n', b'd', 0x48];
    let debut_du_sceau = conteneur
        .windows(motif.len())
        .rposition(|fenetre| fenetre == motif)
        .expect("le sceau termine le flux");

    let mut falsifie = conteneur.clone();
    falsifie[debut_du_header + membre_header.len() / 2] ^= 0x01;

    // Puis le sceau est **recalculé** — exactement ce que ferait un adversaire
    // actif, et exactement ce contre quoi un BLAKE3 nu ne protège pas.
    let empreinte = blake3::hash(&falsifie[..debut_du_sceau]);
    let fin = falsifie.len();
    falsifie[fin - 32..].copy_from_slice(empreinte.as_bytes());

    // Le sceau repasse au vert : l'import accepte.
    let cible = atelier.path().join("falsifie");
    Vault::import(&mut &falsifie[..], &cible, vault_core::ImportPolicy::Refuse)
        .expect("le sceau recalculé passe : c'est précisément sa limite");

    // Mais l'authenticité, elle, ne se falsifie pas : les tags AEAD refusent au
    // déverrouillage, ou l'index devient illisible.
    let ouverture = Vault::open(&cible).and_then(|vault| vault.unlock(passphrase()));
    let verdict = match ouverture {
        Ok(session) => session.verify_content().map(|_| ()),
        Err(erreur) => Err(erreur),
    };
    assert!(
        matches!(verdict, Err(Error::Authentication | Error::Corrupted)),
        "la falsification doit être vue au déverrouillage : {verdict:?}"
    );
}
