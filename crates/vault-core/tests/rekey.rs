//! Changement de passphrase (T061, FR-033 à FR-035).
//!
//! Trois exigences, dont une seule demande un montage particulier.
//!
//! **FR-033, FR-034 — le contenu n'est ni déchiffré ni rechiffré.** La clé
//! maîtresse est tirée du CSPRNG et enveloppée par une clé dérivée de la
//! passphrase (D-004) ; changer de passphrase ne touche donc qu'à l'enveloppe.
//! L'affirmation se vérifie exactement : **tous les fichiers du vault sauf
//! `header` sont identiques octet pour octet avant et après**. Un test qui se
//! contenterait de relire le contenu ne distinguerait pas une opération qui
//! aurait tout rechiffré à l'identique.
//!
//! **FR-035 — une interruption ne rend jamais le vault inutilisable.** Cette
//! exigence-là ne se prouve pas en appelant une fonction : elle porte sur ce
//! qui reste quand le processus meurt. Elle a son propre binaire de test,
//! `rekey_interruption.rs`, qui explique aussi pourquoi il doit rester seul.
//!
//! Ce qui se vérifie ici est la face déterministe de C-022 : tout échec en
//! cours d'opération — dérivation refusée, écriture impossible — laisse
//! l'ancienne passphrase valide et l'en-tête du disque intact.

use std::path::{Path, PathBuf};

use vault_core::{AddMode, Error, KdfParams, OnConflict, SecretString, Vault, VaultPath};

const ANCIENNE: &str = "passphrase de test bien assez longue";
const NOUVELLE: &str = "une toute autre passphrase, tout aussi longue";

fn params() -> KdfParams {
    KdfParams::new(64, 1, 1).expect("paramètres valides")
}

fn secret(texte: &str) -> SecretString {
    SecretString::from(texte.to_owned())
}

fn chemin(nom: &str) -> VaultPath {
    VaultPath::from_components([nom.as_bytes().to_vec()]).expect("chemin valide")
}

/// Contenu déterministe.
fn contenu(taille: usize) -> Vec<u8> {
    (0..taille)
        .map(|index| u8::try_from(index % 251).expect("reste inférieur à 251"))
        .collect()
}

/// Crée un vault peuplé et le referme.
fn coffre_peuple(atelier: &Path) -> PathBuf {
    let coffre = atelier.join("coffre");
    let source = atelier.join("source");
    std::fs::create_dir_all(&source).expect("créable");

    let mut vault = Vault::create(&coffre, secret(ANCIENNE), params()).expect("créable");
    for (nom, taille) in [("note.txt", 300), ("gros.bin", 70_000)] {
        let fichier = source.join(nom);
        std::fs::write(&fichier, contenu(taille)).expect("écrivable");
        vault
            .add_file(&fichier, &chemin(nom), AddMode::Copy, OnConflict::Fail)
            .expect("ajoutable");
    }
    vault.lock();
    coffre
}

/// Empreinte de tous les fichiers du vault **sauf** `header`, contenu compris.
///
/// C'est l'instrument de C-021 : ce qui n'est pas l'en-tête ne doit pas bouger
/// d'un octet.
fn empreinte_hors_en_tete(coffre: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut fichiers: Vec<(PathBuf, Vec<u8>)> = walkdir::WalkDir::new(coffre)
        .sort_by_file_name()
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entree| entree.file_type().is_file())
        .filter(|entree| entree.file_name() != "header")
        // Le fichier support du verrou est vide et sans rapport avec le format.
        .filter(|entree| entree.file_name() != ".lock")
        .map(|entree| {
            let relatif = entree
                .path()
                .strip_prefix(coffre)
                .expect("sous la racine")
                .to_path_buf();
            (relatif, std::fs::read(entree.path()).expect("lisible"))
        })
        .collect();
    fichiers.sort();
    fichiers
}

/// Ouvre le vault avec cette passphrase, si elle convient.
fn ouvre_avec(coffre: &Path, passphrase: &str) -> bool {
    Vault::open(coffre)
        .expect("ouvrable")
        .unlock(secret(passphrase))
        .is_ok()
}

/// Déverrouille, ou échoue en disant **quel** vault et **pourquoi**.
fn deverrouille(coffre: &Path, passphrase: &str) -> vault_core::UnlockedVault {
    Vault::open(coffre)
        .expect("ouvrable")
        .unlock(secret(passphrase))
        .unwrap_or_else(|erreur| panic!("déverrouillage de {} : {erreur:?}", coffre.display()))
}

/// FR-033, FR-034, C-021 : l'ancienne passphrase est refusée, la nouvelle donne
/// accès à un contenu intact, et **rien d'autre que l'en-tête n'a changé**.
#[test]
fn le_contenu_est_intact_et_seul_l_en_tete_a_change() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_peuple(atelier.path());
    let avant = empreinte_hors_en_tete(&coffre);
    let en_tete_avant = std::fs::read(coffre.join("header")).expect("lisible");

    let mut session = deverrouille(&coffre, ANCIENNE);
    session
        .change_passphrase(secret(NOUVELLE), None)
        .expect("changeable");
    session.lock();

    assert_eq!(
        empreinte_hors_en_tete(&coffre),
        avant,
        "seul l'en-tête doit avoir changé"
    );
    assert_ne!(
        std::fs::read(coffre.join("header")).expect("lisible"),
        en_tete_avant,
        "l'en-tête, lui, a bien changé"
    );

    assert!(!ouvre_avec(&coffre, ANCIENNE), "l'ancienne est refusée");

    let session = Vault::open(&coffre)
        .expect("ouvrable")
        .unlock(secret(NOUVELLE))
        .expect("la nouvelle ouvre");
    let sortie = atelier.path().join("sortie");
    std::fs::create_dir(&sortie).expect("créable");
    for (nom, taille) in [("note.txt", 300), ("gros.bin", 70_000)] {
        session
            .extract(&chemin(nom), &sortie, OnConflict::Replace)
            .expect("extractible");
        assert_eq!(
            std::fs::read(sortie.join(nom)).expect("lisible"),
            contenu(taille),
            "{nom}"
        );
    }
}

/// C-023 : les paramètres de coût se relèvent au passage, et l'en-tête les
/// publie.
#[test]
fn les_parametres_de_cout_se_relevent_au_passage() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_peuple(atelier.path());
    let releves = KdfParams::new(128, 2, 1).expect("valides");

    let mut session = deverrouille(&coffre, ANCIENNE);
    session
        .change_passphrase(secret(NOUVELLE), Some(releves))
        .expect("changeable");
    assert_eq!(session.kdf_params(), releves);
    session.lock();

    let verrouille = Vault::open(&coffre).expect("ouvrable");
    assert_eq!(verrouille.kdf_params(), releves);
    assert!(verrouille.unlock(secret(NOUVELLE)).is_ok());
}

/// Sans paramètres, ceux du vault sont conservés : changer de passphrase ne
/// doit pas rabaisser silencieusement un coût que l'utilisateur avait relevé.
#[test]
fn sans_parametres_ceux_du_vault_sont_conserves() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = atelier.path().join("coffre");
    let eleves = KdfParams::new(256, 2, 1).expect("valides");
    Vault::create(&coffre, secret(ANCIENNE), eleves)
        .expect("créable")
        .lock();

    let mut session = deverrouille(&coffre, ANCIENNE);
    session
        .change_passphrase(secret(NOUVELLE), None)
        .expect("changeable");
    session.lock();

    assert_eq!(
        Vault::open(&coffre).expect("ouvrable").kdf_params(),
        eleves,
        "les paramètres du vault sont conservés"
    );
}

/// Un temporaire abandonné par un processus tué ne gêne pas l'ouverture : il
/// n'est référencé par rien, et `Vault::open` ne lit que `header`.
///
/// Le résidu est déposé à la main plutôt qu'en tuant un processus : ce test n'a
/// donc rien à faire dans `rekey_interruption.rs`, dont l'en-tête explique
/// pourquoi aucun autre test ne peut y cohabiter.
#[test]
fn un_temporaire_abandonne_n_empeche_pas_d_ouvrir() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_peuple(atelier.path());

    std::fs::write(coffre.join(".vault-tmp-abandonne"), b"residu").expect("écrivable");

    assert!(ouvre_avec(&coffre, ANCIENNE));
}

/// FR-005, C-001 : le minimum de longueur vaut aussi au changement, et le refus
/// arrive **avant** toute écriture — l'ancienne passphrase ouvre toujours.
#[test]
fn une_nouvelle_passphrase_trop_courte_est_refusee_sans_rien_ecrire() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_peuple(atelier.path());
    let en_tete_avant = std::fs::read(coffre.join("header")).expect("lisible");

    let mut session = deverrouille(&coffre, ANCIENNE);
    assert!(matches!(
        session.change_passphrase(secret("onze carac"), None),
        Err(Error::WeakPassphrase { minimum: 12 })
    ));
    session.lock();

    assert_eq!(
        std::fs::read(coffre.join("header")).expect("lisible"),
        en_tete_avant,
        "l'en-tête n'a pas été touché"
    );
    assert!(ouvre_avec(&coffre, ANCIENNE));
}
