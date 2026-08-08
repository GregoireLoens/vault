//! Indiscernabilité des erreurs (T052, SC-006, FR-040).
//!
//! FR-040 exige qu'une passphrase erronée et un vault altéré soient
//! **indiscernables**. C'est une exigence sur la sortie, pas sur le code : deux
//! messages différents suffiraient à donner à un attaquant hors ligne un
//! oracle lui indiquant quelle partie de sa tentative a échoué — et donc à lui
//! confirmer qu'une passphrase essayée était la bonne sur un vault qu'il a
//! lui-même altéré.
//!
//! La comparaison est donc faite **octet pour octet** sur le rendu complet de
//! l'erreur, affichage et `Debug` compris. Comparer les variants ne suffirait
//! pas : deux occurrences du même variant pourraient porter des données
//! différentes, et c'est le texte qui atteint l'utilisateur.
//!
//! # La frontière, énoncée plutôt que masquée
//!
//! Un fichier qui n'est **pas** un en-tête de vault donne [`Error::Corrupted`],
//! discernable d'`Authentication`. C'est délibéré (C-024) : le dire ne
//! renseigne personne sur la passphrase, puisqu'aucune passphrase n'a été
//! essayée. La dernière fonction de ce fichier pose cette frontière
//! explicitement.

use std::path::{Path, PathBuf};

use vault_core::{Error, KdfParams, SecretString, Vault};

fn params() -> KdfParams {
    KdfParams::new(64, 1, 1).expect("paramètres valides")
}

fn passphrase() -> SecretString {
    SecretString::from("passphrase de test bien assez longue".to_owned())
}

/// Crée un vault vide et le referme.
fn coffre_neuf(atelier: &Path) -> PathBuf {
    let coffre = atelier.join("coffre");
    Vault::create(&coffre, passphrase(), params())
        .expect("créable")
        .lock();
    coffre
}

/// Rendu complet d'une erreur, tel qu'il peut atteindre l'utilisateur.
fn rendu(erreur: &Error) -> Vec<u8> {
    format!("{erreur}\u{1f}{erreur:?}").into_bytes()
}

/// Tente d'ouvrir le vault et rend le rendu de l'erreur obtenue.
fn echec(coffre: &Path, passphrase: SecretString) -> Vec<u8> {
    let erreur = Vault::open(coffre)
        .and_then(|vault| vault.unlock(passphrase))
        .expect_err("l'ouverture devait échouer");
    rendu(&erreur)
}

/// SC-006, FR-040 : le rendu d'une passphrase erronée et celui d'un en-tête
/// altéré sont **identiques, octet pour octet**.
///
/// Le balayage porte sur toutes les positions de l'en-tête. Celles qui
/// produisent `Corrupted` ou `UnsupportedFormatVersion` sont écartées : ce sont
/// les altérations qui empêchent de reconnaître un vault, avant toute
/// tentative d'authentification. Toutes les autres doivent rendre exactement ce
/// que rend une passphrase fausse.
#[test]
fn une_passphrase_erronee_et_un_en_tete_altere_rendent_les_memes_octets() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_neuf(atelier.path());
    let en_tete = coffre.join("header");
    let original = std::fs::read(&en_tete).expect("lisible");

    let reference = echec(
        &coffre,
        SecretString::from("une passphrase parfaitement fausse".to_owned()),
    );

    let mut compares = 0usize;
    let mut verdicts = Vec::new();
    for position in 0..original.len() {
        let mut altere = original.clone();
        altere[position] ^= 0x01;
        std::fs::write(&en_tete, &altere).expect("écrivable");

        let erreur = Vault::open(&coffre)
            .and_then(|vault| vault.unlock(passphrase()))
            .expect_err("l'ouverture devait échouer");

        if matches!(erreur, Error::Authentication) {
            compares += 1;
            verdicts.push(rendu(&erreur) == reference);
        }
    }
    std::fs::write(&en_tete, &original).expect("écrivable");

    assert!(
        compares > 0,
        "aucune altération n'a mené jusqu'à l'authentification"
    );
    assert_eq!(
        verdicts,
        vec![true; compares],
        "{compares} positions comparées"
    );
}

/// Un index altéré est lui aussi indiscernable d'une passphrase erronée. Il
/// n'est pourtant découvert qu'**après** le désenveloppement réussi de la clé
/// maîtresse : c'est le cas où un message trop précis trahirait qu'une
/// passphrase essayée était la bonne.
#[test]
fn un_index_altere_rend_les_memes_octets_qu_une_passphrase_erronee() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_neuf(atelier.path());
    let index = coffre.join("index");
    let original = std::fs::read(&index).expect("lisible");

    let reference = echec(
        &coffre,
        SecretString::from("une passphrase parfaitement fausse".to_owned()),
    );

    let verdicts: Vec<bool> = (0..original.len())
        .map(|position| {
            let mut altere = original.clone();
            altere[position] ^= 0x01;
            std::fs::write(&index, &altere).expect("écrivable");
            echec(&coffre, passphrase()) == reference
        })
        .collect();
    std::fs::write(&index, &original).expect("écrivable");

    assert_eq!(verdicts, vec![true; original.len()]);
}

/// La longueur de la passphrase essayée ne transparaît pas davantage : une
/// tentative d'un caractère et une tentative de mille rendent le même texte.
///
/// FR-005 exige douze caractères à la *création* ; une tentative plus courte
/// est refusée comme n'importe quelle autre passphrase fausse, et non par un
/// message sur la longueur, qui renseignerait sur le secret attendu.
#[test]
fn la_longueur_de_la_passphrase_essayee_ne_transparait_pas() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_neuf(atelier.path());

    let tentatives = [
        "x".to_owned(),
        "onze carac".to_owned(),
        "passphrase de test bien assez longu".to_owned(),
        "x".repeat(1000),
    ];

    let rendus: Vec<Vec<u8>> = tentatives
        .into_iter()
        .map(|tentative| echec(&coffre, SecretString::from(tentative)))
        .collect();

    let premier = rendus.first().expect("au moins une tentative").clone();
    assert_eq!(rendus, vec![premier; 4]);
}

/// La frontière, énoncée : un fichier qui n'est pas un en-tête de vault se
/// distingue, et c'est voulu. Aucune passphrase n'a été essayée, donc rien
/// n'est appris sur elle.
#[test]
fn ce_qui_n_est_pas_un_vault_se_distingue_et_c_est_delibere() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_neuf(atelier.path());

    let reference = echec(
        &coffre,
        SecretString::from("une passphrase parfaitement fausse".to_owned()),
    );

    std::fs::write(coffre.join("header"), b"ceci n'est pas un en-tete").expect("écrivable");
    let corrompu = Vault::open(&coffre).expect_err("refus attendu");

    assert!(matches!(corrompu, Error::Corrupted));
    assert_ne!(rendu(&corrompu), reference);
}
