//! Contrat de la ligne de commande — T050, T057.
//!
//! Ces tests exercent le **binaire**, à travers un processus réel. Ils ne
//! peuvent donc pas fournir de terminal : c'est précisément ce qui rend
//! CLI-022 vérifiable ici, et ce qui limite ces tests aux chemins qui ne
//! demandent aucune saisie. Les dialogues eux-mêmes sont vérifiés par les tests
//! unitaires du crate, qui pilotent une console scriptée.

use std::path::{Path, PathBuf};

use assert_cmd::Command;

const PASSPHRASE: &str = "une passphrase bien assez longue";

fn vault() -> Command {
    Command::cargo_bin("vault").expect("le binaire vault doit être construit")
}

/// Crée un vault refermé et rend son emplacement.
///
/// Passe par la bibliothèque plutôt que par le binaire : la création exige une
/// confirmation littérale et une passphrase, donc un terminal.
fn coffre_neuf(atelier: &Path) -> PathBuf {
    let coffre = atelier.join("coffre");
    vault_core::Vault::create(
        &coffre,
        vault_core::SecretString::from(PASSPHRASE.to_owned()),
        vault_core::KdfParams::new(64, 1, 1).expect("valides"),
    )
    .expect("créable")
    .lock();
    coffre
}

fn en_texte(chemin: &Path) -> &str {
    chemin.to_str().expect("UTF-8")
}

/// Code 0 : une commande qui ne demande rien aboutit.
#[test]
fn l_aide_sort_en_succes() {
    vault().arg("--help").assert().success();
    vault().arg("--version").assert().success();
}

/// Code 2 : arguments invalides.
#[test]
fn un_usage_invalide_sort_en_code_2() {
    vault().assert().code(2);
    vault().arg("commande-inconnue").assert().code(2);
    vault().args(["add"]).assert().code(2);
    vault().args(["extract", "x"]).assert().code(2);
    vault()
        .args(["add", "--move", "--copy", "fichier"])
        .assert()
        .code(2);
    vault()
        .args(["add", "--on-conflict", "autre", "fichier"])
        .assert()
        .code(2);
}

/// CLI-022 : sur un terminal non interactif, une commande exigeant une saisie
/// échoue en code 2 plutôt que de supposer une réponse.
#[test]
fn sans_terminal_une_saisie_exigee_sort_en_code_2() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");

    vault()
        .args([
            "create",
            atelier.path().join("coffre").to_str().expect("UTF-8"),
        ])
        .assert()
        .code(2)
        .stdout(predicates::str::contains("terminal"));
}

/// Code 5 : vault introuvable. Le chemin est refusé avant toute saisie, donc
/// ce cas est atteignable sans terminal.
#[test]
fn un_vault_introuvable_sort_en_code_5() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");

    vault()
        .args([
            "ls",
            "--vault",
            atelier.path().join("nulle-part").to_str().expect("UTF-8"),
        ])
        .assert()
        .code(5);
}

/// Code 6 : espace insuffisant. Il n'est pas atteignable sans terminal, la
/// commande demandant la passphrase avant de vérifier la place ; le code lui-
/// même est vérifié par les tests unitaires de `error.rs` et de `cmd/extract.rs`.
///
/// Ce test consigne cette limite plutôt que de la passer sous silence, et
/// vérifie ce qui l'est : que la commande refuse bien la saisie plutôt que de
/// supposer une réponse.
#[test]
fn l_espace_insuffisant_n_est_pas_atteignable_sans_terminal() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");

    vault()
        .args([
            "extract",
            "x",
            "--to",
            atelier.path().to_str().expect("UTF-8"),
            "--vault",
            atelier.path().to_str().expect("UTF-8"),
        ])
        .assert()
        .code(5);
}

/// Code 0 : `vault info` aboutit **sans terminal**, parce qu'il ne demande
/// aucune saisie (CLI-018). C'est la seule commande dans ce cas.
#[test]
fn l_information_publique_s_obtient_sans_terminal() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_neuf(atelier.path());

    vault()
        .args(["info", "--vault", en_texte(&coffre)])
        .assert()
        .success()
        .stdout(predicates::str::contains("argon2id"))
        .stdout(predicates::str::contains("xchacha20poly1305"));
}

/// Code 4 : le vault est déjà ouvert par une autre instance (FR-012).
///
/// Le verrou est tenu par ce processus de test, qui joue l'autre instance. Le
/// refus est prononcé **avant** la demande de passphrase : c'est ce qui le
/// rend observable ici, et ce qui évite à l'utilisateur une saisie qui ne
/// pouvait pas aboutir.
#[test]
fn un_vault_deja_ouvert_sort_en_code_4() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_neuf(atelier.path());

    let session = vault_core::Vault::open(&coffre)
        .expect("ouvrable")
        .unlock(vault_core::SecretString::from(PASSPHRASE.to_owned()))
        .expect("déverrouillable");

    vault()
        .args(["ls", "--vault", en_texte(&coffre)])
        .assert()
        .code(4)
        .stdout(predicates::str::contains("autre processus"));

    // Le verrou rendu, la commande retombe sur son refus ordinaire de saisie.
    session.lock();
    vault()
        .args(["ls", "--vault", en_texte(&coffre)])
        .assert()
        .code(2);
}

/// Code 7 : version de format non gérée (VR-H1).
///
/// L'en-tête est patché sur son seul champ `format_version`, laissé en clair
/// par le format. Le refus intervient au décodage, avant toute passphrase.
#[test]
fn une_version_de_format_inconnue_sort_en_code_7() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_neuf(atelier.path());
    let en_tete = coffre.join("header");

    let mut octets = std::fs::read(&en_tete).expect("lisible");
    let cle = b"format_version";
    let position = octets
        .windows(cle.len())
        .position(|fenetre| fenetre == cle)
        .expect("le champ figure dans l'en-tête")
        + cle.len();
    assert_eq!(octets[position], 1, "la version courante est 1");
    octets[position] = 2;
    std::fs::write(&en_tete, &octets).expect("écrivable");

    for commande in ["info", "ls"] {
        vault()
            .args([commande, "--vault", en_texte(&coffre)])
            .assert()
            .code(7)
            .stdout(predicates::str::contains("format"));
    }
}

/// Code 3 : échec d'authentification.
///
/// **Il n'est pas atteignable depuis un processus sans terminal**, et ce test
/// consigne la limite plutôt que de la passer sous silence : le code 3 suppose
/// une tentative de déverrouillage, donc une passphrase, que CLI-001 interdit
/// de recevoir autrement que par une saisie masquée.
///
/// Ce qui est vérifiable ici l'est : un vault dont l'en-tête est altéré ne
/// **renseigne pas davantage** qu'un vault intact avant la saisie — les deux
/// s'arrêtent au même refus, avec le même code et le même message. L'égalité
/// octet pour octet des deux causes du code 3, elle, est vérifiée par le test
/// `le_code_3_est_indiscernable_de_ses_deux_causes` du crate, qui pilote une
/// console scriptée.
#[test]
fn le_code_3_n_est_pas_atteignable_sans_terminal() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_neuf(atelier.path());

    let intact = vault()
        .args(["ls", "--vault", en_texte(&coffre)])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();

    // Le sel est altéré : le vault ne s'ouvrirait plus avec sa passphrase.
    let en_tete = coffre.join("header");
    let mut octets = std::fs::read(&en_tete).expect("lisible");
    let cle = b"kdf_salt";
    let position = octets
        .windows(cle.len())
        .position(|fenetre| fenetre == cle)
        .expect("le champ figure dans l'en-tête")
        + cle.len()
        + 2;
    octets[position] ^= 0x01;
    std::fs::write(&en_tete, &octets).expect("écrivable");

    let altere = vault()
        .args(["ls", "--vault", en_texte(&coffre)])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();

    assert_eq!(
        altere, intact,
        "l'altération ne doit rien changer à ce qui précède la saisie"
    );
}

/// CLI-020 : aucune option ne permet de passer la passphrase en argument.
#[test]
fn aucune_option_n_accepte_la_passphrase() {
    let aide = vault()
        .arg("--help")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let aide = String::from_utf8(aide).expect("UTF-8");
    assert!(!aide.contains("passphrase"), "aide : {aide}");

    for commande in ["create", "add", "ls", "extract", "info"] {
        let aide = vault()
            .args([commande, "--help"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let aide = String::from_utf8(aide).expect("UTF-8");
        assert!(
            !aide.contains("--passphrase") && !aide.contains("--password"),
            "{commande} : {aide}"
        );
    }
}
