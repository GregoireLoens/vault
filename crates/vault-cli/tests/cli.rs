//! Contrat de la ligne de commande — T050.
//!
//! Ces tests exercent le **binaire**, à travers un processus réel. Ils ne
//! peuvent donc pas fournir de terminal : c'est précisément ce qui rend
//! CLI-022 vérifiable ici, et ce qui limite ces tests aux chemins qui ne
//! demandent aucune saisie. Les dialogues eux-mêmes sont vérifiés par les tests
//! unitaires du crate, qui pilotent une console scriptée.

use assert_cmd::Command;

fn vault() -> Command {
    Command::cargo_bin("vault").expect("le binaire vault doit être construit")
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

    for commande in ["create", "add", "ls", "extract"] {
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
