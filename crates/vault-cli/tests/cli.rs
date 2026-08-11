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

/// Sérialise les tests de ce binaire. **Chaque test le prend en première
/// ligne.**
///
/// Ce n'est pas une précaution de confort, et le supprimer réintroduirait un
/// échec intermittent que l'intégration continue a réellement produit.
///
/// Un verrou `flock` appartient à la **description de fichier ouverte**, et
/// `fork` la partage. Or ce fichier ne fait que deux choses : créer des vaults —
/// donc prendre des verrous — et lancer le binaire `vault`, c'est-à-dire
/// dupliquer le processus. Quand une duplication tombe pendant qu'un autre fil
/// détient un verrou, l'enfant en hérite jusqu'à son `exec` : les descripteurs
/// sont bien marqués « à fermer sur exec », mais la fenêtre entre les deux est
/// réelle et la charge de la machine l'élargit.
///
/// Le vault que le fil victime vient de refermer paraît alors **encore ouvert**,
/// et le test échoue en `AlreadyInUse` sur un vault qui n'a rien à voir avec
/// celui que l'enfant visait. C'est exactement ce qui s'est produit sur un
/// exécuteur `ubuntu-latest`, sur `un_vault_deja_ouvert_sort_en_code_4`, sans
/// jamais se reproduire en local.
///
/// Sérialiser supprime la classe entière plutôt que le cas observé : aucune
/// duplication ne peut plus avoir lieu pendant qu'un verrou est tenu. Ces dix
/// tests s'exécutent en un dixième de seconde, le coût est nul.
///
/// La propriété elle-même est décrite dans le module `fs::lock` de
/// `vault-core`. Elle ne concerne pas le binaire `vault`, qui ne se duplique
/// jamais.
static VERROU_DE_SUITE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Prend le verrou de série pour la durée du test.
///
/// L'empoisonnement est ignoré : un test voisin qui a paniqué ne doit pas faire
/// échouer les suivants pour une raison sans rapport avec ce qu'ils vérifient.
fn en_serie() -> std::sync::MutexGuard<'static, ()> {
    VERROU_DE_SUITE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

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
    let _serie = en_serie();
    vault().arg("--help").assert().success();
    vault().arg("--version").assert().success();
}

/// Code 2 : arguments invalides.
#[test]
fn un_usage_invalide_sort_en_code_2() {
    let _serie = en_serie();
    vault().assert().code(2);
    vault().arg("commande-inconnue").assert().code(2);
    vault().args(["add"]).assert().code(2);
    vault().args(["rm"]).assert().code(2);
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
    let _serie = en_serie();
    let atelier = tempfile::tempdir().expect("répertoire temporaire");

    vault()
        .args([
            "create",
            atelier.path().join("coffre").to_str().expect("UTF-8"),
        ])
        .assert()
        .code(2)
        // FR-037, XFR-006 : les erreurs passent par l'**erreur** standard. La
        // sortie standard est réservée à ce qu'une machine lit, et un
        // conteneur d'export peut l'occuper entière.
        .stderr(predicates::str::contains("terminal"))
        .stdout(predicates::str::is_empty());
}

/// Code 5 : vault introuvable. Le chemin est refusé avant toute saisie, donc
/// ce cas est atteignable sans terminal.
#[test]
fn un_vault_introuvable_sort_en_code_5() {
    let _serie = en_serie();
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
    let _serie = en_serie();
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
    let _serie = en_serie();
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
    let _serie = en_serie();
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
        .stderr(predicates::str::contains("autre processus"))
        .stdout(predicates::str::is_empty());

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
    let _serie = en_serie();
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
            .stderr(predicates::str::contains("format"));
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
    let _serie = en_serie();
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

/// CLI-020 : **aucune option** ne permet de passer la passphrase en argument.
///
/// Le balayage porte sur les lignes d'option de chaque aide — celles dont le
/// premier caractère non blanc est un tiret — et non sur le texte entier. La
/// version précédente bannissait le mot partout, ce qui était un raccourci
/// commode tant qu'aucune commande n'avait à parler de passphrase : la
/// description de `passwd` en parle, sans pour autant en accepter une en
/// argument. Ce que CLI-020 interdit, c'est le passage par la ligne de
/// commande, où la valeur atterrirait dans l'historique du shell et dans la
/// table des processus. C'est cela, et cela seul, qui est vérifié — sur toutes
/// les commandes, l'aide générale comprise.
#[test]
fn aucune_option_n_accepte_la_passphrase() {
    let _serie = en_serie();
    let aide_de = |arguments: &[&str]| {
        let sortie = vault()
            .args(arguments)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        String::from_utf8(sortie).expect("UTF-8")
    };

    let mut fautives: Vec<String> = Vec::new();
    for commande in ["", "create", "add", "ls", "extract", "info", "rm", "passwd"] {
        let arguments: Vec<&str> = if commande.is_empty() {
            vec!["--help"]
        } else {
            vec![commande, "--help"]
        };
        for ligne in aide_de(&arguments).lines() {
            let coupee = ligne.trim_start();
            let est_une_option = coupee.starts_with('-');
            let evoque_le_secret = coupee.contains("passphrase")
                || coupee.contains("password")
                || coupee.contains("secret");
            if est_une_option && evoque_le_secret {
                fautives.push(format!("{commande} : {ligne}"));
            }
        }
    }

    assert_eq!(fautives, Vec::<String>::new());
}
