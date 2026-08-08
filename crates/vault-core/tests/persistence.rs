//! Persistance entre processus (T053).
//!
//! Le test indépendant de la user story 2 énonce : « créer un vault, y déposer
//! du contenu, **terminer le processus**, rouvrir et vérifier l'identité du
//! contenu ». Refermer une session dans le même processus ne le vérifierait
//! pas : l'index resterait en mémoire, le verrou dans le même descripteur, et
//! rien ne prouverait que ce qui a été relu vient du disque.
//!
//! Cette suite lance donc de vrais processus auxiliaires. Le binaire de test se
//! réinvoque lui-même sur [`processus_auxiliaire`], avec un rôle transmis par
//! l'environnement — le seul moyen portable de disposer d'un second processus
//! sans dépendre d'un binaire tiers, ni d'un shell, ni du système hôte.
//!
//! Trois propriétés en découlent, qu'aucun test intra-processus n'établit :
//!
//! - le contenu relu est identique à celui d'avant, **octet pour octet** ;
//! - le verrou est rendu par la **fin du processus**, et non par un appel de
//!   fermeture qu'un arrêt brutal pourrait sauter ;
//! - les deux processus n'échangent que l'emplacement du vault et la
//!   passphrase — jamais un état déchiffré.

use std::path::{Path, PathBuf};

use vault_core::{AddMode, EntryKind, KdfParams, OnConflict, SecretString, Vault, VaultPath};

/// Sérialise les tests de ce binaire. **Chaque test qui lance un processus
/// auxiliaire le prend en première ligne.**
///
/// Un verrou `flock` appartient à la description de fichier ouverte, et `fork`
/// la partage : dupliquer le processus pendant qu'un autre fil détient le
/// verrou d'un vault en lègue une copie à l'enfant jusqu'à son `exec`. Le vault
/// qu'un fil vient de refermer paraît alors encore ouvert, et un test échoue en
/// `AlreadyInUse` sur un vault sans rapport avec celui que l'enfant visait.
///
/// Ce fichier réunit précisément les deux ingrédients : `relire` déverrouille
/// dans le processus de test, et trois tests lancent des processus. Sérialiser
/// supprime la classe entière. Le module `fs::lock` décrit la propriété ; la
/// même précaution vaut dans `vault-cli/tests/cli.rs`, où elle a été prise
/// après un échec réel de l'intégration continue.
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

/// Rôle du processus auxiliaire, transmis par l'environnement.
const ROLE: &str = "VAULT_TEST_PERSISTANCE_ROLE";
/// Répertoire de travail, transmis par l'environnement.
const ATELIER: &str = "VAULT_TEST_PERSISTANCE_ATELIER";

fn params() -> KdfParams {
    KdfParams::new(64, 1, 1).expect("paramètres valides")
}

fn passphrase() -> SecretString {
    SecretString::from("passphrase de test bien assez longue".to_owned())
}

/// Corpus déterministe.
///
/// Les deux processus le reconstituent chacun de leur côté : rien de ce qui est
/// comparé ne transite entre eux, ce qui est précisément ce qui donne sa valeur
/// à la comparaison.
fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("note.txt", b"une note qui doit survivre".to_vec()),
        ("vide.bin", Vec::new()),
        (
            "gros.bin",
            (0..70_000u32)
                .map(|index| u8::try_from(index % 251).expect("reste inférieur à 251"))
                .collect(),
        ),
        (
            "accentué.txt",
            "été à la plage — ç, ù, ï\n".as_bytes().to_vec(),
        ),
    ]
}

fn chemin(nom: &str) -> VaultPath {
    VaultPath::from_components([nom.as_bytes().to_vec()]).expect("chemin valide")
}

/// Premier processus : crée le vault, y dépose le corpus, et s'arrête.
fn creer(atelier: &Path) {
    let source = atelier.join("source");
    std::fs::create_dir_all(&source).expect("créable");

    let mut vault =
        Vault::create(&atelier.join("coffre"), passphrase(), params()).expect("créable");

    for (nom, contenu) in corpus() {
        let fichier = source.join(nom);
        std::fs::write(&fichier, &contenu).expect("écrivable");
        vault
            .add_file(&fichier, &chemin(nom), AddMode::Copy, OnConflict::Fail)
            .expect("ajoutable");
    }

    assert_eq!(vault.list(None).len(), corpus().len());
    // Aucune fermeture explicite : c'est la fin du processus qui doit rendre le
    // verrou et faire disparaître les secrets.
    std::mem::forget(vault);
}

/// Second processus : rouvre le vault et vérifie que tout y est.
fn relire(atelier: &Path) {
    let coffre = atelier.join("coffre");
    let sortie = atelier.join("sortie");
    std::fs::create_dir_all(&sortie).expect("créable");

    let vault = Vault::open(&coffre)
        .expect("ouvrable par un autre processus")
        .unlock(passphrase())
        .expect("le verrou a été rendu par la fin du premier processus");

    assert_eq!(vault.list(None).len(), corpus().len());

    for (nom, contenu) in corpus() {
        let entree = vault.stat(&chemin(nom)).expect("présente");
        assert_eq!(entree.kind, EntryKind::File);
        assert_eq!(entree.size, Some(contenu.len() as u64), "{nom}");

        vault
            .extract(&chemin(nom), &sortie, OnConflict::Replace)
            .expect("extractible");
        assert_eq!(
            std::fs::read(sortie.join(nom)).expect("lisible"),
            contenu,
            "{nom} a changé entre les deux processus"
        );
    }
}

/// Point d'entrée des processus auxiliaires.
///
/// Sans rôle dans l'environnement — c'est-à-dire lors d'une exécution
/// ordinaire de la suite — ce test ne fait rien.
#[test]
fn processus_auxiliaire() {
    let Ok(role) = std::env::var(ROLE) else {
        return;
    };
    let atelier = PathBuf::from(std::env::var(ATELIER).expect("atelier transmis"));

    if role == "creer" {
        creer(&atelier);
    } else {
        relire(&atelier);
    }
}

/// Lance un processus auxiliaire et rend vrai s'il a abouti.
fn auxiliaire(role: &str, atelier: &Path) -> bool {
    std::process::Command::new(std::env::current_exe().expect("binaire de test"))
        .args(["processus_auxiliaire", "--exact", "--nocapture"])
        .env(ROLE, role)
        .env(ATELIER, atelier)
        .status()
        .expect("processus lançable")
        .success()
}

/// Le contenu survit à la fin du processus qui l'a déposé.
#[test]
fn le_contenu_survit_a_la_fin_du_processus() {
    let _serie = en_serie();
    let atelier = tempfile::tempdir().expect("répertoire temporaire");

    assert!(auxiliaire("creer", atelier.path()), "création");
    assert!(auxiliaire("relire", atelier.path()), "relecture");

    // Un troisième processus — celui-ci — relit à son tour : la relecture n'a
    // rien consommé, et le vault reste ouvrable indéfiniment.
    relire(atelier.path());
}

/// VR-S4 : le verrou est rendu par la fin du processus, sans fermeture
/// explicite. Le premier processus s'arrête en ayant délibérément oublié sa
/// session ; le second doit tout de même pouvoir ouvrir.
#[test]
fn le_verrou_ne_survit_pas_au_processus_qui_le_tenait() {
    let _serie = en_serie();
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    assert!(auxiliaire("creer", atelier.path()), "création");

    // Le fichier support du verrou subsiste — c'est le descripteur qui le
    // portait, et le noyau l'a fermé.
    assert!(atelier.path().join("coffre").join(".lock").exists());

    Vault::open(&atelier.path().join("coffre"))
        .expect("ouvrable")
        .unlock(passphrase())
        .expect("verrou libre");
}

/// Un vault refermé ne contient que ce que le format prévoit : rien n'a été
/// laissé en clair à côté, et aucun résidu de session ne subsiste.
#[test]
fn un_vault_referme_ne_contient_que_le_format() {
    let _serie = en_serie();
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    assert!(auxiliaire("creer", atelier.path()), "création");

    let mut noms: Vec<String> = std::fs::read_dir(atelier.path().join("coffre"))
        .expect("listable")
        .filter_map(std::result::Result::ok)
        .map(|entree| entree.file_name().to_string_lossy().into_owned())
        .collect();
    noms.sort();

    assert_eq!(
        noms,
        vec![
            ".lock".to_owned(),
            "header".to_owned(),
            "index".to_owned(),
            "objects".to_owned()
        ]
    );
}
