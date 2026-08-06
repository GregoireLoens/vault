//! Suite bloquante — absence de fuite en clair (T033, SC-003).
//!
//! Le principe I est la raison d'être du produit, et il est invérifiable à la
//! lecture du code au-delà d'une certaine taille. Cette suite le vérifie
//! mécaniquement : après une session d'utilisation représentative, elle balaie
//! **tout** ce que le vault a écrit sur le disque et cherche la moindre
//! occurrence d'un contenu, d'un nom d'origine ou d'un fragment d'arborescence.
//!
//! Le balayage porte sur les octets bruts de chaque fichier du vault, y compris
//! l'en-tête en clair, et sur les noms des fichiers eux-mêmes. Un test qui
//! n'inspecterait que `objects/` laisserait passer une fuite par l'index ou par
//! un temporaire oublié.

use std::path::Path;

use vault_core::{AddMode, KdfParams, OnConflict, SecretString, Vault, VaultPath};

/// Marqueurs choisis pour être introuvables par hasard : s'ils apparaissent
/// dans le vault, c'est qu'ils y ont été écrits en clair.
const CONTENU_SECRET: &[u8] = b"XYZZY-CONTENU-CONFIDENTIEL-A-NE-PAS-DIVULGUER";
const NOM_SECRET: &str = "PLOUGH-nom-de-fichier-revelateur.txt";
const DOSSIER_SECRET: &str = "FROTZ-dossier-revelateur";

fn params() -> KdfParams {
    KdfParams::new(64, 1, 1).expect("paramètres valides")
}

fn passphrase() -> SecretString {
    SecretString::from("passphrase de test bien assez longue".to_owned())
}

/// Tous les fichiers du vault, avec leur chemin relatif et leur contenu brut.
fn contenu_du_vault(racine: &Path) -> Vec<(String, Vec<u8>)> {
    walkdir::WalkDir::new(racine)
        .sort_by_file_name()
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entree| entree.file_type().is_file())
        .map(|entree| {
            let relatif = entree
                .path()
                .strip_prefix(racine)
                .expect("sous la racine")
                .to_string_lossy()
                .into_owned();
            (relatif, std::fs::read(entree.path()).expect("lisible"))
        })
        .collect()
}

fn contient(foin: &[u8], aiguille: &[u8]) -> bool {
    !aiguille.is_empty()
        && foin.len() >= aiguille.len()
        && foin.windows(aiguille.len()).any(|f| f == aiguille)
}

/// Mène une session représentative : création, ajout d'une arborescence, ajout
/// d'un fichier isolé, consultation. Renvoie le chemin du vault.
fn session_representative(atelier: &Path) -> std::path::PathBuf {
    let source = atelier.join("source");
    std::fs::create_dir_all(source.join(DOSSIER_SECRET)).expect("créable");
    std::fs::write(source.join(DOSSIER_SECRET).join(NOM_SECRET), CONTENU_SECRET)
        .expect("écrivable");
    std::fs::write(source.join("ordinaire.bin"), vec![0xab; 200_000]).expect("écrivable");

    let coffre = atelier.join("coffre");
    let mut vault = Vault::create(&coffre, passphrase(), params()).expect("vault créable");
    vault
        .add_dir(
            &source,
            &VaultPath::root(),
            AddMode::Copy,
            OnConflict::Fail,
            &mut |_| {},
        )
        .expect("ajoutable");

    let isole = atelier.join("isolé.txt");
    std::fs::write(&isole, CONTENU_SECRET).expect("écrivable");
    vault
        .add_file(
            &isole,
            &VaultPath::from_components([b"isole.txt".to_vec()]).expect("valide"),
            AddMode::Copy,
            OnConflict::Fail,
        )
        .expect("ajoutable");

    assert!(!vault.list(None).is_empty());
    vault.lock();
    coffre
}

/// SC-003 : aucun octet reconnaissable des données d'entrée n'apparaît dans le
/// répertoire du vault.
#[test]
fn aucun_contenu_ne_transparait() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = session_representative(atelier.path());

    for (nom, octets) in contenu_du_vault(&coffre) {
        assert!(
            !contient(&octets, CONTENU_SECRET),
            "contenu en clair dans {nom}"
        );
        assert!(
            !contient(&octets, NOM_SECRET.as_bytes()),
            "nom de fichier en clair dans {nom}"
        );
        assert!(
            !contient(&octets, DOSSIER_SECRET.as_bytes()),
            "nom de dossier en clair dans {nom}"
        );
    }
}

/// FR-036 : les noms des fichiers du vault ne révèlent rien non plus. Un blob
/// porte un identifiant aléatoire, sans rapport avec le nom réel.
#[test]
fn aucun_nom_de_fichier_ne_transparait() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = session_representative(atelier.path());

    let noms: Vec<String> = contenu_du_vault(&coffre)
        .into_iter()
        .map(|(nom, _)| nom)
        .collect();

    for nom in &noms {
        assert!(!nom.contains(NOM_SECRET), "nom révélateur : {nom}");
        assert!(!nom.contains(DOSSIER_SECRET), "nom révélateur : {nom}");
        assert!(!nom.contains("ordinaire"), "nom révélateur : {nom}");
    }

    // La disposition attendue : un en-tête, un index, un verrou, et un blob par
    // fichier — trois fichiers ajoutés, donc trois blobs.
    let blobs = noms.iter().filter(|nom| nom.starts_with("objects")).count();
    assert_eq!(blobs, 3, "fichiers du vault : {noms:?}");
    assert!(noms.iter().any(|nom| nom == "header"));
    assert!(noms.iter().any(|nom| nom == "index"));
}

/// C-028 : aucun temporaire ne doit subsister. Un résidu serait un fichier
/// qu'aucun index ne référence et que personne ne nettoiera.
#[test]
fn aucun_temporaire_ne_subsiste() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = session_representative(atelier.path());

    let residus: Vec<String> = contenu_du_vault(&coffre)
        .into_iter()
        .map(|(nom, _)| nom)
        .filter(|nom| nom.contains(".vault-tmp-") || str::ends_with(nom, ".tmp"))
        .collect();
    assert!(residus.is_empty(), "temporaires oubliés : {residus:?}");
}

/// FR-037, VR-B3 : la taille exacte d'un fichier n'est pas déductible de celle
/// de son blob. Deux contenus de tailles différentes mais proches donnent des
/// blobs de taille identique.
#[test]
fn la_taille_exacte_n_est_pas_deductible() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let mut vault = Vault::create(&atelier.path().join("coffre"), passphrase(), params())
        .expect("vault créable");

    for (index, taille) in [10usize, 700, 2000].into_iter().enumerate() {
        let source = atelier.path().join(format!("source-{index}"));
        std::fs::write(&source, vec![0x5a; taille]).expect("écrivable");
        vault
            .add_file(
                &source,
                &VaultPath::from_components([format!("f{index}").into_bytes()]).expect("valide"),
                AddMode::Copy,
                OnConflict::Fail,
            )
            .expect("ajoutable");
    }

    let tailles: Vec<u64> = std::fs::read_dir(vault.path().join("objects"))
        .expect("listable")
        .filter_map(std::result::Result::ok)
        .map(|entree| entree.metadata().expect("lisible").len())
        .collect();

    assert_eq!(tailles.len(), 3);
    assert!(
        tailles.iter().all(|taille| *taille == 4096),
        "trois contenus très différents doivent tomber dans le même palier : {tailles:?}"
    );
}

/// VR-B1 : deux fichiers au contenu identique donnent deux blobs distincts. Un
/// vault ne révèle pas ses doublons.
#[test]
fn deux_contenus_identiques_donnent_deux_blobs_distincts() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let source = atelier.path().join("source.bin");
    std::fs::write(&source, b"exactement le meme contenu").expect("écrivable");

    let mut vault = Vault::create(&atelier.path().join("coffre"), passphrase(), params())
        .expect("vault créable");
    for nom in ["premier", "second"] {
        vault
            .add_file(
                &source,
                &VaultPath::from_components([nom.as_bytes().to_vec()]).expect("valide"),
                AddMode::Copy,
                OnConflict::Fail,
            )
            .expect("ajoutable");
    }

    let blobs: Vec<Vec<u8>> = std::fs::read_dir(vault.path().join("objects"))
        .expect("listable")
        .filter_map(std::result::Result::ok)
        .map(|entree| std::fs::read(entree.path()).expect("lisible"))
        .collect();

    assert_eq!(blobs.len(), 2);
    assert_ne!(
        blobs[0], blobs[1],
        "deux blobs identiques révéleraient un doublon"
    );
}

/// VR-H3 : l'en-tête, seul élément en clair, ne dit rien du contenu. Il est
/// identique avant et après l'ajout de fichiers.
#[test]
fn l_en_tete_ne_change_pas_avec_le_contenu() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = atelier.path().join("coffre");
    let mut vault = Vault::create(&coffre, passphrase(), params()).expect("vault créable");

    let avant = std::fs::read(coffre.join("header")).expect("lisible");

    let source = atelier.path().join("source.bin");
    std::fs::write(&source, vec![0x11; 50_000]).expect("écrivable");
    vault
        .add_file(
            &source,
            &VaultPath::from_components([b"f".to_vec()]).expect("valide"),
            AddMode::Copy,
            OnConflict::Fail,
        )
        .expect("ajoutable");

    assert_eq!(
        std::fs::read(coffre.join("header")).expect("lisible"),
        avant,
        "l'en-tête ne doit pas être réécrit par un ajout"
    );
}
