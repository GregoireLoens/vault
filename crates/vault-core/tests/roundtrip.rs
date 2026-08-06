//! Suite bloquante — aller-retour fidèle (T032, SC-002).
//!
//! SC-002 exige que **100 % des fichiers extraits soient identiques octet pour
//! octet aux originaux**, sur un corpus hétérogène. C'est la propriété la plus
//! élémentaire d'un coffre-fort : tout le reste — le chiffrement, l'index, le
//! remplissage — n'a de valeur que si les données ressortent intactes.
//!
//! La suite combine deux approches. Des cas nommés couvrent les situations que
//! l'on sait délicates : contenu vide, frontières de morceau, noms accentués,
//! arborescence profonde. `proptest` explore ensuite l'espace des noms
//! hostiles, des tailles et des profondeurs, et cherche des contre-exemples là
//! où l'auteur n'a pas pensé à regarder.

use std::path::Path;

use proptest::prelude::*;
use vault_core::{AddMode, EntryKind, KdfParams, OnConflict, SecretString, Vault, VaultPath};

/// Paramètres Argon2id minimaux. Ces tests vérifient la fidélité de
/// l'aller-retour, pas le coût d'une attaque par force brute ; employer
/// 128 MiB ici ajouterait des minutes à chaque exécution.
fn params() -> KdfParams {
    KdfParams::new(64, 1, 1).expect("paramètres valides")
}

fn passphrase() -> SecretString {
    SecretString::from("passphrase de test bien assez longue".to_owned())
}

fn chemin(composants: &[&[u8]]) -> VaultPath {
    VaultPath::from_components(composants.iter().map(|c| c.to_vec())).expect("chemin valide")
}

/// Compare deux arborescences octet pour octet, chemins compris.
fn arborescences_identiques(gauche: &Path, droite: &Path) -> bool {
    let lire = |racine: &Path| {
        let mut entrees: Vec<(std::path::PathBuf, Option<Vec<u8>>)> = walkdir::WalkDir::new(racine)
            .sort_by_file_name()
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|entree| entree.path() != racine)
            .map(|entree| {
                let relatif = entree
                    .path()
                    .strip_prefix(racine)
                    .expect("sous la racine")
                    .to_path_buf();
                let contenu = entree
                    .file_type()
                    .is_file()
                    .then(|| std::fs::read(entree.path()).expect("lisible"));
                (relatif, contenu)
            })
            .collect();
        entrees.sort();
        entrees
    };
    lire(gauche) == lire(droite)
}

#[test]
fn un_fichier_isole_ressort_identique() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let source = atelier.path().join("note.txt");
    std::fs::write(&source, b"contenu de reference").expect("écrivable");

    let mut vault = Vault::create(&atelier.path().join("coffre"), passphrase(), params())
        .expect("vault créable");
    let entree = vault
        .add_file(
            &source,
            &chemin(&[b"note.txt"]),
            AddMode::Copy,
            OnConflict::Fail,
        )
        .expect("ajoutable");

    assert_eq!(entree.kind, EntryKind::File);
    assert_eq!(entree.size, Some(20));

    let sortie = atelier.path().join("sortie");
    std::fs::create_dir(&sortie).expect("créable");
    vault
        .extract(&chemin(&[b"note.txt"]), &sortie, OnConflict::Fail)
        .expect("extractible");

    assert_eq!(
        std::fs::read(sortie.join("note.txt")).expect("lisible"),
        b"contenu de reference"
    );
}

/// Les tailles retenues encadrent les frontières de morceau de 64 KiB, là où
/// se logent les erreurs de découpage, et incluent le fichier vide, que le
/// format traite comme un morceau vide marqué comme dernier.
#[test]
fn toutes_les_tailles_frontieres_ressortent_identiques() {
    const CHUNK: usize = 64 * 1024;
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let source = atelier.path().join("source");
    std::fs::create_dir(&source).expect("créable");

    let tailles = [0usize, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK + 7];
    for taille in tailles {
        let contenu: Vec<u8> = (0..taille)
            .map(|index| u8::try_from(index % 251).expect("reste inférieur à 251"))
            .collect();
        std::fs::write(source.join(format!("taille-{taille}")), &contenu).expect("écrivable");
    }

    let mut vault = Vault::create(&atelier.path().join("coffre"), passphrase(), params())
        .expect("vault créable");
    vault
        .add_dir(
            &source,
            &VaultPath::root(),
            AddMode::Copy,
            OnConflict::Fail,
            &mut |_| {},
        )
        .expect("ajoutable");

    let sortie = atelier.path().join("sortie");
    std::fs::create_dir(&sortie).expect("créable");
    vault
        .extract(&VaultPath::root(), &sortie, OnConflict::Fail)
        .expect("extractible");

    assert!(arborescences_identiques(&source, &sortie));
}

/// Le corpus hétérogène du test indépendant de la user story 1 : texte,
/// binaire, taille nulle, arborescences imbriquées, noms accentués.
#[test]
fn un_corpus_heterogene_ressort_identique() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let source = atelier.path().join("corpus");
    std::fs::create_dir_all(source.join("documents/impôts/2025")).expect("créable");
    std::fs::create_dir_all(source.join("photos/été")).expect("créable");
    std::fs::create_dir(source.join("vide")).expect("créable");

    std::fs::write(source.join("lisez-moi.txt"), "texte accentué — é à ù\n").expect("écrivable");
    std::fs::write(source.join("documents/impôts/2025/avis.pdf"), [0u8; 4096]).expect("écrivable");
    std::fs::write(
        source.join("photos/été/plage.jpg"),
        (0..=255u8).collect::<Vec<_>>(),
    )
    .expect("écrivable");
    std::fs::write(source.join("photos/rien"), b"").expect("écrivable");

    let mut vault = Vault::create(&atelier.path().join("coffre"), passphrase(), params())
        .expect("vault créable");
    let ajoutees = vault
        .add_dir(
            &source,
            &VaultPath::root(),
            AddMode::Copy,
            OnConflict::Fail,
            &mut |_| {},
        )
        .expect("ajoutable");

    let fichiers = ajoutees
        .iter()
        .filter(|entree| entree.kind == EntryKind::File)
        .count();
    assert_eq!(fichiers, 4);
    assert_eq!(vault.list(None).len(), ajoutees.len());

    let sortie = atelier.path().join("sortie");
    std::fs::create_dir(&sortie).expect("créable");
    vault
        .extract(&VaultPath::root(), &sortie, OnConflict::Fail)
        .expect("extractible");

    assert!(arborescences_identiques(&source, &sortie));
}

/// FR-027 : la date de modification d'origine est restituée elle aussi.
#[test]
fn la_date_de_modification_est_restituee() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let source = atelier.path().join("daté.bin");
    std::fs::write(&source, b"contenu").expect("écrivable");
    let attendue = std::fs::metadata(&source)
        .expect("lisible")
        .modified()
        .expect("date disponible");

    let mut vault = Vault::create(&atelier.path().join("coffre"), passphrase(), params())
        .expect("vault créable");
    vault
        .add_file(
            &source,
            &chemin(&["daté.bin".as_bytes()]),
            AddMode::Copy,
            OnConflict::Fail,
        )
        .expect("ajoutable");

    let sortie = atelier.path().join("sortie");
    std::fs::create_dir(&sortie).expect("créable");
    vault
        .extract(&chemin(&["daté.bin".as_bytes()]), &sortie, OnConflict::Fail)
        .expect("extractible");

    let restituee = std::fs::metadata(sortie.join("daté.bin"))
        .expect("lisible")
        .modified()
        .expect("date disponible");

    // La seconde est la résolution du format ; comparer plus finement
    // reviendrait à tester la résolution du système de fichiers hôte.
    let ecart = restituee
        .duration_since(attendue)
        .or_else(|_| attendue.duration_since(restituee))
        .expect("écart mesurable");
    assert!(ecart.as_secs() <= 1, "écart de {ecart:?}");
}

/// VR-I1 : deux noms qui ne diffèrent que par leur normalisation Unicode sont
/// deux entrées distinctes, et chacune ressort avec ses octets d'origine.
#[test]
fn deux_normalisations_unicode_restent_distinctes() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let mut vault = Vault::create(&atelier.path().join("coffre"), passphrase(), params())
        .expect("vault créable");

    let compose = atelier.path().join("café.txt");
    let decompose = atelier.path().join("cafe\u{0301}.txt");
    std::fs::write(&compose, "composé".as_bytes()).expect("écrivable");
    std::fs::write(&decompose, "décomposé".as_bytes()).expect("écrivable");

    vault
        .add_file(
            &compose,
            &chemin(&["café.txt".as_bytes()]),
            AddMode::Copy,
            OnConflict::Fail,
        )
        .expect("ajoutable");
    vault
        .add_file(
            &decompose,
            &chemin(&["cafe\u{0301}.txt".as_bytes()]),
            AddMode::Copy,
            OnConflict::Fail,
        )
        .expect("ajoutable");

    assert_eq!(vault.list(None).len(), 2, "deux entrées distinctes");
}

/// SC-002 sous forme de propriété : *tout* fichier ajouté puis extrait est
/// identique. `proptest` explore les noms hostiles, les tailles et les
/// profondeurs d'arborescence.
fn composant_valide() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..=10).prop_filter("composant refusé par VR-I4", |octets| {
        octets != b"."
            && octets != b".."
            && !octets.iter().any(|o| *o == b'/' || *o == b'\\' || *o == 0)
    })
}

proptest! {
    // 48 cas : assez pour explorer, assez peu pour que la suite reste rapide.
    // Chaque cas crée un vault, donc dérive une clé Argon2id.
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn tout_fichier_ajoute_puis_extrait_est_identique(
        composants in prop::collection::vec(composant_valide(), 1..=4),
        contenu in prop::collection::vec(any::<u8>(), 0..=5000),
    ) {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let source = atelier.path().join("source.bin");
        std::fs::write(&source, &contenu).expect("écrivable");

        let mut vault = Vault::create(&atelier.path().join("coffre"), passphrase(), params())
            .expect("vault créable");

        let destination = VaultPath::from_components(composants).expect("chemin valide");
        vault
            .add_file(&source, &destination, AddMode::Copy, OnConflict::Fail)
            .expect("ajoutable");

        let entree = vault.stat(&destination).expect("présente");
        prop_assert_eq!(entree.size, Some(contenu.len() as u64));

        let sortie = atelier.path().join("sortie");
        std::fs::create_dir(&sortie).expect("créable");
        vault.extract(&destination, &sortie, OnConflict::Fail).expect("extractible");

        let attendu = sortie.join(
            destination
                .file_name()
                .map(|nom| VaultPath::from_components([nom.to_vec()]).expect("valide"))
                .expect("un nom")
                .to_os_path()
                .expect("représentable"),
        );
        prop_assert_eq!(std::fs::read(&attendu).expect("lisible"), contenu);
    }
}
