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
use vault_core::{
    AddMode, EntryKind, ExportEnvelope, ImportPolicy, KdfParams, OnConflict, SecretString, Vault,
    VaultPath,
};

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
/// deux entrées distinctes du vault.
///
/// La distinction est vérifiée **dans le vault**, à partir d'une source unique.
/// Écrire les deux formes côte à côte sur le disque ne prouverait rien de
/// portable : APFS est insensible à la normalisation et les fusionnerait, si
/// bien que le test mesurerait le système de fichiers hôte au lieu du format.
#[test]
fn deux_normalisations_unicode_restent_distinctes() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let mut vault = Vault::create(&atelier.path().join("coffre"), passphrase(), params())
        .expect("vault créable");

    let source = atelier.path().join("source.txt");
    std::fs::write(&source, b"contenu").expect("écrivable");

    let compose = chemin(&["café.txt".as_bytes()]);
    let decompose = chemin(&["cafe\u{0301}.txt".as_bytes()]);
    assert_ne!(compose, decompose, "les octets diffèrent");

    vault
        .add_file(&source, &compose, AddMode::Copy, OnConflict::Fail)
        .expect("ajoutable");
    vault
        .add_file(&source, &decompose, AddMode::Copy, OnConflict::Fail)
        .expect("la seconde forme n'est pas une collision");

    assert_eq!(vault.list(None).len(), 2, "deux entrées distinctes");
    assert!(vault.stat(&compose).is_ok());
    assert!(vault.stat(&decompose).is_ok());
}

// SC-002 sous forme de propriété. Deux propriétés, en réalité, parce que le
// vault et le système de fichiers hôte n'acceptent pas les mêmes noms.
//
// VR-I1 conserve les noms en **octets bruts** : le vault accepte donc tout ce
// que VR-I4 ne refuse pas, y compris des suites qui ne sont pas de l'UTF-8.
// Mais un hôte est plus exigeant — macOS impose de l'UTF-8 valide, NTFS
// interdit en plus une liste de caractères et de noms réservés. Explorer les
// noms hostiles *jusqu'à l'extraction* reviendrait donc à exiger du système de
// fichiers ce qu'il ne sait pas faire, et c'est ce qui faisait échouer cette
// suite sur les exécuteurs macOS et Windows.
//
// La séparation suit cette frontière : l'aller-retour complet emprunte un
// alphabet que les trois jeux de règles acceptent, et l'exploration hostile
// s'arrête à l'index — là où la fidélité est promise sur toutes les
// plateformes.

/// Alphabet accepté par [`NamingRules::Bytes`], `Utf8` **et** `Windows`.
///
/// Le préfixe et le suffixe garantissent qu'aucun nom n'est vide, ne vaut `.`
/// ou `..`, ne se termine par un point ou une espace, et ne heurte un nom de
/// périphérique réservé.
fn composant_portable() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(
        prop::sample::select(vec!['a', 'B', '9', '-', '_', ' ', '.', 'é', 'ß', '漢']),
        0..=9,
    )
    .prop_map(|caracteres| {
        let mut nom = String::from("f");
        nom.extend(caracteres);
        nom.push('z');
        nom.into_bytes()
    })
}

/// Composants que le **vault** accepte, hostiles pour l'hôte ou non.
fn composant_hostile() -> impl Strategy<Value = Vec<u8>> {
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

    /// Tout fichier ajouté puis extrait est identique, contenu et nom compris.
    #[test]
    fn tout_fichier_ajoute_puis_extrait_est_identique(
        composants in prop::collection::vec(composant_portable(), 1..=4),
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

    /// VR-I1 : **tout** nom que le vault accepte ressort de l'index avec ses
    /// octets d'origine, y compris ceux qu'aucun hôte ne saurait écrire. La
    /// propriété tient sur toutes les plateformes, parce qu'elle ne touche
    /// jamais au système de fichiers de destination.
    #[test]
    fn tout_nom_hostile_traverse_l_index_intact(
        composants in prop::collection::vec(composant_hostile(), 1..=4),
        contenu in prop::collection::vec(any::<u8>(), 0..=200),
    ) {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        let source = atelier.path().join("source.bin");
        std::fs::write(&source, &contenu).expect("écrivable");

        let destination = VaultPath::from_components(composants).expect("chemin valide");
        {
            let mut vault =
                Vault::create(&coffre, passphrase(), params()).expect("vault créable");
            vault
                .add_file(&source, &destination, AddMode::Copy, OnConflict::Fail)
                .expect("ajoutable");
        }

        // Le vault est refermé puis rouvert : les octets ont fait l'aller-retour
        // par l'index chiffré sur le disque.
        let vault = Vault::open(&coffre)
            .expect("ouvrable")
            .unlock(passphrase())
            .expect("déverrouillable");

        let entree = vault.stat(&destination).expect("présente");
        prop_assert_eq!(&entree.path, &destination);
        prop_assert_eq!(entree.size, Some(contenu.len() as u64));

        let listees: Vec<VaultPath> = vault.list(None).into_iter().map(|e| e.path).collect();
        prop_assert!(listees.contains(&destination));
    }
}

// ---------------------------------------------------------------------------
// Aller-retour export/import — T015, principe VI, FR-044, SC-001, SC-014
// ---------------------------------------------------------------------------
//
// Le principe VI exige « un test de round-trip export/import vérifiant la
// restitution octet pour octet du contenu et de l'arborescence » depuis la
// ratification. Il n'existait pas — non par négligence, mais parce que la
// fonctionnalité qu'il doit éprouver n'existait pas. Le voici.
//
// **La comparaison porte sur le répertoire du vault**, et non seulement sur ce
// qu'un déverrouillage donne à voir : les blobs orphelins doivent survivre au
// voyage, puisqu'un export copie fidèlement (FR-008). Le seul fichier écarté
// est `.lock`, qui décrit l'état d'exécution d'un poste et non le contenu d'un
// vault (FR-008a).

/// Contenu du répertoire d'un vault, `.lock` excepté.
fn repertoire_de_vault(coffre: &Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut contenu: Vec<(std::path::PathBuf, Vec<u8>)> = walkdir::WalkDir::new(coffre)
        .sort_by_file_name()
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entree| entree.file_type().is_file())
        .map(|entree| {
            (
                entree
                    .path()
                    .strip_prefix(coffre)
                    .expect("sous le vault")
                    .to_path_buf(),
                std::fs::read(entree.path()).expect("lisible"),
            )
        })
        .filter(|(chemin, _)| chemin != Path::new(".lock"))
        .collect();
    contenu.sort();
    contenu
}

/// Le test que le principe VI attend : exporter, **supprimer le vault
/// d'origine**, réimporter, et comparer.
///
/// Le corpus couvre ce que le quickstart énumère : arborescence profonde, noms
/// non conformes à l'UTF-8, fichier vide, entrée de 0 octet, dossier sans
/// contenu. Le vault vide, lui, a son propre test.
#[test]
fn export_import_restitue_le_vault_octet_pour_octet() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = atelier.path().join("coffre");
    let mut vault = Vault::create(&coffre, passphrase(), params()).expect("vault créable");

    // Une arborescence profonde, un dossier sans contenu, et des fichiers de
    // tailles variées — dont un vide.
    let source = atelier.path().join("corpus");
    std::fs::create_dir_all(source.join("a/b/c/d/e")).expect("créable");
    std::fs::create_dir(source.join("dossier-vide")).expect("créable");
    std::fs::write(source.join("a/b/c/d/e/profond.bin"), [0x5a; 12_345]).expect("écrivable");
    std::fs::write(source.join("a/b/vide"), b"").expect("écrivable");
    std::fs::write(source.join("accentué — é à ù.txt"), "contenu\n").expect("écrivable");
    vault
        .add_dir(
            &source,
            &VaultPath::root(),
            AddMode::Copy,
            OnConflict::Fail,
            &mut |_| {},
        )
        .expect("ajoutable");

    // VR-I1 : les noms sont conservés en octets bruts. Un nom non conforme à
    // l'UTF-8 doit donc faire le voyage comme les autres, et il est ajouté par
    // le chemin de vault plutôt que depuis le disque.
    //
    // **Il vit à part, sous `hostile/`, et c'est délibéré** : ce nom n'est
    // représentable ni sur APFS ni sur NTFS, et l'extraire y échouerait par
    // `UnrepresentableName`. Le mettre dans le corpus rendrait donc ce test
    // vert sur Linux et rouge ailleurs — pour une raison qui n'a rien à voir
    // avec ce qu'il éprouve. Sa survie se vérifie par l'**index**, comme le
    // fait déjà `tout_nom_hostile_traverse_l_index_intact`.
    let hostile = atelier.path().join("hostile.bin");
    std::fs::write(&hostile, b"octets bruts").expect("écrivable");
    vault
        .add_file(
            &hostile,
            &chemin(&[b"hostile", b"\xff\xfe non-utf8"]),
            AddMode::Copy,
            OnConflict::Fail,
        )
        .expect("ajoutable");

    let entrees_attendues = vault.list(None).len();
    vault.lock();

    // Un blob qu'aucune entrée ne référence : un export copie fidèlement, donc
    // il part lui aussi (FR-008).
    let orphelin = coffre
        .join("objects")
        .join("0000000000000000000000000000000000000000000000000000000000000001");
    std::fs::write(&orphelin, b"dechet inerte").expect("écrivable");

    let avant = repertoire_de_vault(&coffre);

    let mut conteneur = Vec::new();
    let resume =
        Vault::export(&coffre, ExportEnvelope::Source, &mut conteneur).expect("exportable");

    // Le vault d'origine disparaît : rien de ce qui suit ne peut s'y adosser.
    std::fs::remove_dir_all(&coffre).expect("supprimable");

    let restaure = atelier.path().join("restaure");
    let recu =
        Vault::import(&mut &conteneur[..], &restaure, ImportPolicy::Refuse).expect("importable");
    assert_eq!(recu.blob_count, resume.blob_count);

    // SC-001 : le répertoire est restitué octet pour octet, orphelin compris.
    assert_eq!(repertoire_de_vault(&restaure), avant);

    // Et il est utilisable : il s'ouvre avec la passphrase du vault source, et
    // son contenu ressort identique au corpus déposé.
    let session = Vault::open(&restaure)
        .expect("ouvrable")
        .unlock(passphrase())
        .expect("déverrouillable");
    assert_eq!(session.list(None).len(), entrees_attendues);

    // L'extraction porte sur le corpus **représentable**, entrée par entrée :
    // extraire la racine emporterait le nom non conforme à l'UTF-8, que ni
    // APFS ni NTFS n'acceptent.
    let sortie = atelier.path().join("sortie");
    std::fs::create_dir(&sortie).expect("créable");
    for entree in [
        chemin(&[b"a"]),
        chemin(&["accentué — é à ù.txt".as_bytes()]),
        chemin(&[b"dossier-vide"]),
    ] {
        session
            .extract(&entree, &sortie, OnConflict::Fail)
            .expect("extractible");
    }

    // Le contenu ressort identique, arborescence profonde et fichier vide
    // compris.
    for relatif in ["a/b/c/d/e/profond.bin", "a/b/vide", "accentué — é à ù.txt"] {
        assert_eq!(
            std::fs::read(sortie.join(relatif)).expect("extrait lisible"),
            std::fs::read(source.join(relatif)).expect("original lisible"),
            "{relatif}"
        );
    }
    assert!(
        sortie.join("dossier-vide").is_dir(),
        "un dossier sans contenu"
    );

    // VR-I1 : le nom non conforme à l'UTF-8 a traversé le conteneur intact. Il
    // se vérifie par l'index, jamais par le disque.
    assert!(
        session
            .stat(&chemin(&[b"hostile", b"\xff\xfe non-utf8"]))
            .is_ok(),
        "le nom brut doit survivre au voyage"
    );
}

/// Un vault vide fait l'aller-retour : c'est licite, et l'import redonne un
/// vault vide et ouvrable.
#[test]
fn export_import_d_un_vault_vide() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = atelier.path().join("coffre");
    Vault::create(&coffre, passphrase(), params())
        .expect("créable")
        .lock();
    let avant = repertoire_de_vault(&coffre);

    let mut conteneur = Vec::new();
    Vault::export(&coffre, ExportEnvelope::Source, &mut conteneur).expect("exportable");

    let restaure = atelier.path().join("restaure");
    Vault::import(&mut &conteneur[..], &restaure, ImportPolicy::Refuse).expect("importable");

    assert_eq!(repertoire_de_vault(&restaure), avant);
    assert!(
        Vault::open(&restaure)
            .expect("ouvrable")
            .unlock(passphrase())
            .expect("déverrouillable")
            .list(None)
            .is_empty()
    );
}

/// FR-012 : un conteneur produit sous passphrase distincte s'ouvre avec
/// **cette** passphrase, et le contenu reste celui du vault source — la clé
/// maîtresse n'a pas changé, seule son enveloppe.
#[test]
fn export_import_sous_passphrase_distincte() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = atelier.path().join("coffre");
    let mut vault = Vault::create(&coffre, passphrase(), params()).expect("créable");
    let source = atelier.path().join("note.txt");
    std::fs::write(&source, b"une note").expect("écrivable");
    vault
        .add_file(
            &source,
            &chemin(&[b"note.txt"]),
            AddMode::Copy,
            OnConflict::Fail,
        )
        .expect("ajoutable");
    vault.lock();

    let distincte = SecretString::from("une toute autre passphrase, longue".to_owned());
    let mut conteneur = Vec::new();
    Vault::export(
        &coffre,
        ExportEnvelope::NewPassphrase {
            current: passphrase(),
            new: SecretString::from("une toute autre passphrase, longue".to_owned()),
        },
        &mut conteneur,
    )
    .expect("exportable");

    let restaure = atelier.path().join("restaure");
    Vault::import(&mut &conteneur[..], &restaure, ImportPolicy::Refuse).expect("importable");

    // L'ancienne passphrase n'ouvre plus le vault reconstitué…
    assert!(
        Vault::open(&restaure)
            .expect("ouvrable")
            .unlock(passphrase())
            .is_err()
    );
    // …et la nouvelle donne accès au même contenu.
    let session = Vault::open(&restaure)
        .expect("ouvrable")
        .unlock(distincte)
        .expect("déverrouillable");
    let sortie = atelier.path().join("sortie");
    std::fs::create_dir(&sortie).expect("créable");
    session
        .extract(&chemin(&[b"note.txt"]), &sortie, OnConflict::Fail)
        .expect("extractible");
    assert_eq!(
        std::fs::read(sortie.join("note.txt")).expect("lisible"),
        b"une note"
    );
}
