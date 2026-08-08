//! Compatibilité ascendante (T064, SC-008).
//!
//! SC-008 exige que **100 % des vaults créés par une version donnée restent
//! ouvrables par les versions ultérieures**, et le principe IV en fait un
//! engagement permanent : toute version future doit savoir lire tous les
//! formats antérieurs.
//!
//! Une suite qui créerait un vault puis le relirait ne prouverait rien de tout
//! cela — seulement que le logiciel sait lire ce qu'il vient d'écrire, ce que
//! `roundtrip.rs` établit déjà. La preuve demande des vaults que le logiciel
//! **d'aujourd'hui n'a pas produits**, et qu'il ne peut pas modifier
//! rétroactivement : c'est ce que sont les références de `tests/fixtures/`.
//!
//! Chacune est ouverte, déverrouillée, et son contenu comparé **octet pour
//! octet** à ce qui y a été déposé. Le jour où une évolution du format cesserait
//! de savoir les lire, cette suite échouerait — et c'est le logiciel qu'il
//! faudrait corriger, jamais la référence. Voir `tests/fixtures/README.md`.
//!
//! # La référence est copiée avant d'être ouverte
//!
//! Ouvrir un vault n'est pas une opération en lecture seule : le verrou y crée
//! son fichier support, et le déverrouillage balaie les blobs orphelins
//! (VR-I6). Ouvrir la référence en place laisserait donc la suite modifier des
//! fichiers versionnés — et, dans le pire des cas, en supprimer. Chaque test
//! travaille sur une copie jetable.

use std::path::{Path, PathBuf};

use vault_core::{
    EntryKind, FORMAT_VERSION, KdfParams, OnConflict, SecretString, Vault, VaultPath,
};

/// Emplacement des références, relatif à la racine du crate.
const FIXTURES: &str = "tests/fixtures";

/// Une version de format publiée, et de quoi ouvrir sa référence.
struct Reference {
    /// Nom du répertoire dans `tests/fixtures/`.
    repertoire: &'static str,
    /// Version de format que la référence déclare.
    version: u32,
    /// Passphrase de la référence. Publique : ce vault ne protège rien.
    passphrase: &'static str,
    /// Paramètres de dérivation attendus dans l'en-tête.
    kdf: (u32, u32, u32),
}

/// Toutes les références connues.
///
/// **Cette liste ne fait que s'allonger.** Retirer une entrée reviendrait à
/// abandonner la lecture d'un format qu'une version publiée a produit, ce que
/// le principe IV interdit.
const REFERENCES: [Reference; 1] = [Reference {
    repertoire: "v1",
    version: 1,
    passphrase: "vault fixture v1 passphrase de reference",
    kdf: (64, 1, 1),
}];

/// Contenu attendu de la référence v1, tel qu'il y a été déposé.
fn contenu_v1() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "lisez-moi.txt",
            "Vault de référence, format 1.\nCe fichier ne doit jamais changer.\n"
                .as_bytes()
                .to_vec(),
        ),
        ("vide.bin", Vec::new()),
        ("photos/été.jpg", (0..=255u8).collect()),
        (
            "photos/grand.bin",
            (0..70_000u32)
                .map(|index| u8::try_from(index % 251).expect("reste inférieur à 251"))
                .collect(),
        ),
    ]
}

fn chemin(nom: &str) -> VaultPath {
    VaultPath::from_components(nom.split('/').map(|c| c.as_bytes().to_vec()))
        .expect("chemin valide")
}

/// Copie une référence dans un répertoire jetable et rend son emplacement.
fn copie_jetable(reference: &Reference, atelier: &Path) -> PathBuf {
    let origine = Path::new(FIXTURES).join(reference.repertoire);
    assert!(
        origine.is_dir(),
        "référence absente : {}",
        origine.display()
    );

    let cible = atelier.join("coffre");
    std::fs::create_dir_all(cible.join("objects")).expect("créable");
    for entree in walkdir::WalkDir::new(&origine)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entree| entree.file_type().is_file())
    {
        let relatif = entree
            .path()
            .strip_prefix(&origine)
            .expect("sous la racine");
        std::fs::copy(entree.path(), cible.join(relatif)).expect("copiable");
    }
    cible
}

/// SC-008 : chaque référence s'ouvre, et son en-tête annonce ce qu'il doit.
#[test]
fn chaque_reference_s_ouvre_sans_passphrase() {
    for reference in &REFERENCES {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = copie_jetable(reference, atelier.path());

        let verrouille = Vault::open(&coffre).expect("ouvrable");
        assert_eq!(
            verrouille.format_version(),
            reference.version,
            "{}",
            reference.repertoire
        );
        let (memoire, passes, parallelisme) = reference.kdf;
        assert_eq!(
            verrouille.kdf_params(),
            KdfParams::new(memoire, passes, parallelisme).expect("valides"),
            "les paramètres lus sont ceux de l'en-tête, pas ceux du logiciel"
        );
    }
}

/// SC-008 : le contenu de la référence v1 ressort **octet pour octet**.
#[test]
fn la_reference_v1_livre_son_contenu_intact() {
    let reference = &REFERENCES[0];
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = copie_jetable(reference, atelier.path());

    let session = Vault::open(&coffre)
        .expect("ouvrable")
        .unlock(SecretString::from(reference.passphrase.to_owned()))
        .expect("déverrouillable");

    // Quatre fichiers et le dossier qui en contient deux.
    assert_eq!(session.list(None).len(), contenu_v1().len() + 1);
    assert_eq!(
        session.stat(&chemin("photos")).expect("présent").kind,
        EntryKind::Directory
    );

    let sortie = atelier.path().join("sortie");
    std::fs::create_dir(&sortie).expect("créable");
    session
        .extract(&VaultPath::root(), &sortie, OnConflict::Fail)
        .expect("extractible");

    let verdicts: Vec<bool> = contenu_v1()
        .into_iter()
        .map(|(nom, attendu)| {
            let entree = session.stat(&chemin(nom)).expect("présente");
            let sur_disque = std::fs::read(sortie.join(nom)).expect("lisible");
            entree.size == Some(attendu.len() as u64) && sur_disque == attendu
        })
        .collect();

    assert_eq!(verdicts, vec![true; contenu_v1().len()]);
}

/// Le logiciel écrit toujours la dernière version du format, et sait lire
/// toutes celles dont il détient une référence.
#[test]
fn les_references_couvrent_toutes_les_versions_lisibles() {
    let connues: Vec<u32> = REFERENCES.iter().map(|r| r.version).collect();
    let manquantes: Vec<u32> = (1..=FORMAT_VERSION)
        .filter(|version| !connues.contains(version))
        .collect();

    assert_eq!(
        manquantes,
        Vec::<u32>::new(),
        "une version de format publiée est sans vault de référence"
    );
}

/// La référence n'est pas modifiée par le fait d'être ouverte : c'est la copie
/// qui prend le verrou et le balayage des orphelins.
#[test]
fn ouvrir_une_reference_ne_la_modifie_pas() {
    let reference = &REFERENCES[0];
    let origine = Path::new(FIXTURES).join(reference.repertoire);

    let avant: Vec<PathBuf> = fichiers_de(&origine);
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = copie_jetable(reference, atelier.path());
    Vault::open(&coffre)
        .expect("ouvrable")
        .unlock(SecretString::from(reference.passphrase.to_owned()))
        .expect("déverrouillable");

    assert_eq!(fichiers_de(&origine), avant);
    assert!(
        !origine.join(".lock").exists(),
        "aucun verrou ne doit apparaître dans ce qui est versionné"
    );
}

/// Chemins relatifs des fichiers d'un répertoire, triés.
fn fichiers_de(racine: &Path) -> Vec<PathBuf> {
    let mut chemins: Vec<PathBuf> = walkdir::WalkDir::new(racine)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entree| entree.file_type().is_file())
        .map(|entree| {
            entree
                .path()
                .strip_prefix(racine)
                .expect("sous la racine")
                .to_path_buf()
        })
        .collect();
    chemins.sort();
    chemins
}
