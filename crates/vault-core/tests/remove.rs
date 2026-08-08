//! Suppression (T058, FR-031, FR-032).
//!
//! FR-032 est la seule exigence de cette user story qui demande à être prouvée
//! plutôt qu'illustrée : « le contenu supprimé ne doit pas rester récupérable
//! par une lecture ultérieure du vault, **y compris par un utilisateur
//! connaissant la passphrase** ». Ce n'est donc pas assez de vérifier que
//! `ls` ne montre plus l'entrée : il faut que le blob ait quitté le disque, et
//! que le constat tienne après avoir refermé et rouvert le vault avec la bonne
//! passphrase.
//!
//! Les tests vérifient toujours les deux faces de l'opération. Ce qui est
//! supprimé doit disparaître ; ce qui ne l'est pas doit ressortir **octet pour
//! octet**. Une suppression qui emporterait un voisin serait aussi grave qu'une
//! suppression qui ne supprimerait rien.
//!
//! # L'ordre, et pourquoi il se teste
//!
//! C-020 impose de réécrire l'index **d'abord** et de délier les blobs
//! **ensuite**. L'ordre inverse ferait qu'une interruption laisserait un index
//! désignant un blob absent — un vault cassé. Dans le bon ordre, elle ne laisse
//! que des orphelins, c'est-à-dire des déchets que le déverrouillage suivant
//! balaie. Le test qui le vérifie provoque l'échec de la réécriture et constate
//! que **rien** n'a été délié.

use std::path::{Path, PathBuf};

use vault_core::{
    AddMode, EntryKind, Error, KdfParams, OnConflict, SecretString, Vault, VaultPath,
};

fn params() -> KdfParams {
    KdfParams::new(64, 1, 1).expect("paramètres valides")
}

fn passphrase() -> SecretString {
    SecretString::from("passphrase de test bien assez longue".to_owned())
}

fn chemin(composants: &[&[u8]]) -> VaultPath {
    VaultPath::from_components(composants.iter().map(|c| c.to_vec())).expect("chemin valide")
}

/// Contenu déterministe d'un fichier du corpus.
fn contenu(nom: &str, taille: usize) -> Vec<u8> {
    let graine = u8::try_from(nom.len() % 251).expect("reste inférieur à 251");
    (0..taille)
        .map(|index| graine.wrapping_add(u8::try_from(index % 251).expect("reste inférieur à 251")))
        .collect()
}

/// Fichiers de l'atelier : deux à la racine, deux dans un dossier imbriqué.
///
/// Les entrées de dossier — `photos` et `photos/ete` — s'ajoutent d'elles-mêmes
/// avec [`vault_core::UnlockedVault::add_dir`] ; sans elles, il n'y aurait rien
/// à supprimer sous le nom `photos`.
const CORPUS: [(&str, &[&[u8]], usize); 4] = [
    ("note.txt", &[b"note.txt"], 300),
    ("garde.bin", &[b"garde.bin"], 5000),
    ("photos/plage.jpg", &[b"photos", b"plage.jpg"], 70_000),
    (
        "photos/ete/rando.jpg",
        &[b"photos", b"ete", b"rando.jpg"],
        900,
    ),
];

/// Entrées de dossier créées par l'ajout récursif.
const DOSSIERS: usize = 2;

struct Atelier {
    _racine: tempfile::TempDir,
    coffre: PathBuf,
    sortie: PathBuf,
}

impl Atelier {
    fn neuf() -> Self {
        let racine = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = racine.path().join("coffre");
        let source = racine.path().join("source");
        std::fs::create_dir_all(source.join("photos/ete")).expect("créable");

        for (nom, _, taille) in CORPUS {
            std::fs::write(source.join(nom), contenu(nom, taille)).expect("écrivable");
        }

        let mut vault = Vault::create(&coffre, passphrase(), params()).expect("créable");
        vault
            .add_dir(
                &source,
                &VaultPath::root(),
                AddMode::Copy,
                OnConflict::Fail,
                &mut |_| {},
            )
            .expect("ajoutable");
        assert_eq!(vault.list(None).len(), CORPUS.len() + DOSSIERS);
        vault.lock();

        let sortie = racine.path().join("sortie");
        std::fs::create_dir(&sortie).expect("créable");
        Self {
            _racine: racine,
            coffre,
            sortie,
        }
    }

    fn ouvrir(&self) -> vault_core::UnlockedVault {
        Vault::open(&self.coffre)
            .expect("ouvrable")
            .unlock(passphrase())
            .expect("déverrouillable")
    }

    /// Emplacement sur disque du blob d'une entrée.
    fn blob(&self, session: &vault_core::UnlockedVault, composants: &[&[u8]]) -> PathBuf {
        let (blob_id, _) = session
            .blob_of(&chemin(composants))
            .expect("présente")
            .expect("un blob");
        self.coffre.join("objects").join(blob_id.to_hex())
    }

    /// Nombre de blobs présents dans `objects/`.
    fn blobs_sur_disque(&self) -> usize {
        std::fs::read_dir(self.coffre.join("objects"))
            .expect("listable")
            .count()
    }
}

/// Vérifie qu'une entrée ressort du vault octet pour octet.
fn ressort_identique(
    session: &vault_core::UnlockedVault,
    sortie: &Path,
    nom: &str,
    composants: &[&[u8]],
    taille: usize,
) -> bool {
    let chemin_vault = chemin(composants);
    if session
        .extract(&chemin_vault, sortie, OnConflict::Replace)
        .is_err()
    {
        return false;
    }
    let feuille = composants.last().expect("un nom");
    let attendu = sortie.join(String::from_utf8_lossy(feuille).into_owned());
    std::fs::read(&attendu).expect("lisible") == contenu(nom, taille)
}

/// FR-032 : ce qui est supprimé quitte le disque, et n'y revient pas quand on
/// rouvre le vault avec la bonne passphrase.
#[test]
fn un_fichier_supprime_n_est_plus_recuperable() {
    let atelier = Atelier::neuf();
    let mut session = atelier.ouvrir();
    let blob = atelier.blob(&session, &[b"note.txt"]);
    assert!(blob.is_file(), "le blob existe avant la suppression");

    assert_eq!(
        session
            .remove(&chemin(&[b"note.txt"]), false)
            .expect("supprimable"),
        1
    );

    assert!(matches!(
        session.stat(&chemin(&[b"note.txt"])),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        session.extract(&chemin(&[b"note.txt"]), &atelier.sortie, OnConflict::Fail),
        Err(Error::NotFound)
    ));
    assert!(!blob.exists(), "le blob doit avoir quitté le disque");

    // Le vault refermé puis rouvert avec la **bonne** passphrase : rien ne
    // revient. C'est le cœur de FR-032.
    session.lock();
    let session = atelier.ouvrir();
    assert!(matches!(
        session.stat(&chemin(&[b"note.txt"])),
        Err(Error::NotFound)
    ));
    let chemins: Vec<VaultPath> = session.list(None).into_iter().map(|e| e.path).collect();
    assert!(!chemins.contains(&chemin(&[b"note.txt"])));
    assert!(!blob.exists());
}

/// L'autre face : ce qui n'a pas été supprimé ressort intact, octet pour octet.
#[test]
fn les_elements_restants_sont_intacts() {
    let atelier = Atelier::neuf();
    let mut session = atelier.ouvrir();
    session
        .remove(&chemin(&[b"note.txt"]), false)
        .expect("supprimable");
    session.lock();

    let session = atelier.ouvrir();
    let verdicts: Vec<bool> = CORPUS
        .iter()
        .filter(|(nom, _, _)| *nom != "note.txt")
        .map(|(nom, composants, taille)| {
            ressort_identique(&session, &atelier.sortie, nom, composants, *taille)
        })
        .collect();

    assert_eq!(verdicts, vec![true; CORPUS.len() - 1]);
    assert_eq!(atelier.blobs_sur_disque(), CORPUS.len() - 1);
}

/// Un dossier peuplé ne part pas par mégarde : sans récursion, refus net, et
/// **rien** n'a changé.
#[test]
fn un_dossier_peuple_exige_la_recursion() {
    let atelier = Atelier::neuf();
    let mut session = atelier.ouvrir();
    let avant = session.index_version();

    assert!(matches!(
        session.remove(&chemin(&[b"photos"]), false),
        Err(Error::DirectoryNotEmpty)
    ));

    assert_eq!(session.index_version(), avant, "l'index n'a pas bougé");
    assert_eq!(atelier.blobs_sur_disque(), CORPUS.len());
    assert!(ressort_identique(
        &session,
        &atelier.sortie,
        "photos/plage.jpg",
        &[b"photos", b"plage.jpg"],
        70_000
    ));
}

/// Avec la récursion, toute la descendance part — entrées et blobs — et les
/// voisins restent intacts.
#[test]
fn la_suppression_recursive_emporte_la_descendance() {
    let atelier = Atelier::neuf();
    let mut session = atelier.ouvrir();
    let plage = atelier.blob(&session, &[b"photos", b"plage.jpg"]);
    let rando = atelier.blob(&session, &[b"photos", b"ete", b"rando.jpg"]);

    // Le dossier, son sous-dossier et leurs deux fichiers.
    assert_eq!(
        session
            .remove(&chemin(&[b"photos"]), true)
            .expect("supprimable"),
        4
    );

    assert!(!plage.exists());
    assert!(!rando.exists());
    assert!(matches!(
        session.stat(&chemin(&[b"photos", b"plage.jpg"])),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        session.stat(&chemin(&[b"photos", b"ete", b"rando.jpg"])),
        Err(Error::NotFound)
    ));

    assert!(ressort_identique(
        &session,
        &atelier.sortie,
        "note.txt",
        &[b"note.txt"],
        300
    ));
    assert!(ressort_identique(
        &session,
        &atelier.sortie,
        "garde.bin",
        &[b"garde.bin"],
        5000
    ));
    assert_eq!(atelier.blobs_sur_disque(), 2);
}

/// Une entrée absente est introuvable, et la tentative ne touche à rien.
#[test]
fn une_entree_absente_est_introuvable() {
    let atelier = Atelier::neuf();
    let mut session = atelier.ouvrir();
    let avant = session.index_version();

    assert!(matches!(
        session.remove(&chemin(&[b"absent.txt"]), false),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        session.remove(&chemin(&[b"absent.txt"]), true),
        Err(Error::NotFound)
    ));

    assert_eq!(session.index_version(), avant);
    assert_eq!(atelier.blobs_sur_disque(), CORPUS.len());
}

/// C-020, VR-B6 : après une suppression réussie, aucune entrée de l'index ne
/// désigne un blob absent. C'est l'invariant que l'ordre protège.
#[test]
fn aucune_entree_ne_designe_un_blob_absent_apres_suppression() {
    let atelier = Atelier::neuf();
    let mut session = atelier.ouvrir();
    session
        .remove(&chemin(&[b"photos", b"plage.jpg"]), false)
        .expect("supprimable");
    session.lock();

    let session = atelier.ouvrir();
    let manquants: Vec<VaultPath> = session
        .list(None)
        .into_iter()
        .filter(|entree| entree.kind == EntryKind::File)
        .filter(|entree| {
            let (blob_id, _) = session
                .blob_of(&entree.path)
                .expect("présente")
                .expect("un blob");
            !atelier
                .coffre
                .join("objects")
                .join(blob_id.to_hex())
                .exists()
        })
        .map(|entree| entree.path)
        .collect();

    assert_eq!(manquants, Vec::<VaultPath>::new());
}

/// C-020, dans le sens qui compte : si la réécriture de l'index échoue,
/// **aucun blob n'a été délié**. L'ordre inverse laisserait ici un index
/// désignant un blob absent — un vault cassé, et non des déchets.
///
/// Le répertoire du vault est rendu non inscriptible : la réécriture de
/// l'index, qui passe par un temporaire voisin, ne peut plus aboutir. Le
/// procédé n'a pas d'équivalent portable — sous Windows, un attribut de
/// lecture seule sur un répertoire ne l'empêche pas d'accueillir des fichiers.
#[cfg(unix)]
#[test]
fn un_echec_de_reecriture_ne_delie_aucun_blob() {
    use std::os::unix::fs::PermissionsExt;

    let atelier = Atelier::neuf();
    let mut session = atelier.ouvrir();
    let blob = atelier.blob(&session, &[b"note.txt"]);
    let avant = session.index_version();

    let permissions_initiales = std::fs::metadata(&atelier.coffre)
        .expect("lisible")
        .permissions();
    let mut verrouillees = permissions_initiales.clone();
    verrouillees.set_mode(0o500);
    std::fs::set_permissions(&atelier.coffre, verrouillees).expect("modifiable");

    let resultat = session.remove(&chemin(&[b"note.txt"]), false);

    std::fs::set_permissions(&atelier.coffre, permissions_initiales).expect("modifiable");

    assert!(
        matches!(resultat, Err(Error::Io(_))),
        "obtenu : {resultat:?}"
    );
    assert!(
        blob.exists(),
        "aucun blob ne doit être délié tant que l'index n'est pas réécrit"
    );
    assert_eq!(
        session.index_version(),
        avant,
        "l'index en mémoire doit avoir été restauré"
    );
    assert!(ressort_identique(
        &session,
        &atelier.sortie,
        "note.txt",
        &[b"note.txt"],
        300
    ));
}

/// Une feuille se retire sans récursion, et la récursion sur une feuille est
/// acceptée elle aussi : elle n'a simplement rien de plus à emporter.
#[test]
fn une_feuille_se_retire_dans_les_deux_modes() {
    for recursive in [false, true] {
        let atelier = Atelier::neuf();
        let mut session = atelier.ouvrir();
        assert_eq!(
            session
                .remove(&chemin(&[b"garde.bin"]), recursive)
                .expect("supprimable"),
            1,
            "recursive = {recursive}"
        );
        assert_eq!(atelier.blobs_sur_disque(), CORPUS.len() - 1);
    }
}
