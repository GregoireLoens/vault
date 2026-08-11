//! Suite bloquante — atomicité et résistance aux interruptions (T034,
//! SC-007, SC-011).
//!
//! SC-007 : une interruption provoquée à n'importe quel instant laisse le vault
//! ouvrable, avec ses données antérieures intactes. SC-011 : en mode
//! déplacement, l'original survit à un échec d'ajout.
//!
//! # Comment les échecs sont injectés
//!
//! Provoquer une coupure d'alimentation en test n'est pas praticable. Ce qui
//! l'est, et qui couvre le même invariant, c'est de rendre **impossible** une
//! écriture donnée et de vérifier que le vault reste dans son état antérieur.
//! Deux leviers portables sont employés :
//!
//! - remplacer `objects/` par un fichier ordinaire, ce qui fait échouer la
//!   création du temporaire d'un blob sur toutes les plateformes ;
//! - refuser l'ajout en amont — source absente, entrée non ordinaire,
//!   collision — pour vérifier qu'aucun octet n'a été écrit.
//!
//! Un troisième levier, le retrait du droit d'écriture sur le répertoire du
//! vault, ne fonctionne que sur des systèmes à permissions POSIX ; il est donc
//! sous `cfg(unix)` et n'existe pas dans la compilation Windows.
//!
//! L'invariant vérifié après chaque injection est toujours le même : **le vault
//! se rouvre, et son contenu est exactement celui d'avant l'opération.**

use std::path::Path;

use vault_core::{AddMode, Error, KdfParams, OnConflict, SecretString, Vault, VaultPath};

fn params() -> KdfParams {
    KdfParams::new(64, 1, 1).expect("paramètres valides")
}

fn passphrase() -> SecretString {
    SecretString::from("passphrase de test bien assez longue".to_owned())
}

fn chemin(nom: &str) -> VaultPath {
    VaultPath::from_components([nom.as_bytes().to_vec()]).expect("chemin valide")
}

/// Prépare un vault contenant déjà une entrée, et le referme.
///
/// Les données antérieures sont ce que chaque injection doit laisser intact.
fn vault_peuple(atelier: &Path) -> std::path::PathBuf {
    let coffre = atelier.join("coffre");
    let source = atelier.join("anterieur.bin");
    std::fs::write(&source, b"donnee anterieure a preserver").expect("écrivable");

    let mut vault = Vault::create(&coffre, passphrase(), params()).expect("vault créable");
    vault
        .add_file(
            &source,
            &chemin("anterieur.bin"),
            AddMode::Copy,
            OnConflict::Fail,
        )
        .expect("ajoutable");
    vault.lock();
    coffre
}

/// Rouvre le vault et vérifie que l'entrée antérieure est intacte, contenu
/// compris. C'est l'assertion centrale de SC-007.
fn le_vault_est_intact(coffre: &Path, atelier: &Path, marqueur: &str) {
    let vault = Vault::open(coffre)
        .unwrap_or_else(|erreur| panic!("[{marqueur}] le vault doit rester ouvrable : {erreur}"))
        .unlock(passphrase())
        .unwrap_or_else(|erreur| {
            panic!("[{marqueur}] le vault doit rester déverrouillable : {erreur}")
        });

    let entrees = vault.list(None);
    assert_eq!(entrees.len(), 1, "[{marqueur}] entrées : {entrees:?}");
    assert_eq!(entrees[0].path, chemin("anterieur.bin"), "[{marqueur}]");

    let sortie = atelier.join(format!("sortie-{marqueur}"));
    std::fs::create_dir(&sortie).expect("créable");
    vault
        .extract(&chemin("anterieur.bin"), &sortie, OnConflict::Fail)
        .unwrap_or_else(|erreur| panic!("[{marqueur}] contenu antérieur perdu : {erreur}"));
    assert_eq!(
        std::fs::read(sortie.join("anterieur.bin")).expect("lisible"),
        b"donnee anterieure a preserver",
        "[{marqueur}] contenu antérieur altéré"
    );
}

/// Remplace `objects/` par un fichier ordinaire : plus aucun blob ne peut être
/// écrit. Renvoie de quoi rétablir le répertoire.
fn saboter_objects(coffre: &Path) {
    let objects = coffre.join("objects");
    let blobs: Vec<(std::ffi::OsString, Vec<u8>)> = std::fs::read_dir(&objects)
        .expect("listable")
        .filter_map(std::result::Result::ok)
        .map(|entree| {
            (
                entree.file_name(),
                std::fs::read(entree.path()).expect("lisible"),
            )
        })
        .collect();

    std::fs::remove_dir_all(&objects).expect("supprimable");
    std::fs::write(&objects, b"ceci n'est pas un repertoire").expect("écrivable");
    // Les blobs sont mémorisés pour être rétablis à la vérification.
    let sauvegarde = coffre.join(".sauvegarde");
    std::fs::create_dir(&sauvegarde).expect("créable");
    for (nom, octets) in blobs {
        std::fs::write(sauvegarde.join(nom), octets).expect("écrivable");
    }
}

fn reparer_objects(coffre: &Path) {
    let objects = coffre.join("objects");
    std::fs::remove_file(&objects).expect("supprimable");
    std::fs::rename(coffre.join(".sauvegarde"), &objects).expect("renommable");
}

/// SC-007 : l'écriture d'un blob échoue, l'index n'est pas touché, le vault
/// reste ouvrable et son contenu antérieur intact.
#[test]
fn un_echec_d_ecriture_de_blob_laisse_le_vault_intact() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = vault_peuple(atelier.path());

    let source = atelier.path().join("nouveau.bin");
    std::fs::write(&source, vec![0x7f; 100_000]).expect("écrivable");

    saboter_objects(&coffre);
    {
        let mut vault = Vault::open(&coffre)
            .expect("ouvrable")
            .unlock(passphrase())
            .expect("déverrouillable");
        let echec = vault.add_file(
            &source,
            &chemin("nouveau.bin"),
            AddMode::Copy,
            OnConflict::Fail,
        );
        assert!(matches!(echec, Err(Error::Io(_))), "obtenu : {echec:?}");
    }
    reparer_objects(&coffre);

    le_vault_est_intact(&coffre, atelier.path(), "blob");
}

/// SC-011 : en mode déplacement, un échec d'ajout laisse l'original en place.
/// C'est le seul cas où une erreur pourrait détruire des données que le vault
/// n'a pas encore.
#[test]
fn en_mode_deplacement_l_original_survit_a_un_echec() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = vault_peuple(atelier.path());

    let source = atelier.path().join("a-deplacer.bin");
    std::fs::write(&source, b"contenu qui ne doit pas disparaitre").expect("écrivable");

    saboter_objects(&coffre);
    {
        let mut vault = Vault::open(&coffre)
            .expect("ouvrable")
            .unlock(passphrase())
            .expect("déverrouillable");
        let echec = vault.add_file(
            &source,
            &chemin("a-deplacer.bin"),
            AddMode::Move,
            OnConflict::Fail,
        );
        assert!(echec.is_err(), "l'ajout devait échouer");
    }
    reparer_objects(&coffre);

    assert_eq!(
        std::fs::read(&source).expect("l'original doit survivre"),
        b"contenu qui ne doit pas disparaitre"
    );
    le_vault_est_intact(&coffre, atelier.path(), "deplacement");
}

/// En mode déplacement réussi, l'original disparaît — sans quoi FR-018 ne
/// serait pas tenu.
#[test]
fn en_mode_deplacement_reussi_l_original_disparait() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = vault_peuple(atelier.path());

    let source = atelier.path().join("a-deplacer.bin");
    std::fs::write(&source, b"contenu confie au vault").expect("écrivable");

    let mut vault = Vault::open(&coffre)
        .expect("ouvrable")
        .unlock(passphrase())
        .expect("déverrouillable");
    vault
        .add_file(
            &source,
            &chemin("a-deplacer.bin"),
            AddMode::Move,
            OnConflict::Fail,
        )
        .expect("ajoutable");

    assert!(!source.exists(), "l'original doit avoir été retiré");
    assert_eq!(vault.list(None).len(), 2);
}

/// Un refus en amont ne doit rien avoir écrit du tout : ni blob, ni index.
#[test]
fn un_refus_en_amont_n_ecrit_rien() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = vault_peuple(atelier.path());

    let empreinte_avant = empreinte_du_vault(&coffre);

    {
        let mut vault = Vault::open(&coffre)
            .expect("ouvrable")
            .unlock(passphrase())
            .expect("déverrouillable");

        // Source absente.
        let absente = atelier.path().join("jamais-creee.bin");
        assert!(matches!(
            vault.add_file(&absente, &chemin("x"), AddMode::Copy, OnConflict::Fail),
            Err(Error::Io(_))
        ));

        // Collision refusée (VR-I3, C-018).
        let source = atelier.path().join("autre.bin");
        std::fs::write(&source, b"peu importe").expect("écrivable");
        assert!(matches!(
            vault.add_file(
                &source,
                &chemin("anterieur.bin"),
                AddMode::Copy,
                OnConflict::Fail
            ),
            Err(Error::AlreadyExists)
        ));

        // Chemin de destination sous un nom réservé : refusé par VR-I4 en
        // amont de toute écriture.
        assert!(VaultPath::from_components([b"..".to_vec()]).is_err());
    }

    assert_eq!(
        empreinte_du_vault(&coffre),
        empreinte_avant,
        "un refus ne doit modifier aucun octet du vault"
    );
    le_vault_est_intact(&coffre, atelier.path(), "refus");
}

/// FR-023, C-009 : un fichier au-delà de la limite est refusé **avant** toute
/// écriture, et le vault reste rigoureusement inchangé.
///
/// Le fichier est créé creux, ce qui ne coûte rien sur ext4. Ce test est
/// réservé à Linux : sur NTFS, `set_len` réserve réellement les quatre
/// gigaoctets. La garde de taille elle-même est vérifiée sur toutes les
/// plateformes par les tests unitaires de `ops/add.rs`.
#[cfg(target_os = "linux")]
#[test]
fn un_fichier_trop_volumineux_est_refuse_sans_rien_ecrire() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = vault_peuple(atelier.path());

    let enorme = atelier.path().join("enorme.bin");
    std::fs::File::create(&enorme)
        .expect("créable")
        .set_len(vault_core::MAX_FILE_SIZE + 1)
        .expect("taille réservable");

    let empreinte_avant = empreinte_du_vault(&coffre);
    {
        let mut vault = Vault::open(&coffre)
            .expect("ouvrable")
            .unlock(passphrase())
            .expect("déverrouillable");
        assert!(matches!(
            vault.add_file(
                &enorme,
                &chemin("enorme.bin"),
                AddMode::Copy,
                OnConflict::Fail
            ),
            Err(Error::FileTooLarge { .. })
        ));
    }
    assert_eq!(empreinte_du_vault(&coffre), empreinte_avant);
    le_vault_est_intact(&coffre, atelier.path(), "volumineux");
}

/// C-012 : une entrée non ordinaire est refusée plutôt que traitée à moitié.
#[cfg(unix)]
#[test]
fn un_lien_symbolique_est_refuse_sans_rien_ecrire() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = vault_peuple(atelier.path());

    let cible = atelier.path().join("cible.bin");
    std::fs::write(&cible, b"contenu de la cible").expect("écrivable");
    let lien = atelier.path().join("lien.bin");
    std::os::unix::fs::symlink(&cible, &lien).expect("lien créable");

    let empreinte_avant = empreinte_du_vault(&coffre);
    {
        let mut vault = Vault::open(&coffre)
            .expect("ouvrable")
            .unlock(passphrase())
            .expect("déverrouillable");
        assert!(matches!(
            vault.add_file(&lien, &chemin("lien.bin"), AddMode::Copy, OnConflict::Fail),
            Err(Error::UnsupportedEntry)
        ));
    }
    assert_eq!(empreinte_du_vault(&coffre), empreinte_avant);
    le_vault_est_intact(&coffre, atelier.path(), "lien");
}

/// L'index ne peut pas être réécrit : le vault doit rester exactement dans son
/// état antérieur, index compris.
///
/// Le retrait du droit d'écriture sur un répertoire n'a de sens que sur un
/// système à permissions POSIX ; ce test n'existe pas dans la compilation
/// Windows, où l'invariant est couvert par l'injection sur `objects/`.
#[cfg(unix)]
#[test]
fn un_echec_de_reecriture_de_l_index_laisse_le_vault_intact() {
    use std::os::unix::fs::PermissionsExt;

    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = vault_peuple(atelier.path());

    let source = atelier.path().join("nouveau.bin");
    std::fs::write(&source, b"contenu du nouveau fichier").expect("écrivable");

    let index_avant = std::fs::read(coffre.join("index")).expect("lisible");

    let mut permissions = std::fs::metadata(&coffre).expect("lisible").permissions();
    permissions.set_mode(0o500);
    std::fs::set_permissions(&coffre, permissions).expect("modifiable");

    {
        let mut vault = Vault::open(&coffre)
            .expect("ouvrable")
            .unlock(passphrase())
            .expect("déverrouillable");
        let echec = vault.add_file(
            &source,
            &chemin("nouveau.bin"),
            AddMode::Copy,
            OnConflict::Fail,
        );
        assert!(matches!(echec, Err(Error::Io(_))), "obtenu : {echec:?}");
    }

    let mut permissions = std::fs::metadata(&coffre).expect("lisible").permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&coffre, permissions).expect("modifiable");

    assert_eq!(
        std::fs::read(coffre.join("index")).expect("lisible"),
        index_avant,
        "l'index ne doit pas avoir bougé"
    );
    le_vault_est_intact(&coffre, atelier.path(), "index");
}

/// D-008, VR-I6 : un blob écrit mais non référencé — ce que laisse une
/// interruption entre l'écriture du blob et le remplacement de l'index — est un
/// déchet inerte, pas une corruption. Le vault s'ouvre et fonctionne.
#[test]
fn un_blob_orphelin_ne_corrompt_pas_le_vault() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = vault_peuple(atelier.path());

    std::fs::write(
        coffre.join("objects").join("0".repeat(64)),
        vec![0x33; 4096],
    )
    .expect("écrivable");

    le_vault_est_intact(&coffre, atelier.path(), "orphelin");
}

/// C-002 : la création est atomique. Un emplacement déjà occupé est refusé, et
/// aucun vault partiel ne subsiste.
#[test]
fn la_creation_refuse_un_emplacement_occupe() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = vault_peuple(atelier.path());

    assert!(matches!(
        Vault::create(&coffre, passphrase(), params()),
        Err(Error::AlreadyExists)
    ));
    le_vault_est_intact(&coffre, atelier.path(), "creation");

    // Un chemin dont le parent n'existe pas échoue sans laisser de trace.
    let impossible = atelier.path().join("absent").join("coffre");
    assert!(Vault::create(&impossible, passphrase(), params()).is_err());
    assert!(!impossible.exists());
    assert!(!atelier.path().join("absent").exists());
}

/// FR-005, C-001 : une passphrase trop courte est refusée avant toute
/// écriture.
#[test]
fn une_passphrase_trop_courte_ne_cree_rien() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = atelier.path().join("coffre");

    assert!(matches!(
        Vault::create(&coffre, SecretString::from("court".to_owned()), params()),
        Err(Error::WeakPassphrase { minimum: 12 })
    ));
    assert!(!coffre.exists());
}

/// Empreinte de l'état du vault : chemins relatifs et contenus, triés.
fn empreinte_du_vault(coffre: &Path) -> Vec<(String, Vec<u8>)> {
    let mut fichiers: Vec<(String, Vec<u8>)> = walkdir::WalkDir::new(coffre)
        .sort_by_file_name()
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entree| entree.file_type().is_file())
        .map(|entree| {
            (
                entree
                    .path()
                    .strip_prefix(coffre)
                    .expect("sous la racine")
                    .to_string_lossy()
                    .into_owned(),
                std::fs::read(entree.path()).expect("lisible"),
            )
        })
        .collect();
    fichiers.sort();
    fichiers
}

// ---------------------------------------------------------------------------
// Import et remplacement — T019, FR-015, FR-047, SC-005, quickstart 5
// ---------------------------------------------------------------------------
//
// L'invariant est celui de D-208, et il ne souffre aucune exception : **à
// chaque point d'écriture, une interruption laisse la destination soit avec un
// vault complet et ouvrable, soit sans vault ouvrable.** Aucun état
// intermédiaire n'est jamais visible sous le nom de la destination.
//
// Les interruptions sont injectées comme ailleurs dans ce fichier : en rendant
// **impossible** une écriture donnée. Un conteneur tronqué à chaque octet
// couvre tous les points d'arrêt de la réception, ce qu'aucune injection
// ponctuelle ne ferait ; un système de fichiers rendu inécrivable couvre la
// création du répertoire d'attente.

/// Un vault peuplé, refermé, et le conteneur qu'il produit.
fn coffre_et_conteneur(atelier: &Path) -> (std::path::PathBuf, Vec<u8>) {
    let coffre = atelier.join("coffre");
    let mut vault = Vault::create(&coffre, passphrase(), params()).expect("créable");
    for (nom, contenu) in [("note.txt", &b"une note"[..]), ("gros.bin", &[0x2a; 9000])] {
        let source = atelier.join(nom);
        std::fs::write(&source, contenu).expect("écrivable");
        vault
            .add_file(&source, &chemin(nom), AddMode::Copy, OnConflict::Fail)
            .expect("ajoutable");
    }
    vault.lock();

    let mut conteneur = Vec::new();
    Vault::export(&coffre, vault_core::ExportEnvelope::Source, &mut conteneur).expect("exportable");
    (coffre, conteneur)
}

/// Vrai s'il existe à cet emplacement un vault **ouvrable**.
fn vault_ouvrable(chemin: &Path) -> bool {
    Vault::open(chemin)
        .and_then(|vault| vault.unlock(passphrase()))
        .is_ok()
}

/// **FR-015, SC-005 : à chaque point d'interruption de la réception, la
/// destination reste sans vault ouvrable.**
///
/// Le conteneur est tronqué à *chaque* longueur possible. C'est la forme la
/// plus exigeante du test : elle couvre l'arrêt au milieu de l'en-tête, d'un
/// cadre, d'une charge, et juste avant le sceau — sans qu'aucun de ces points
/// n'ait eu à être nommé.
#[test]
fn import_toute_troncature_ne_laisse_aucun_vault_ouvrable() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let (_, conteneur) = coffre_et_conteneur(atelier.path());
    let cible = atelier.path().join("restaure");

    for coupe in 0..conteneur.len() {
        let resultat = Vault::import(
            &mut &conteneur[..coupe],
            &cible,
            vault_core::ImportPolicy::Refuse,
        );
        assert!(
            resultat.is_err(),
            "un conteneur tronqué à {coupe} a été accepté"
        );
        assert!(
            !cible.exists(),
            "un vault est apparu après une troncature à {coupe}"
        );
    }

    // Le conteneur entier, lui, aboutit : la boucle ci-dessus n'a pas refusé
    // par un effet de bord qui rendrait tout import impossible.
    Vault::import(
        &mut &conteneur[..],
        &cible,
        vault_core::ImportPolicy::Refuse,
    )
    .expect("importable");
    assert!(vault_ouvrable(&cible));
}

/// **Un remplacement interrompu ne perd jamais l'ancien vault.** La séquence de
/// D-208 déplace avant de mettre en place ; à toute interruption, l'ancien est
/// retrouvé — sous son nom d'origine, ou sous son nom de remplacement.
#[test]
fn import_un_remplacement_interrompu_conserve_l_ancien_vault() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let (coffre, conteneur) = coffre_et_conteneur(atelier.path());

    // L'ancien vault reçoit un marqueur, pour être reconnaissable ensuite.
    let source = atelier.path().join("marqueur.txt");
    std::fs::write(&source, b"marqueur").expect("écrivable");
    let mut session = Vault::open(&coffre)
        .expect("ouvrable")
        .unlock(passphrase())
        .expect("déverrouillable");
    session
        .add_file(
            &source,
            &chemin("marqueur.txt"),
            AddMode::Copy,
            OnConflict::Fail,
        )
        .expect("ajoutable");
    session.lock();
    let ancien = repertoire(&coffre);

    // Chaque troncature interrompt la réception avant la bascule : l'ancien
    // vault est intact sous son nom d'origine, et rien n'a bougé.
    for coupe in [0, conteneur.len() / 3, conteneur.len() - 1] {
        assert!(
            Vault::import(
                &mut &conteneur[..coupe],
                &coffre,
                vault_core::ImportPolicy::Replace
            )
            .is_err()
        );
        assert_eq!(repertoire(&coffre), ancien, "coupé à {coupe}");
        assert!(vault_ouvrable(&coffre));
    }

    // Et le remplacement mené à son terme retrouve l'ancien **à côté**, complet
    // et ouvrable : il a été déplacé, jamais supprimé (FR-013b).
    let ecarte = Vault::import(
        &mut &conteneur[..],
        &coffre,
        vault_core::ImportPolicy::Replace,
    )
    .expect("remplaçable")
    .replaced
    .expect("l'ancien a été déplacé");

    assert_eq!(repertoire(&ecarte), ancien);
    assert!(vault_ouvrable(&ecarte));
    assert!(vault_ouvrable(&coffre));
}

/// Contenu d'un répertoire de vault, `.lock` excepté.
fn repertoire(coffre: &Path) -> Vec<(String, Vec<u8>)> {
    let mut contenu: Vec<(String, Vec<u8>)> = walkdir::WalkDir::new(coffre)
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
                    .to_string_lossy()
                    .into_owned(),
                std::fs::read(entree.path()).expect("lisible"),
            )
        })
        .filter(|(nom, _)| nom != ".lock")
        .collect();
    contenu.sort();
    contenu
}

/// Un échec d'écriture pendant la réception ne laisse rien à destination.
///
/// Le levier est celui du reste de ce fichier : rendre le répertoire parent
/// inécrivable, ce qui fait échouer la création du répertoire d'attente.
#[cfg(unix)]
#[test]
fn import_un_parent_inecrivable_ne_laisse_rien() {
    use std::os::unix::fs::PermissionsExt;

    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let (_, conteneur) = coffre_et_conteneur(atelier.path());

    let parent = atelier.path().join("verrouille");
    std::fs::create_dir(&parent).expect("créable");
    let cible = parent.join("restaure");

    let mut permissions = std::fs::metadata(&parent).expect("lisible").permissions();
    permissions.set_mode(0o500);
    std::fs::set_permissions(&parent, permissions).expect("modifiable");

    let resultat = Vault::import(
        &mut &conteneur[..],
        &cible,
        vault_core::ImportPolicy::Refuse,
    );

    let mut permissions = std::fs::metadata(&parent).expect("lisible").permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&parent, permissions).expect("modifiable");

    assert!(matches!(resultat, Err(Error::Io(_))), "{resultat:?}");
    assert!(!cible.exists());
    assert_eq!(
        std::fs::read_dir(&parent).expect("listable").count(),
        0,
        "aucun répertoire d'attente ne doit subsister"
    );
}

/// FR-035 : sur un chemin d'erreur **propre**, aucun répertoire d'attente ne
/// subsiste. Il ne survit qu'à une interruption du processus — le seul cas où
/// il y a quelque chose à identifier.
#[test]
fn import_un_echec_propre_ne_laisse_aucun_repertoire_d_attente() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let (_, conteneur) = coffre_et_conteneur(atelier.path());

    for coupe in [conteneur.len() / 2, conteneur.len() - 1] {
        assert!(
            Vault::import(
                &mut &conteneur[..coupe],
                &atelier.path().join("restaure"),
                vault_core::ImportPolicy::Refuse
            )
            .is_err()
        );
    }

    let residus: Vec<String> = std::fs::read_dir(atelier.path())
        .expect("listable")
        .filter_map(std::result::Result::ok)
        .map(|entree| entree.file_name().to_string_lossy().into_owned())
        .filter(|nom| nom.contains(".vault-entrant-"))
        .collect();
    assert!(residus.is_empty(), "{residus:?}");
}
