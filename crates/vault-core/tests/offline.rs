//! Isolation réseau (T066, SC-005, FR-038).
//!
//! FR-038 est une exigence négative — « le système ne doit établir aucune
//! connexion réseau » — et les exigences négatives sont les plus faciles à
//! croire vérifiées sans l'être. SC-005 la formule en deux moitiés, et cette
//! suite les traite séparément parce qu'elles ne se prouvent pas de la même
//! façon.
//!
//! **« L'intégralité des fonctions s'exécute sur une machine sans
//! connectivité. »** C'est une propriété de l'exécution, non du code : elle se
//! démontre en faisant tourner le cycle complet là où il n'y a pas de réseau.
//! `scripts/dev.sh` lance chaque commande dans un conteneur avec
//! `--network none` — l'absence de réseau y est la valeur par défaut, et le
//! réseau l'exception qu'il faut réclamer par `--net`. Le premier test déroule
//! donc création, ajout, consultation, extraction, suppression et changement de
//! passphrase, et son passage sous ce conteneur **est** la démonstration.
//!
//! **« 0 tentative de connexion sortante est observée. »** Celle-là ne peut pas
//! se déduire d'un succès : un logiciel qui tenterait une connexion et
//! poursuivrait après son échec passerait le premier test sans encombre. Elle
//! est donc constatée directement, en comptant les **descripteurs de socket du
//! processus** après le cycle complet. Il doit n'y en avoir aucun.
//!
//! Ce second test ne suppose pas l'absence de réseau, et c'est ce qui en fait
//! le plus utile des deux : il a le même sens sur l'exécuteur d'intégration
//! continue, qui est parfaitement connecté. Un vault qui ouvrirait une socket y
//! serait pris en flagrant délit, là où le premier test ne verrait rien.
//!
//! Le décompte des descripteurs passe par `/proc/self/fd`, donc ne vaut que
//! sous Linux. C'est la plateforme de la couverture et de la porte principale ;
//! ailleurs, la garantie repose sur `cargo deny check bans`, qui interdit toute
//! dépendance réseau, même transitive (D-012, T070).

use std::path::Path;

use vault_core::{AddMode, KdfParams, OnConflict, SecretString, Vault, VaultPath};

const PASSPHRASE: &str = "passphrase de test bien assez longue";
const NOUVELLE: &str = "une toute autre passphrase, aussi longue";

fn params() -> KdfParams {
    KdfParams::new(64, 1, 1).expect("paramètres valides")
}

fn secret(texte: &str) -> SecretString {
    SecretString::from(texte.to_owned())
}

fn chemin(nom: &str) -> VaultPath {
    VaultPath::from_components(nom.split('/').map(|c| c.as_bytes().to_vec()))
        .expect("chemin valide")
}

/// Déroule le cycle de vie complet d'un vault et rend le contenu relu.
///
/// Toutes les opérations du logiciel y passent : c'est ce que SC-005 appelle
/// « une session complète ».
fn cycle_complet(atelier: &Path) -> Vec<u8> {
    let source = atelier.join("source");
    std::fs::create_dir_all(source.join("photos")).expect("créable");
    std::fs::write(source.join("note.txt"), b"contenu de reference").expect("écrivable");
    std::fs::write(source.join("photos/plage.jpg"), vec![0x7e; 5000]).expect("écrivable");

    let coffre = atelier.join("coffre");

    // Création, ajout récursif, consultation.
    let mut vault = Vault::create(&coffre, secret(PASSPHRASE), params()).expect("créable");
    vault
        .add_dir(
            &source,
            &VaultPath::root(),
            AddMode::Copy,
            OnConflict::Fail,
            &mut |_| {},
        )
        .expect("ajoutable");
    assert_eq!(vault.list(None).len(), 3);
    assert!(vault.stat(&chemin("note.txt")).is_ok());

    // Changement de passphrase, puis fermeture.
    vault
        .change_passphrase(secret(NOUVELLE), None)
        .expect("changeable");
    vault.lock();

    // Réouverture avec la nouvelle, extraction, suppression.
    let mut vault = Vault::open(&coffre)
        .expect("ouvrable")
        .unlock(secret(NOUVELLE))
        .expect("déverrouillable");

    let sortie = atelier.join("sortie");
    std::fs::create_dir(&sortie).expect("créable");
    vault
        .extract(&chemin("note.txt"), &sortie, OnConflict::Fail)
        .expect("extractible");
    let relu = std::fs::read(sortie.join("note.txt")).expect("lisible");

    assert_eq!(
        vault.remove(&chemin("photos"), true).expect("supprimable"),
        2
    );
    vault.lock();

    relu
}

/// SC-005, première moitié : tout fonctionne sans connectivité.
///
/// Le test n'a rien de particulier — c'est **l'endroit où il s'exécute** qui
/// démontre l'exigence.
#[test]
fn le_cycle_complet_aboutit_sans_connectivite() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    assert_eq!(cycle_complet(atelier.path()), b"contenu de reference");
}

/// SC-005, seconde moitié : aucune connexion sortante n'est tentée.
///
/// Le décompte porte sur les descripteurs du **processus**, et non sur l'espace
/// de noms réseau : c'est bien ce logiciel qui est mesuré, et non ce que le
/// conteneur autorise.
#[cfg(target_os = "linux")]
#[test]
fn aucune_socket_n_est_ouverte_par_une_session_complete() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");

    let avant = sockets_du_processus();
    cycle_complet(atelier.path());
    let apres = sockets_du_processus();

    assert_eq!(avant, Vec::<String>::new(), "avant : {avant:?}");
    assert_eq!(apres, Vec::<String>::new(), "après : {apres:?}");
}

/// Descripteurs de socket ouverts par ce processus.
///
/// Sous Linux, chaque descripteur est un lien symbolique de `/proc/self/fd` ;
/// ceux qui désignent une socket pointent vers `socket:[inode]`.
#[cfg(target_os = "linux")]
fn sockets_du_processus() -> Vec<String> {
    let mut trouvees: Vec<String> = std::fs::read_dir("/proc/self/fd")
        .expect("/proc monté")
        .filter_map(std::result::Result::ok)
        .filter_map(|entree| std::fs::read_link(entree.path()).ok())
        .map(|cible| cible.to_string_lossy().into_owned())
        .filter(|cible| cible.starts_with("socket:"))
        .collect();
    trouvees.sort();
    trouvees
}
