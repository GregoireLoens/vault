//! Suite bloquante — la surface publique du transport (T045).
//!
//! Ce que la **bibliothèque** garantit avant qu'aucune session ssh ne soit
//! ouverte : la forme d'une cible distante, le refus de ce qui n'en est pas
//! une, et le contrôle d'une destination locale.
//!
//! Le transport lui-même — arguments remis au client, tubes, codes de retour —
//! est éprouvé de bout en bout dans `crates/vault-cli/tests/transfer.rs`, contre
//! le faux client ssh placé en tête du `PATH`. La séparation n'est pas
//! arbitraire : substituer le `PATH` suppose de le modifier pour un processus,
//! et `std::env::set_var` est `unsafe` depuis l'édition 2024 — ce que
//! `unsafe_code = "forbid"` interdit dans cet espace de travail. Le seul moyen
//! sans couture est donc de lancer le **binaire** avec un `PATH` choisi, ce qui
//! relève du crate de ligne de commande.

use std::ffi::OsStr;

use vault_core::{Error, ImportPolicy, KdfParams, RemoteTarget, SecretString, SshOptions, Vault};

fn cible(brut: &str) -> RemoteTarget {
    RemoteTarget::parse(OsStr::new(brut)).expect("cible valide")
}

/// FR-019 : la forme `[utilisateur@]hôte:chemin` est celle que tout le monde
/// écrit déjà pour `scp`, et elle se décompose sans surprise.
#[test]
fn une_cible_distante_se_lit_comme_on_l_ecrit() {
    let complete = cible("utilisateur@poste-b:/home/vous/coffre");
    assert_eq!(complete.user(), Some("utilisateur"));
    assert_eq!(complete.host(), "poste-b");
    assert_eq!(complete.path(), "/home/vous/coffre");

    let sobre = cible("poste-b:~/coffres/mon-vault");
    assert_eq!(sobre.user(), None);
    assert_eq!(sobre.host(), "poste-b");
    assert_eq!(sobre.path(), "~/coffres/mon-vault");

    // Le chemin distant peut contenir des deux-points : seul le premier sépare.
    assert_eq!(cible("hote:/a:b:c").path(), "/a:b:c");
}

/// FR-019a : le contrôle de forme, qui est **tout** ce dont la grammaire de
/// `send` et `fetch` a besoin. La combinaison distant-distant, elle, est
/// inexprimable — il n'y a donc rien à contrôler de ce côté (D-209).
#[test]
fn ce_qui_ressemble_a_un_chemin_local_en_est_un() {
    for local in [
        "/home/vous/coffre",
        "coffre",
        "./coffre",
        "../coffre",
        "/home/vous/a:b",
        "C:\\coffres\\mon-vault",
        "",
    ] {
        assert!(!RemoteTarget::looks_remote(OsStr::new(local)), "{local:?}");
        assert!(
            matches!(
                RemoteTarget::parse(OsStr::new(local)),
                Err(Error::InvalidPath)
            ),
            "{local:?}"
        );
    }

    for distant in ["hote:chemin", "moi@hote:/absolu", "hote:~/relatif"] {
        assert!(
            RemoteTarget::looks_remote(OsStr::new(distant)),
            "{distant:?}"
        );
        assert!(
            RemoteTarget::parse(OsStr::new(distant)).is_ok(),
            "{distant:?}"
        );
    }
}

/// D-206 : un chemin distant qui n'est pas de l'UTF-8 valide est refusé.
///
/// Le format conserve les octets bruts des noms — c'est VR-I1 — mais une ligne
/// de commande ssh ne les accepte pas, et refuser explicitement vaut mieux que
/// de laisser le shell distant produire une erreur opaque.
#[cfg(unix)]
#[test]
fn une_cible_non_utf8_est_refusee() {
    use std::os::unix::ffi::OsStrExt;

    assert!(matches!(
        RemoteTarget::parse(OsStr::from_bytes(b"hote:/coffre-\xff\xfe")),
        Err(Error::InvalidPath)
    ));
}

/// La commande distante par défaut est `vault`, et rien d'autre n'est supposé
/// du poste distant.
#[test]
fn les_options_ssh_ont_un_defaut_sobre() {
    let defaut = SshOptions::default();
    assert_eq!(defaut.remote_command, "vault");
    assert!(
        defaut.options.is_empty(),
        "vault n'ajoute aucune option de son propre chef"
    );
}

/// **Un rapatriement contrôle sa destination locale avant d'ouvrir la moindre
/// session ssh.**
///
/// C'est ce qui donne son sens à FR-028 dans ce sens-là : la destination est
/// ici, et rien n'oblige à traverser le réseau pour découvrir qu'elle est
/// occupée. Le test le vérifie par l'absurde — l'hôte nommé n'existe pas, et
/// pourtant le refus est celui de la destination.
#[test]
fn un_rapatriement_refuse_sa_destination_avant_tout_reseau() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = atelier.path().join("coffre");
    Vault::create(
        &coffre,
        SecretString::from("passphrase de test bien assez longue".to_owned()),
        KdfParams::new(64, 1, 1).expect("valides"),
    )
    .expect("créable")
    .lock();

    assert!(matches!(
        Vault::fetch(
            &cible("hote-qui-n-existe-pas:/coffre"),
            &coffre,
            &SshOptions::default(),
            ImportPolicy::Refuse,
        ),
        Err(Error::DestinationOccupied)
    ));

    // Une destination qui existe sans être un vault est refusée de même, et le
    // remplacement n'y change rien (FR-013c).
    let fichier = atelier.path().join("fichier-ordinaire");
    std::fs::write(&fichier, b"contenu etranger").expect("écrivable");
    for policy in [ImportPolicy::Refuse, ImportPolicy::Replace] {
        assert!(matches!(
            Vault::fetch(
                &cible("hote-qui-n-existe-pas:/coffre"),
                &fichier,
                &SshOptions::default(),
                policy,
            ),
            Err(Error::AlreadyExists)
        ));
    }
    assert_eq!(
        std::fs::read(&fichier).expect("lisible"),
        b"contenu etranger"
    );
}

/// `Vault::check_destination` est le verdict que rend le mode de sondage, et il
/// n'écrit rien : c'est ce qui permet à FR-029a de tenir — un oui ou un non, et
/// pas un octet de plus.
#[test]
fn le_verdict_du_sondage_n_ecrit_rien() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let libre = atelier.path().join("libre");

    Vault::check_destination(&libre, ImportPolicy::Refuse).expect("destination libre");
    assert!(!libre.exists(), "le sondage ne crée rien");

    let coffre = atelier.path().join("coffre");
    Vault::create(
        &coffre,
        SecretString::from("passphrase de test bien assez longue".to_owned()),
        KdfParams::new(64, 1, 1).expect("valides"),
    )
    .expect("créable")
    .lock();
    let avant = std::fs::read(coffre.join("header")).expect("lisible");

    assert!(matches!(
        Vault::check_destination(&coffre, ImportPolicy::Refuse),
        Err(Error::DestinationOccupied)
    ));
    // Avec remplacement demandé, la même destination devient acceptable.
    Vault::check_destination(&coffre, ImportPolicy::Replace).expect("remplaçable");

    assert_eq!(
        std::fs::read(coffre.join("header")).expect("lisible"),
        avant,
        "le sondage ne touche à rien"
    );
}

/// FR-017 : la lisibilité d'une version de conteneur est publiée, parce que le
/// sondage en a besoin avant qu'un seul octet ne parte.
#[test]
fn la_lisibilite_d_une_version_de_conteneur_est_publiee() {
    assert!(vault_core::is_container_version_readable(
        vault_core::CONTAINER_VERSION
    ));
    for inconnue in [0, vault_core::CONTAINER_VERSION + 1, u32::MAX] {
        assert!(
            !vault_core::is_container_version_readable(inconnue),
            "{inconnue}"
        );
    }
}
