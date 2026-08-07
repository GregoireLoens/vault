//! `vault extract` — T048.
//!
//! FR-026 à FR-030, CLI-011 à CLI-013.
//!
//! La ligne de commande ajoute trois choses à l'opération de la bibliothèque :
//!
//! - **CLI-011** : une confirmation avant d'écraser un fichier existant.
//!   `vault-core` refuse par défaut (C-018) ; c'est ici qu'on demande à
//!   l'utilisateur s'il veut passer outre.
//! - **CLI-012** : un message qui donne la place requise et la place
//!   disponible, plutôt qu'un simple « espace insuffisant ».
//! - **CLI-013** : le signalement explicite d'une altération. Silence ou
//!   message vague laisseraient croire à un incident de lecture ordinaire.

use std::path::{Path, PathBuf};

use vault_core::{Error, OnConflict};

use crate::cmd::{Contexte, chemin_de_vault, taille_lisible};
use crate::error::{CliError, CliResult};
use crate::prompt;

/// Options de `vault extract`.
#[derive(Clone, Debug)]
pub struct Options {
    /// Entrées à extraire.
    pub chemins: Vec<PathBuf>,
    /// `--to` : répertoire de destination.
    pub destination: PathBuf,
}

/// Extrait des entrées vers le disque, en clair.
///
/// # Errors
///
/// - [`CliError::Usage`] si aucun chemin n'est donné ;
/// - [`CliError::Refused`] si l'écrasement est refusé ;
/// - celles de [`vault_core::UnlockedVault::extract`].
pub fn executer(contexte: &mut Contexte, options: &Options) -> CliResult<()> {
    if options.chemins.is_empty() {
        return Err(CliError::Usage("Aucun chemin à extraire.".to_owned()));
    }

    let chemins = options
        .chemins
        .iter()
        .map(|chemin| chemin_de_vault(chemin))
        .collect::<CliResult<Vec<_>>>()?;

    let session = contexte.deverrouiller()?;
    std::fs::create_dir_all(&options.destination)?;

    let mut extraits = 0usize;
    for chemin in &chemins {
        let politique = politique_de_collision(contexte, &options.destination, chemin)?;
        match session.extract(chemin, &options.destination, politique) {
            Ok(()) => extraits += session.list(Some(chemin)).len(),
            Err(erreur) => return Err(expliquer(contexte, erreur)),
        }
    }

    if contexte.json {
        contexte
            .console
            .output(&format!("{{\"extracted\":{extraits}}}"));
    } else {
        contexte.console.info(&format!(
            "{extraits} entrée(s) extraite(s) vers {}.",
            options.destination.display()
        ));
    }
    Ok(())
}

/// Décide de la politique de collision, en demandant si nécessaire (CLI-011).
fn politique_de_collision(
    contexte: &mut Contexte,
    destination: &Path,
    chemin: &vault_core::VaultPath,
) -> CliResult<OnConflict> {
    let Some(nom) = chemin.file_name() else {
        // Extraire la racine : la collision se juge fichier par fichier, et
        // `OnConflict::Fail` la fait remonter comme une erreur ordinaire.
        return Ok(OnConflict::Fail);
    };
    let cible = destination.join(String::from_utf8_lossy(nom).into_owned());
    if !cible.exists() {
        return Ok(OnConflict::Fail);
    }

    let accepte = prompt::confirmer(
        contexte.console,
        &format!("{} existe déjà. L'écraser ?", cible.display()),
        contexte.yes,
    )?;
    if accepte {
        Ok(OnConflict::Replace)
    } else {
        Err(CliError::Refused)
    }
}

/// Enrichit une erreur d'extraction du message que le contrat exige.
fn expliquer(contexte: &mut Contexte, erreur: Error) -> CliError {
    match erreur {
        // CLI-012 : donner les deux nombres, pas seulement le verdict.
        Error::InsufficientSpace { needed, available } => {
            contexte.console.warn(&format!(
                "  ⚠  Espace insuffisant : {} nécessaires, {} disponibles.",
                taille_lisible(needed),
                taille_lisible(available)
            ));
            CliError::Core(erreur)
        }
        // CLI-013 : une altération se dit clairement, et l'on précise que la
        // sortie partielle a été retirée — sans quoi l'utilisateur pourrait
        // aller chercher un fichier tronqué à destination.
        Error::Authentication | Error::Corrupted => {
            contexte.console.warn(
                "  ⚠  Altération détectée : l'extraction a été interrompue et la sortie\n     partielle supprimée. Ce vault ne peut pas être restitué en l'état.",
            );
            CliError::Core(erreur)
        }
        autre => CliError::Core(autre),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::console::fake::FakeConsole;

    const PASSPHRASE: &str = "une passphrase bien assez longue";

    struct Atelier {
        _racine: tempfile::TempDir,
        coffre: PathBuf,
        sortie: PathBuf,
    }

    fn atelier() -> Atelier {
        let racine = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = racine.path().join("coffre");
        let source = racine.path().join("source");
        std::fs::create_dir_all(source.join("photos")).expect("créable");
        std::fs::write(source.join("photos/plage.jpg"), vec![0x7e; 3000]).expect("écrivable");
        std::fs::write(source.join("note.txt"), b"une note").expect("écrivable");

        let mut vault = vault_core::Vault::create(
            &coffre,
            vault_core::SecretString::from(PASSPHRASE.to_owned()),
            vault_core::KdfParams::new(64, 1, 1).expect("valides"),
        )
        .expect("créable");
        vault
            .add_dir(
                &source,
                &vault_core::VaultPath::root(),
                vault_core::AddMode::Copy,
                vault_core::OnConflict::Fail,
                &mut |_| {},
            )
            .expect("ajoutable");
        vault.lock();

        let sortie = racine.path().join("sortie");
        Atelier {
            _racine: racine,
            coffre,
            sortie,
        }
    }

    fn contexte<'a>(console: &'a mut FakeConsole, atelier: &Atelier) -> Contexte<'a> {
        Contexte {
            console,
            vault_dir: atelier.coffre.clone(),
            yes: false,
            json: false,
            idle_timeout: None,
        }
    }

    fn options(chemins: &[&str], sortie: &Path) -> Options {
        Options {
            chemins: chemins.iter().map(PathBuf::from).collect(),
            destination: sortie.to_path_buf(),
        }
    }

    #[test]
    fn une_entree_s_extrait_vers_la_destination() {
        let atelier = atelier();
        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);

        executer(
            &mut contexte(&mut console, &atelier),
            &options(&["note.txt"], &atelier.sortie),
        )
        .expect("extractible");

        assert_eq!(
            std::fs::read(atelier.sortie.join("note.txt")).expect("lisible"),
            b"une note"
        );
        assert!(console.tout_affiche().contains("1 entrée(s) extraite(s)"));
    }

    #[test]
    fn un_dossier_s_extrait_avec_son_contenu() {
        let atelier = atelier();
        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        let mut ctx = contexte(&mut console, &atelier);
        ctx.json = true;

        executer(&mut ctx, &options(&["photos"], &atelier.sortie)).expect("extractible");

        assert!(atelier.sortie.join("photos/plage.jpg").is_file());
        assert!(console.tout_affiche().contains("\"extracted\":2"));
    }

    /// CLI-011 : la confirmation est demandée, et un refus n'écrase rien.
    #[test]
    fn l_ecrasement_demande_confirmation() {
        let atelier = atelier();
        std::fs::create_dir_all(&atelier.sortie).expect("créable");
        let cible = atelier.sortie.join("note.txt");
        std::fs::write(&cible, b"contenu preexistant").expect("écrivable");

        let mut console = FakeConsole::new(&[PASSPHRASE], &["n"]);
        assert!(matches!(
            executer(
                &mut contexte(&mut console, &atelier),
                &options(&["note.txt"], &atelier.sortie)
            ),
            Err(CliError::Refused)
        ));
        assert_eq!(
            std::fs::read(&cible).expect("lisible"),
            b"contenu preexistant"
        );

        let mut console = FakeConsole::new(&[PASSPHRASE], &["o"]);
        executer(
            &mut contexte(&mut console, &atelier),
            &options(&["note.txt"], &atelier.sortie),
        )
        .expect("extractible");
        assert_eq!(std::fs::read(&cible).expect("lisible"), b"une note");
    }

    /// CLI-011 : `--yes` vaut acceptation de l'écrasement.
    #[test]
    fn yes_vaut_acceptation_de_l_ecrasement() {
        let atelier = atelier();
        std::fs::create_dir_all(&atelier.sortie).expect("créable");
        let cible = atelier.sortie.join("note.txt");
        std::fs::write(&cible, b"contenu preexistant").expect("écrivable");

        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        let mut ctx = contexte(&mut console, &atelier);
        ctx.yes = true;
        executer(&mut ctx, &options(&["note.txt"], &atelier.sortie)).expect("extractible");

        assert_eq!(std::fs::read(&cible).expect("lisible"), b"une note");
    }

    /// CLI-013 : une altération est signalée explicitement.
    #[test]
    fn une_alteration_est_signalee_explicitement() {
        let atelier = atelier();
        // Tous les blobs sont altérés : l'ordre de `read_dir` n'est pas
        // spécifié, et n'en altérer qu'un rendrait ce test dépendant de lui.
        let objets = atelier.coffre.join("objects");
        for blob in std::fs::read_dir(&objets)
            .expect("listable")
            .filter_map(std::result::Result::ok)
        {
            let mut octets = std::fs::read(blob.path()).expect("lisible");
            octets[25] ^= 0x01;
            std::fs::write(blob.path(), &octets).expect("écrivable");
        }

        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        let resultat = executer(
            &mut contexte(&mut console, &atelier),
            &options(&["photos"], &atelier.sortie),
        );

        assert!(matches!(
            resultat,
            Err(CliError::Core(Error::Authentication | Error::Corrupted))
        ));
        assert!(console.tout_affiche().contains("Altération détectée"));
    }

    /// CLI-012 : l'espace insuffisant donne les deux nombres.
    #[test]
    fn l_espace_insuffisant_donne_les_deux_nombres() {
        let mut console = FakeConsole::new(&[], &[]);
        let atelier = atelier();
        let mut ctx = contexte(&mut console, &atelier);

        let erreur = expliquer(
            &mut ctx,
            Error::InsufficientSpace {
                needed: 5_000_000_000,
                available: 1_000_000,
            },
        );
        assert_eq!(erreur.code(), 6);
        let affiche = console.tout_affiche();
        assert!(affiche.contains("5.0 Go"));
        assert!(affiche.contains("1.0 Mo"));
    }

    #[test]
    fn les_autres_erreurs_passent_sans_commentaire() {
        let mut console = FakeConsole::new(&[], &[]);
        let atelier = atelier();
        let mut ctx = contexte(&mut console, &atelier);

        let erreur = expliquer(&mut ctx, Error::NotFound);
        assert_eq!(erreur.code(), 5);
        assert!(console.avertissements.is_empty());
    }

    /// CLI-022 : sans terminal, la confirmation d'écrasement ne peut pas être
    /// demandée, et l'extraction échoue plutôt que d'écraser.
    #[test]
    fn sans_terminal_l_ecrasement_ne_peut_pas_etre_confirme() {
        let atelier = atelier();
        std::fs::create_dir_all(&atelier.sortie).expect("créable");
        let cible = atelier.sortie.join("note.txt");
        std::fs::write(&cible, b"contenu preexistant").expect("écrivable");

        let note =
            vault_core::VaultPath::from_components([b"note.txt".to_vec()]).expect("chemin valide");
        let mut muette = FakeConsole::non_interactive();
        let mut ctx = contexte(&mut muette, &atelier);

        assert!(matches!(
            politique_de_collision(&mut ctx, &atelier.sortie, &note),
            Err(CliError::NotInteractive)
        ));
        assert_eq!(
            std::fs::read(&cible).expect("lisible"),
            b"contenu preexistant"
        );
    }

    #[test]
    fn les_usages_invalides_sont_refuses() {
        let atelier = atelier();
        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);

        assert!(matches!(
            executer(
                &mut contexte(&mut console, &atelier),
                &options(&[], &atelier.sortie)
            ),
            Err(CliError::Usage(_))
        ));
        assert!(matches!(
            executer(
                &mut contexte(&mut console, &atelier),
                &options(&["../evasion"], &atelier.sortie)
            ),
            Err(CliError::Core(Error::InvalidPath))
        ));
    }

    #[test]
    fn une_entree_absente_est_introuvable() {
        let atelier = atelier();
        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);

        assert!(matches!(
            executer(
                &mut contexte(&mut console, &atelier),
                &options(&["absente.txt"], &atelier.sortie)
            ),
            Err(CliError::Core(Error::NotFound))
        ));
    }

    /// Extraire la racine ne demande pas de confirmation globale : la
    /// collision se juge fichier par fichier.
    #[test]
    fn extraire_la_racine_ne_demande_rien() {
        let atelier = atelier();
        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);

        executer(
            &mut contexte(&mut console, &atelier),
            &options(&[""], &atelier.sortie),
        )
        .expect("extractible");

        assert!(atelier.sortie.join("note.txt").is_file());
        assert!(atelier.sortie.join("photos/plage.jpg").is_file());
        assert_eq!(console.invites.len(), 1, "seule la passphrase est demandée");
    }

    #[test]
    fn les_options_ont_un_debug() {
        assert!(format!("{:?}", options(&["x"], Path::new("/tmp"))).contains("Options"));
    }
}
