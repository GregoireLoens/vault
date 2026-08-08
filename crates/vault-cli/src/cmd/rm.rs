//! `vault rm` — T060.
//!
//! FR-031, FR-032, CLI-014, CLI-015. La bibliothèque supprime sans rien
//! demander (C-019) ; tout ce que ce module ajoute est ce qui protège
//! l'utilisateur de lui-même.
//!
//! - **CLI-014** : la confirmation rappelle qu'il n'existe **ni corbeille ni
//!   annulation**. Un vault n'a pas de fichier supprimé récupérable, et ne
//!   peut pas en avoir : le contenu est chiffré, et le blob délié n'est plus
//!   référencé par rien. `--yes` contourne cette confirmation — c'est une
//!   confirmation ordinaire, contrairement à celle de la création (CLI-002).
//! - **CLI-015** : `--recursive` est requis pour un dossier non vide.
//!
//! # Ce que la confirmation annonce
//!
//! Le nombre d'entrées est calculé **avant** de demander, en comptant la
//! descendance réelle de chaque chemin. Demander « supprimer photos ? » quand
//! la réponse emporte quatre cents fichiers serait une confirmation de façade.
//! Pour la même raison, l'absence d'une entrée et l'exigence de `--recursive`
//! sont constatées avant la question plutôt qu'après : mieux vaut refuser tout
//! de suite que faire confirmer une opération qui ne pouvait pas aboutir.

use std::path::PathBuf;

use vault_core::{Error, UnlockedVault, VaultPath};

use crate::cmd::{Contexte, chemin_de_vault};
use crate::error::{CliError, CliResult};
use crate::prompt;

/// Rappel affiché avant la confirmation (CLI-014).
const AVERTISSEMENT: &str =
    "La suppression est définitive : il n'existe ni corbeille, ni annulation, ni récupération.";

/// Options de `vault rm`.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Entrées à supprimer.
    pub chemins: Vec<PathBuf>,
    /// `--recursive` : emporte la descendance d'un dossier.
    pub recursive: bool,
}

/// Supprime des entrées du vault.
///
/// # Errors
///
/// - [`CliError::Usage`] si aucun chemin n'est donné ;
/// - [`CliError::Refused`] si la confirmation est refusée ;
/// - [`vault_core::Error::NotFound`] si un chemin n'existe pas ;
/// - [`vault_core::Error::DirectoryNotEmpty`] si un dossier peuplé est visé
///   sans `--recursive` ;
/// - celles de [`UnlockedVault::remove`].
pub fn executer(contexte: &mut Contexte, options: &Options) -> CliResult<()> {
    if options.chemins.is_empty() {
        return Err(CliError::Usage("Aucun chemin à supprimer.".to_owned()));
    }

    let chemins = options
        .chemins
        .iter()
        .map(|chemin| chemin_de_vault(chemin))
        .collect::<CliResult<Vec<_>>>()?;

    let mut session = contexte.deverrouiller()?;
    let total = compter(&session, &chemins, options.recursive)?;

    confirmer_suppression(contexte, total)?;

    let mut retirees = 0usize;
    for chemin in &chemins {
        retirees += session.remove(chemin, options.recursive)?;
    }

    if contexte.json {
        contexte
            .console
            .output(&format!("{{\"removed\":{retirees}}}"));
    } else {
        contexte
            .console
            .info(&format!("{retirees} entrée(s) supprimée(s)."));
    }
    Ok(())
}

/// Présente l'avertissement et exige la confirmation (CLI-014).
///
/// L'avertissement n'est pas affiché sous `--yes` : il n'y a plus de question
/// qu'il accompagnerait, et le répéter après coup ne protège personne.
///
/// # Errors
///
/// - [`CliError::NotInteractive`] sans terminal et sans `--yes` (CLI-022) ;
/// - [`CliError::Refused`] si la réponse n'est pas affirmative.
fn confirmer_suppression(contexte: &mut Contexte, total: usize) -> CliResult<()> {
    if !contexte.yes {
        contexte.console.warn(AVERTISSEMENT);
    }
    let accepte = prompt::confirmer(
        contexte.console,
        &format!("Supprimer {total} entrée(s) ?"),
        contexte.yes,
    )?;
    if accepte {
        Ok(())
    } else {
        Err(CliError::Refused)
    }
}

/// Compte les entrées que l'opération emportera, et refuse d'avance ce que la
/// bibliothèque refuserait.
///
/// Les deux règles vérifiées ici sont celles de [`UnlockedVault::remove`], qui
/// reste seule autorité : on ne les anticipe que pour ne pas faire confirmer
/// une suppression impossible.
fn compter(session: &UnlockedVault, chemins: &[VaultPath], recursive: bool) -> CliResult<usize> {
    let mut total = 0usize;
    for chemin in chemins {
        let sous = session.list(Some(chemin));
        if sous.is_empty() {
            return Err(CliError::Core(Error::NotFound));
        }
        if sous.len() > 1 && !recursive {
            return Err(CliError::Core(Error::DirectoryNotEmpty));
        }
        total += sous.len();
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::console::fake::FakeConsole;

    const PASSPHRASE: &str = "une passphrase bien assez longue";

    /// Prépare un vault contenant `note.txt` et `photos/plage.jpg`.
    fn coffre_peuple(atelier: &Path) -> PathBuf {
        let coffre = atelier.join("coffre");
        let source = atelier.join("source");
        std::fs::create_dir_all(source.join("photos")).expect("créable");
        std::fs::write(source.join("note.txt"), b"une note").expect("écrivable");
        std::fs::write(source.join("photos/plage.jpg"), vec![0u8; 2400]).expect("écrivable");

        let mut vault = vault_core::Vault::create(
            &coffre,
            vault_core::SecretString::from(PASSPHRASE.to_owned()),
            vault_core::KdfParams::new(64, 1, 1).expect("valides"),
        )
        .expect("créable");
        vault
            .add_dir(
                &source,
                &VaultPath::root(),
                vault_core::AddMode::Copy,
                vault_core::OnConflict::Fail,
                &mut |_| {},
            )
            .expect("ajoutable");
        vault.lock();
        coffre
    }

    fn contexte<'a>(console: &'a mut FakeConsole, coffre: &Path) -> Contexte<'a> {
        Contexte {
            console,
            vault_dir: coffre.to_path_buf(),
            yes: false,
            json: false,
            idle_timeout: None,
        }
    }

    fn options(chemins: &[&str], recursive: bool) -> Options {
        Options {
            chemins: chemins.iter().map(PathBuf::from).collect(),
            recursive,
        }
    }

    /// CLI-014 : l'avertissement est présenté, et la confirmation exigée.
    #[test]
    fn la_suppression_est_confirmee_apres_avertissement() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());
        let mut console = FakeConsole::new(&[PASSPHRASE], &["o"]);

        executer(
            &mut contexte(&mut console, &coffre),
            &options(&["note.txt"], false),
        )
        .expect("supprimable");

        let affiche = console.tout_affiche();
        assert!(affiche.contains("ni corbeille"), "{affiche}");
        assert!(affiche.contains("1 entrée(s) supprimée(s)"));
    }

    /// CLI-014 : un refus n'emporte rien.
    #[test]
    fn un_refus_ne_supprime_rien() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());
        let mut console = FakeConsole::new(&[PASSPHRASE], &["n"]);

        assert!(matches!(
            executer(
                &mut contexte(&mut console, &coffre),
                &options(&["note.txt"], false)
            ),
            Err(CliError::Refused)
        ));

        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        let session = contexte(&mut console, &coffre)
            .deverrouiller()
            .expect("déverrouillable");
        assert!(
            session
                .stat(&chemin_de_vault(Path::new("note.txt")).expect("valide"))
                .is_ok()
        );
    }

    /// CLI-014 : `--yes` préaccorde, et l'avertissement ne s'affiche pas — il
    /// n'y a plus de question à accompagner.
    #[test]
    fn yes_preaccorde_la_confirmation() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());
        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        let mut ctx = contexte(&mut console, &coffre);
        ctx.yes = true;

        executer(&mut ctx, &options(&["note.txt"], false)).expect("supprimable");
        assert!(!console.tout_affiche().contains("ni corbeille"));
    }

    /// CLI-015 : un dossier peuplé exige `--recursive`, et le refus arrive
    /// **avant** la confirmation.
    #[test]
    fn un_dossier_peuple_exige_recursive() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());
        let mut console = FakeConsole::new(&[PASSPHRASE], &["o"]);

        assert!(matches!(
            executer(
                &mut contexte(&mut console, &coffre),
                &options(&["photos"], false)
            ),
            Err(CliError::Core(Error::DirectoryNotEmpty))
        ));
        assert_eq!(
            console.invites.len(),
            1,
            "seule la passphrase a été demandée : {:?}",
            console.invites
        );

        let mut console = FakeConsole::new(&[PASSPHRASE], &["o"]);
        executer(
            &mut contexte(&mut console, &coffre),
            &options(&["photos"], true),
        )
        .expect("supprimable");
        assert!(console.tout_affiche().contains("2 entrée(s) supprimée(s)"));
    }

    /// L'entrée absente est signalée avant la confirmation, elle aussi.
    #[test]
    fn une_entree_absente_est_signalee_avant_la_question() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());
        let mut console = FakeConsole::new(&[PASSPHRASE], &["o"]);

        assert!(matches!(
            executer(
                &mut contexte(&mut console, &coffre),
                &options(&["absent.txt"], false)
            ),
            Err(CliError::Core(Error::NotFound))
        ));
        assert_eq!(console.invites.len(), 1);
    }

    /// CLI-022 : sans terminal et sans `--yes`, la confirmation ne peut pas
    /// être demandée, et rien n'est supprimé plutôt qu'une réponse supposée.
    #[test]
    fn sans_terminal_la_suppression_ne_peut_pas_etre_confirmee() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());
        let mut muette = FakeConsole::non_interactive();

        assert!(matches!(
            confirmer_suppression(&mut contexte(&mut muette, &coffre), 1),
            Err(CliError::NotInteractive)
        ));
    }

    #[test]
    fn plusieurs_chemins_partent_ensemble() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());
        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        let mut ctx = contexte(&mut console, &coffre);
        ctx.yes = true;
        ctx.json = true;

        executer(&mut ctx, &options(&["note.txt", "photos"], true)).expect("supprimable");
        assert!(console.tout_affiche().contains("{\"removed\":3}"));
    }

    #[test]
    fn les_chemins_invalides_ou_absents_sont_refuses() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());
        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);

        assert!(matches!(
            executer(&mut contexte(&mut console, &coffre), &options(&[], false)),
            Err(CliError::Usage(_))
        ));
        assert!(matches!(
            executer(
                &mut contexte(&mut console, &coffre),
                &options(&["../evasion"], false)
            ),
            Err(CliError::Core(Error::InvalidPath))
        ));
        assert!(console.invites.is_empty(), "rien n'a été demandé");
        assert!(format!("{:?}", Options::default()).contains("Options"));
    }
}
