//! `vault passwd` — T063.
//!
//! FR-033 à FR-035, CLI-016, CLI-017.
//!
//! **CLI-016** : la passphrase actuelle est redemandée, puis la nouvelle avec
//! confirmation. Redemander l'actuelle peut sembler redondant — la session
//! qu'ouvre cette commande la connaît déjà — mais c'est justement ce que la
//! bibliothèque ne fait pas (C-019 bis) : elle change la passphrase d'une
//! session **déjà déverrouillée**, sans rien redemander. Ici, la commande
//! ouvre elle-même la session, donc la saisie a bien lieu.
//!
//! **CLI-017** : le message final dit que l'opération est immédiate et ne
//! réécrit pas le contenu. Sans lui, un utilisateur qui vient de changer la
//! passphrase d'un vault de quatre cents gigaoctets en une demi-seconde
//! conclurait à un échec silencieux. Le message est affiché **après** le
//! succès, au moment précis où la rapidité surprend.
//!
//! # Ce que cette commande n'expose pas
//!
//! [`vault_core::UnlockedVault::change_passphrase`] permet de relever les
//! paramètres Argon2id au passage (C-023). `contracts/cli.md` ne prévoit aucune
//! option pour cela sur `passwd`, et elle n'en offre donc pas : les paramètres
//! du vault sont conservés. La capacité existe dans la bibliothèque, prête pour
//! le jour où le contrat la réclamera.

use crate::cmd::Contexte;
use crate::error::CliResult;
use crate::prompt;

/// CLI-017 : ce que l'utilisateur doit savoir devant la rapidité de
/// l'opération.
const IMMEDIATE: &str = "L'opération est immédiate et ne réécrit pas le contenu : seule la clé \
qui protège le vault a été réenveloppée. Vos fichiers n'ont pas été touchés.";

/// Change la passphrase du vault.
///
/// # Errors
///
/// - celles du déverrouillage — dont [`vault_core::Error::Authentication`] si
///   la passphrase actuelle est erronée ;
/// - [`crate::error::CliError::Usage`] si les deux saisies de la nouvelle
///   diffèrent ;
/// - [`vault_core::Error::WeakPassphrase`] si la nouvelle est trop courte ;
/// - [`vault_core::Error::Io`] si l'en-tête ne peut pas être remplacé — auquel
///   cas l'ancienne passphrase reste valide.
pub fn executer(contexte: &mut Contexte) -> CliResult<()> {
    let mut session = contexte.deverrouiller()?;
    let nouvelle = prompt::passphrase_neuve(contexte.console)?;

    session.change_passphrase(nouvelle, None)?;

    if contexte.json {
        contexte.console.output("{\"changed\":true}");
    } else {
        contexte.console.info("Passphrase changée.");
        contexte.console.info(IMMEDIATE);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::console::fake::FakeConsole;
    use crate::error::CliError;

    const ANCIENNE: &str = "une passphrase bien assez longue";
    const NOUVELLE: &str = "une toute autre passphrase, aussi longue";

    fn coffre_neuf(atelier: &Path) -> PathBuf {
        let coffre = atelier.join("coffre");
        vault_core::Vault::create(
            &coffre,
            vault_core::SecretString::from(ANCIENNE.to_owned()),
            vault_core::KdfParams::new(64, 1, 1).expect("valides"),
        )
        .expect("créable")
        .lock();
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

    fn ouvre_avec(coffre: &Path, passphrase: &str) -> bool {
        vault_core::Vault::open(coffre)
            .expect("ouvrable")
            .unlock(vault_core::SecretString::from(passphrase.to_owned()))
            .is_ok()
    }

    /// CLI-016 : l'actuelle, puis la nouvelle deux fois. CLI-017 : le message
    /// qui explique la rapidité.
    #[test]
    fn la_passphrase_est_remplacee_apres_trois_saisies() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());
        let mut console = FakeConsole::new(&[ANCIENNE, NOUVELLE, NOUVELLE], &[]);

        executer(&mut contexte(&mut console, &coffre)).expect("changeable");

        assert_eq!(console.invites.len(), 3, "{:?}", console.invites);
        let affiche = console.tout_affiche();
        assert!(affiche.contains("Passphrase changée"));
        assert!(affiche.contains("ne réécrit pas le contenu"), "{affiche}");

        assert!(!ouvre_avec(&coffre, ANCIENNE));
        assert!(ouvre_avec(&coffre, NOUVELLE));
    }

    /// Une passphrase actuelle erronée est refusée, et la nouvelle n'est même
    /// pas demandée.
    #[test]
    fn une_passphrase_actuelle_erronee_arrete_tout() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());
        let mut console = FakeConsole::new(&["une passphrase parfaitement fausse"], &[]);

        assert!(matches!(
            executer(&mut contexte(&mut console, &coffre)),
            Err(CliError::Core(vault_core::Error::Authentication))
        ));
        assert_eq!(console.invites.len(), 1, "rien d'autre n'a été demandé");
        assert!(ouvre_avec(&coffre, ANCIENNE));
    }

    /// Deux saisies discordantes, ou une nouvelle trop courte : refus, et
    /// l'ancienne passphrase reste valide.
    #[test]
    fn une_nouvelle_passphrase_invalide_ne_change_rien() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());

        let mut console = FakeConsole::new(&[ANCIENNE, NOUVELLE, "autre chose entierement"], &[]);
        assert!(matches!(
            executer(&mut contexte(&mut console, &coffre)),
            Err(CliError::Usage(_))
        ));

        let mut console = FakeConsole::new(&[ANCIENNE, "onze carac", "onze carac"], &[]);
        assert!(matches!(
            executer(&mut contexte(&mut console, &coffre)),
            Err(CliError::Core(vault_core::Error::WeakPassphrase {
                minimum: 12
            }))
        ));

        assert!(ouvre_avec(&coffre, ANCIENNE));
    }

    #[test]
    fn la_sortie_json_annonce_le_changement() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());
        let mut console = FakeConsole::new(&[ANCIENNE, NOUVELLE, NOUVELLE], &[]);
        let mut ctx = contexte(&mut console, &coffre);
        ctx.json = true;

        executer(&mut ctx).expect("changeable");
        assert!(console.tout_affiche().contains("{\"changed\":true}"));
    }

    /// CLI-022 : sans terminal, rien ne se passe — pas même la première saisie.
    #[test]
    fn sans_terminal_la_commande_echoue() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());
        let mut muette = FakeConsole::non_interactive();

        assert!(matches!(
            executer(&mut contexte(&mut muette, &coffre)),
            Err(CliError::NotInteractive)
        ));
        assert!(ouvre_avec(&coffre, ANCIENNE));
    }
}
