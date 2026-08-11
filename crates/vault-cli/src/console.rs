//! Dialogue avec l'utilisateur.
//!
//! Toute la logique des commandes passe par le trait [`Console`], jamais
//! directement par `stdin` et `stdout`. Ce n'est pas une abstraction gratuite :
//! c'est ce qui permet de vérifier en test, sans terminal, que la confirmation
//! d'irréversibilité est bien exigée, que `--yes` ne la contourne pas
//! (CLI-002), et qu'un terminal non interactif échoue au lieu de supposer une
//! réponse (CLI-022).
//!
//! **CLI-020, CLI-021** : rien de ce qui transite par ici n'est journalisé. La
//! passphrase ne sort jamais du [`SecretString`] qui la porte, et aucun nom
//! d'entrée du vault n'est écrit ailleurs que sur la sortie du processus.

pub mod tty;

use std::io::Write;

use vault_core::SecretString;

use crate::error::CliResult;

/// Canal de dialogue avec l'utilisateur.
pub trait Console {
    /// Lit une passphrase, sans écho.
    ///
    /// # Errors
    ///
    /// [`CliError::Usage`] si l'entrée n'est pas un terminal — CLI-001
    /// interdit de la recevoir autrement que par une saisie masquée.
    fn read_passphrase(&mut self, invite: &str) -> CliResult<SecretString>;

    /// Lit une ligne de réponse.
    ///
    /// # Errors
    ///
    /// [`CliError::Usage`] si l'entrée n'est pas un terminal.
    fn read_line(&mut self, invite: &str) -> CliResult<String>;

    /// Écrit un message d'information, sauf en mode silencieux.
    fn info(&mut self, texte: &str);

    /// Écrit un message qui doit être vu, mode silencieux compris.
    ///
    /// Les avertissements de FR-020 et FR-021 passent par ici : `--quiet`
    /// supprime la progression, pas les mises en garde.
    fn warn(&mut self, texte: &str);

    /// Écrit une sortie destinée à être lue par une machine.
    fn output(&mut self, texte: &str);
}

/// Console branchée sur le terminal.
///
/// **Deux canaux, et la distinction est normative** (FR-037, XFR-006) : la
/// sortie standard ne porte que ce qu'une machine doit lire — le rendu `--json`,
/// un listage, et surtout le **conteneur d'export**, qui doit y sortir seul.
/// Progression, invites, avertissements et erreurs passent tous par l'erreur
/// standard. Sans cette séparation, `vault export --to - | vault import -`
/// produirait un conteneur corrompu par la première ligne de progression.
pub struct Terminal<W: Write, E: Write> {
    sortie: W,
    erreur: E,
    interactive: bool,
    quiet: bool,
}

impl<W: Write, E: Write> Terminal<W, E> {
    /// Construit une console sur cette sortie standard et cette erreur
    /// standard.
    pub fn new(sortie: W, erreur: E, quiet: bool) -> Self {
        Self {
            sortie,
            erreur,
            interactive: tty::stdin_is_terminal(),
            quiet,
        }
    }

    fn ecrire(&mut self, texte: &str) {
        // Une sortie qui ne peut plus être écrite — tube fermé — ne doit pas
        // faire échouer une opération déjà engagée sur le vault.
        drop(writeln!(self.erreur, "{texte}"));
    }
}

impl<W: Write, E: Write> Console for Terminal<W, E> {
    fn read_passphrase(&mut self, invite: &str) -> CliResult<SecretString> {
        // L'invite va sur l'erreur standard, comme tout le reste du dialogue :
        // la sortie standard peut porter un conteneur.
        tty::read_passphrase(&mut self.erreur, self.interactive, invite)
    }

    fn read_line(&mut self, invite: &str) -> CliResult<String> {
        tty::read_line(&mut self.erreur, self.interactive, invite)
    }

    fn info(&mut self, texte: &str) {
        if !self.quiet {
            self.ecrire(texte);
        }
    }

    fn warn(&mut self, texte: &str) {
        self.ecrire(texte);
    }

    fn output(&mut self, texte: &str) {
        drop(writeln!(self.sortie, "{texte}"));
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! Console scriptée, pour vérifier les dialogues sans terminal.

    use super::{Console, SecretString};
    use crate::error::{CliError, CliResult};

    /// Console dont les réponses sont fixées d'avance.
    pub(crate) struct FakeConsole {
        pub interactive: bool,
        pub passphrases: Vec<String>,
        pub lignes: Vec<String>,
        pub invites: Vec<String>,
        pub sortie: Vec<String>,
        pub avertissements: Vec<String>,
    }

    impl FakeConsole {
        /// Console interactive qui répondra ces passphrases puis ces lignes.
        pub(crate) fn new(passphrases: &[&str], lignes: &[&str]) -> Self {
            Self {
                interactive: true,
                passphrases: passphrases.iter().rev().map(|s| (*s).to_owned()).collect(),
                lignes: lignes.iter().rev().map(|s| (*s).to_owned()).collect(),
                invites: Vec::new(),
                sortie: Vec::new(),
                avertissements: Vec::new(),
            }
        }

        /// Console non interactive : toute saisie y échoue (CLI-022).
        pub(crate) fn non_interactive() -> Self {
            let mut console = Self::new(&[], &[]);
            console.interactive = false;
            console
        }

        /// Tout ce qui a été affiché, avertissements compris.
        pub(crate) fn tout_affiche(&self) -> String {
            let mut tout = self.sortie.join("\n");
            tout.push('\n');
            tout.push_str(&self.avertissements.join("\n"));
            tout
        }
    }

    impl Console for FakeConsole {
        fn read_passphrase(&mut self, invite: &str) -> CliResult<SecretString> {
            if !self.interactive {
                return Err(CliError::NotInteractive);
            }
            self.invites.push(invite.to_owned());
            let reponse = self.passphrases.pop().unwrap_or_default();
            Ok(SecretString::from(reponse))
        }

        fn read_line(&mut self, invite: &str) -> CliResult<String> {
            if !self.interactive {
                return Err(CliError::NotInteractive);
            }
            self.invites.push(invite.to_owned());
            Ok(self.lignes.pop().unwrap_or_default())
        }

        fn info(&mut self, texte: &str) {
            self.sortie.push(texte.to_owned());
        }

        fn warn(&mut self, texte: &str) {
            self.avertissements.push(texte.to_owned());
        }

        fn output(&mut self, texte: &str) {
            self.sortie.push(texte.to_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CliError;

    /// Le mode silencieux supprime la progression et **conserve** les
    /// avertissements : `--quiet` ne doit pas faire taire FR-020 ni FR-021.
    #[test]
    fn le_mode_silencieux_ne_masque_pas_les_avertissements() {
        let mut sortie = Vec::new();
        let mut erreur = Vec::new();
        {
            let mut console = Terminal::new(&mut sortie, &mut erreur, true);
            console.info("progression");
            console.warn("avertissement");
            console.output("resultat");
        }
        let dialogue = String::from_utf8(erreur).expect("UTF-8");
        assert!(!dialogue.contains("progression"));
        assert!(dialogue.contains("avertissement"));

        assert_eq!(String::from_utf8(sortie).expect("UTF-8"), "resultat\n");
    }

    /// FR-037, XFR-006 : **rien** de ce qui n'est pas destiné à une machine ne
    /// doit atteindre la sortie standard. C'est ce qui permet à un conteneur
    /// d'y sortir seul.
    #[test]
    fn la_sortie_standard_ne_porte_que_le_resultat() {
        let mut sortie = Vec::new();
        let mut erreur = Vec::new();
        {
            let mut console = Terminal::new(&mut sortie, &mut erreur, false);
            console.info("progression");
            console.warn("avertissement");
            drop(console.read_line("invite : "));
        }
        assert!(sortie.is_empty(), "{sortie:?}");

        let dialogue = String::from_utf8(erreur).expect("UTF-8");
        assert!(dialogue.contains("progression"));
        assert!(dialogue.contains("avertissement"));
    }

    /// CLI-001, CLI-022 : sans terminal, la saisie échoue au lieu de lire un
    /// tube. La suite de tests s'exécute précisément dans ces conditions.
    #[test]
    fn sans_terminal_toute_saisie_echoue() {
        let mut sortie = Vec::new();
        let mut erreur = Vec::new();
        let mut console = Terminal::new(&mut sortie, &mut erreur, false);

        assert!(matches!(
            console.read_passphrase("Passphrase : "),
            Err(CliError::NotInteractive)
        ));
        assert!(matches!(
            console.read_line("Réponse : "),
            Err(CliError::NotInteractive)
        ));
    }

    /// Une sortie fermée ne doit pas faire échouer l'opération.
    #[test]
    fn une_sortie_cassee_est_absorbee() {
        struct Cassee;
        impl Write for Cassee {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("tube fermé"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("tube fermé"))
            }
        }

        assert!(Write::flush(&mut Cassee).is_err());

        let mut console = Terminal::new(Cassee, Cassee, false);
        console.info("perdu");
        console.warn("perdu");
        console.output("perdu");
        assert!(matches!(
            console.read_passphrase("x"),
            Err(CliError::NotInteractive)
        ));
    }

    #[test]
    fn la_console_scriptee_rend_les_reponses_prevues() {
        use super::fake::FakeConsole;

        use vault_core::ExposeSecret;

        let mut console = FakeConsole::new(&["secret"], &["OUI"]);
        assert_eq!(
            console
                .read_passphrase("Passphrase : ")
                .expect("lisible")
                .expose_secret(),
            "secret"
        );
        assert_eq!(console.read_line("Confirmez : ").expect("lisible"), "OUI");
        assert_eq!(console.invites.len(), 2);

        // Les réponses épuisées rendent une chaîne vide plutôt que de bloquer.
        assert_eq!(console.read_line("Encore ? ").expect("lisible"), "");

        console.info("info");
        console.warn("attention");
        console.output("sortie");
        assert!(console.tout_affiche().contains("attention"));

        let mut muette = FakeConsole::non_interactive();
        assert!(matches!(
            muette.read_passphrase("x"),
            Err(CliError::NotInteractive)
        ));
        assert!(matches!(
            muette.read_line("x"),
            Err(CliError::NotInteractive)
        ));
    }
}
