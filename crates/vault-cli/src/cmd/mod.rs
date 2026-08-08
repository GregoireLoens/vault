//! Commandes de la ligne de commande.
//!
//! Chaque commande est une fonction qui reçoit un [`Contexte`] — la console,
//! l'emplacement du vault et les options communes — et rend un résultat. Aucune
//! d'elles ne touche `stdin` ni `stdout` directement : c'est ce qui les rend
//! vérifiables sans terminal.

pub mod add;
pub mod create;
pub mod extract;
pub mod info;
pub mod ls;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use vault_core::{UnlockedVault, Vault, VaultPath};

use crate::console::Console;
use crate::error::{CliError, CliResult};
use crate::prompt;

/// Contexte d'exécution d'une commande.
pub struct Contexte<'a> {
    /// Canal de dialogue avec l'utilisateur.
    pub console: &'a mut dyn Console,
    /// Emplacement du vault.
    pub vault_dir: PathBuf,
    /// `--yes` : préaccorde les confirmations ordinaires.
    pub yes: bool,
    /// `--json` : sortie lisible par une machine.
    pub json: bool,
    /// `--idle-timeout` : conservé sans effet (CLI-023, FR-010 différé).
    pub idle_timeout: Option<Duration>,
}

impl Contexte<'_> {
    /// Ouvre et déverrouille le vault.
    ///
    /// FR-012 : le refus d'accès concurrent est prononcé **avant** la saisie.
    /// Réclamer une passphrase pour annoncer ensuite que le vault était déjà
    /// ouvert ferait payer à l'utilisateur une saisie qui ne pouvait pas
    /// aboutir. La vérification qui fait foi reste celle de [`Vault::unlock`],
    /// qui prend le verrou et le garde.
    ///
    /// # Errors
    ///
    /// Celles de [`Vault::open`] et [`Vault::unlock`], plus
    /// [`CliError::NotInteractive`] si la passphrase ne peut pas être saisie.
    pub fn deverrouiller(&mut self) -> CliResult<UnlockedVault> {
        let vault = Vault::open(&self.vault_dir)?;
        vault.check_available()?;
        let passphrase = prompt::passphrase_existante(self.console)?;
        let mut session = vault.unlock(passphrase)?;
        // CLI-023 : la valeur est conservée et ne déclenche rien. FR-010 est
        // différé — chaque commande est déjà une session isolée, dont les
        // secrets disparaissent à la fin du processus.
        session.set_idle_timeout(self.idle_timeout);
        Ok(session)
    }
}

/// Convertit un chemin de la ligne de commande en chemin de vault.
///
/// # Errors
///
/// [`vault_core::Error::InvalidPath`] si le chemin est absolu ou remonte d'un
/// cran (VR-I4).
pub fn chemin_de_vault(brut: &Path) -> CliResult<VaultPath> {
    Ok(VaultPath::from_os_path(brut)?)
}

/// Formate une taille en octets pour l'affichage.
// La perte de précision est sans conséquence : cette valeur ne sert qu'à un
// affichage arrondi à la décimale, jamais à un calcul.
#[allow(clippy::cast_precision_loss)]
#[must_use]
pub fn taille_lisible(octets: u64) -> String {
    const UNITES: [&str; 5] = ["o", "Ko", "Mo", "Go", "To"];
    let mut valeur = octets as f64;
    let mut rang = 0;
    while valeur >= 1000.0 && rang + 1 < UNITES.len() {
        valeur /= 1000.0;
        rang += 1;
    }
    if rang == 0 {
        format!("{octets} o")
    } else {
        format!("{valeur:.1} {}", UNITES[rang])
    }
}

/// Échappe une chaîne pour l'insérer dans du JSON.
#[must_use]
pub fn json_echappe(texte: &str) -> String {
    let mut sortie = String::with_capacity(texte.len() + 2);
    for caractere in texte.chars() {
        match caractere {
            '"' => sortie.push_str("\\\""),
            '\\' => sortie.push_str("\\\\"),
            '\n' => sortie.push_str("\\n"),
            '\r' => sortie.push_str("\\r"),
            '\t' => sortie.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(sortie, "\\u{:04x}", c as u32);
            }
            c => sortie.push(c),
        }
    }
    sortie
}

/// Refuse une option incompatible avec une autre.
///
/// # Errors
///
/// [`CliError::Usage`] si les deux sont demandées ensemble.
pub fn refuser_si(condition: bool, message: &str) -> CliResult<()> {
    if condition {
        return Err(CliError::Usage(message.to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn les_tailles_sont_lisibles() {
        assert_eq!(taille_lisible(0), "0 o");
        assert_eq!(taille_lisible(999), "999 o");
        assert_eq!(taille_lisible(1000), "1.0 Ko");
        assert_eq!(taille_lisible(2_400_000), "2.4 Mo");
        assert_eq!(taille_lisible(1_200_000_000), "1.2 Go");
        assert_eq!(taille_lisible(5_000_000_000_000), "5.0 To");
        assert_eq!(taille_lisible(u64::MAX), "18446744.1 To");
    }

    #[test]
    fn l_echappement_json_couvre_les_cas_delicats() {
        assert_eq!(json_echappe("simple"), "simple");
        assert_eq!(json_echappe("gui\"llemet"), "gui\\\"llemet");
        assert_eq!(json_echappe("anti\\slash"), "anti\\\\slash");
        assert_eq!(json_echappe("ligne\nsuite"), "ligne\\nsuite");
        assert_eq!(json_echappe("retour\rchariot"), "retour\\rchariot");
        assert_eq!(json_echappe("tabu\tlation"), "tabu\\tlation");
        assert_eq!(json_echappe("cloche\u{0007}"), "cloche\\u0007");
        assert_eq!(json_echappe("accentué"), "accentué");
    }

    #[test]
    fn un_chemin_hostile_est_refuse() {
        assert!(chemin_de_vault(Path::new("documents/note.txt")).is_ok());
        assert!(matches!(
            chemin_de_vault(Path::new("../evasion")),
            Err(CliError::Core(vault_core::Error::InvalidPath))
        ));
    }

    #[test]
    fn les_options_incompatibles_sont_refusees() {
        assert!(refuser_si(false, "jamais").is_ok());
        assert!(matches!(
            refuser_si(true, "--move et --copy s'excluent"),
            Err(CliError::Usage(message)) if message.contains("s'excluent")
        ));
    }
}
