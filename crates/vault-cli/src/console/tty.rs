//! Saisie sur le terminal.
//!
//! # Pourquoi ce fichier est exclu de la mesure de couverture
//!
//! Ces fonctions **ne peuvent pas s'exécuter sur la plateforme d'intégration
//! continue** : un exécuteur n'a pas de terminal, et CLI-001 interdit de
//! recevoir la passphrase autrement que par une saisie masquée — donc de la
//! lire depuis un tube, ce qui les rendrait testables au prix de la règle
//! qu'elles servent.
//!
//! C'est la seule catégorie d'exclusion que le principe VIII admet : du code
//! qui ne peut pas s'exécuter sur la plateforme d'intégration continue.
//! L'exclusion est déclarée dans `scripts/dev.sh` et dans
//! `.github/workflows/ci.yml`, elle porte sur ce fichier et sur lui seul, et ce
//! fichier ne contient que la saisie elle-même.
//!
//! **La garde de CLI-022 y figure quand même** et reste exercée par les tests,
//! qui s'exécutent précisément sans terminal : ils vérifient qu'une saisie
//! exigée sans terminal échoue au lieu de supposer une réponse. Seul le
//! *décompte* de ces lignes est écarté, pas leur vérification.
//!
//! Tout ce qui est décidé à partir de ces valeurs — exiger `OUI`, refuser que
//! `--yes` contourne l'avertissement, choisir une politique de collision — vit
//! dans [`crate::prompt`] et [`crate::cmd`], et y est mesuré.

use std::io::{IsTerminal, Write};

use vault_core::SecretString;

use crate::error::{CliError, CliResult};

/// Vrai si l'entrée standard est un terminal.
#[must_use]
pub fn stdin_is_terminal() -> bool {
    std::io::stdin().is_terminal()
}

/// Vrai si la sortie standard est un terminal.
///
/// Sert XFR-005 : `vault export --to -` refuse d'écrire des octets binaires sur
/// un terminal. **La détection est ici, la décision est dans
/// [`crate::cmd::export`]** — et c'est cette décision qui est mesurée, ce
/// fichier étant le seul exclu de la couverture.
#[must_use]
pub fn stdout_is_terminal() -> bool {
    std::io::stdout().is_terminal()
}

/// Lit une passphrase sur le terminal, sans écho.
///
/// # Errors
///
/// [`CliError::NotInteractive`] si l'entrée n'est pas un terminal (CLI-001,
/// CLI-022), ou l'erreur d'entrée-sortie remontée par le terminal.
pub fn read_passphrase<W: Write>(
    sortie: &mut W,
    interactive: bool,
    invite: &str,
) -> CliResult<SecretString> {
    if !interactive {
        return Err(CliError::NotInteractive);
    }
    drop(write!(sortie, "{invite}"));
    drop(sortie.flush());
    Ok(SecretString::from(rpassword::read_password()?))
}

/// Lit une ligne de réponse sur le terminal.
///
/// # Errors
///
/// [`CliError::NotInteractive`] si l'entrée n'est pas un terminal (CLI-022),
/// ou l'erreur d'entrée-sortie remontée par le terminal.
pub fn read_line<W: Write>(sortie: &mut W, interactive: bool, invite: &str) -> CliResult<String> {
    if !interactive {
        return Err(CliError::NotInteractive);
    }
    drop(write!(sortie, "{invite}"));
    drop(sortie.flush());
    let mut ligne = String::new();
    std::io::stdin().read_line(&mut ligne)?;
    Ok(ligne.trim_end_matches(['\r', '\n']).to_owned())
}
