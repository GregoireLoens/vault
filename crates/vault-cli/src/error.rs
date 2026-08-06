//! Erreurs de la ligne de commande et codes de retour.
//!
//! Le tableau des codes est celui de `contracts/cli.md`. Deux règles le
//! gouvernent :
//!
//! - **CLI-019** : le code 3 et son message sont **identiques** que la
//!   passphrase soit fausse ou que le vault ait été altéré. Distinguer les deux
//!   renseignerait un attaquant sur ce qu'il a déjà réussi.
//! - **CLI-021** : aucun message ne contient de nom d'entrée du vault. Les
//!   erreurs de `vault-core` respectent déjà cette règle (C-025) ; celles
//!   ajoutées ici s'y tiennent aussi.

use vault_core::Error;

/// Résultat d'une commande.
pub type CliResult<T> = Result<T, CliError>;

/// Erreur remontée par la ligne de commande.
#[derive(Debug)]
pub enum CliError {
    /// Une opération de la bibliothèque a échoué.
    Core(Error),
    /// L'usage est invalide : arguments incohérents.
    Usage(String),
    /// Une saisie était nécessaire sur un terminal non interactif (CLI-022).
    NotInteractive,
    /// L'utilisateur a refusé une confirmation.
    Refused,
    /// Défaillance d'entrée-sortie hors du vault.
    Io(std::io::Error),
}

impl CliError {
    /// Code de retour du processus.
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            Self::Usage(_) | Self::NotInteractive | Self::Refused => 2,
            Self::Io(_) => 1,
            Self::Core(erreur) => match erreur {
                Error::Authentication => 3,
                Error::AlreadyInUse => 4,
                Error::NotFound => 5,
                Error::InsufficientSpace { .. } => 6,
                Error::UnsupportedFormatVersion { .. } => 7,
                Error::WeakPassphrase { .. } | Error::InvalidPath | Error::InvalidKdfParams => 2,
                _ => 1,
            },
        }
    }

    /// Message destiné à l'utilisateur.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            // CLI-019 : message constant, quelle que soit la cause réelle.
            Self::Core(Error::Authentication) => {
                "Échec d'authentification : passphrase erronée ou vault altéré.".to_owned()
            }
            Self::Core(Error::AlreadyInUse) => {
                "Ce vault est déjà ouvert par un autre processus.".to_owned()
            }
            Self::Core(erreur) => erreur.to_string(),
            Self::Usage(details) => details.clone(),
            Self::NotInteractive => {
                "Cette commande demande une saisie, et l'entrée standard n'est pas un terminal."
                    .to_owned()
            }
            Self::Refused => "Opération annulée.".to_owned(),
            Self::Io(erreur) => erreur.to_string(),
        }
    }
}

impl From<Error> for CliError {
    fn from(erreur: Error) -> Self {
        Self::Core(erreur)
    }
}

impl From<std::io::Error> for CliError {
    fn from(erreur: std::io::Error) -> Self {
        Self::Io(erreur)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chaque_erreur_a_le_code_du_contrat() {
        let cas: [(CliError, i32); 12] = [
            (CliError::Core(Error::Authentication), 3),
            (CliError::Core(Error::AlreadyInUse), 4),
            (CliError::Core(Error::NotFound), 5),
            (
                CliError::Core(Error::InsufficientSpace {
                    needed: 2,
                    available: 1,
                }),
                6,
            ),
            (
                CliError::Core(Error::UnsupportedFormatVersion {
                    found: 2,
                    supported: 1,
                }),
                7,
            ),
            (CliError::Core(Error::WeakPassphrase { minimum: 12 }), 2),
            (CliError::Core(Error::InvalidPath), 2),
            (CliError::Core(Error::InvalidKdfParams), 2),
            (CliError::Core(Error::Corrupted), 1),
            (CliError::Usage("mauvais argument".to_owned()), 2),
            (CliError::NotInteractive, 2),
            (CliError::Refused, 2),
        ];

        let codes: Vec<i32> = cas.iter().map(|(erreur, _)| erreur.code()).collect();
        assert_eq!(codes, vec![3, 4, 5, 6, 7, 2, 2, 2, 1, 2, 2, 2]);
        for (erreur, _) in &cas {
            assert!(!erreur.message().is_empty());
            assert!(!format!("{erreur:?}").is_empty());
        }

        let io = CliError::from(std::io::Error::other("disque"));
        assert_eq!(io.code(), 1);
        assert!(io.message().contains("disque"));
        assert_eq!(CliError::from(Error::NotFound).code(), 5);
    }

    /// CLI-019 : le message du code 3 ne dit pas laquelle des deux causes s'est
    /// produite, et il est le même dans les deux cas — c'est le même variant.
    #[test]
    fn le_message_d_authentification_est_constant_et_avare() {
        let message = CliError::Core(Error::Authentication).message();
        assert_eq!(message, CliError::Core(Error::Authentication).message());
        assert!(
            message.contains("ou"),
            "les deux causes restent indistinctes"
        );
        assert!(!message.contains("index"));
        assert!(!message.contains("en-tête"));
    }
}
