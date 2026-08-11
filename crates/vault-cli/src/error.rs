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
                // XFR-060 : un variant **distinct** d'`AlreadyExists`, qui
                // continue de rendre 1 pour la collision d'entrée d'`add
                // --on-conflict fail`. Les confondre ferait changer le code de
                // retour d'`add` (D-210).
                Error::DestinationOccupied => 8,
                Error::TransportFailed => 9,
                // FR-029a, FR-029b : le compte rendu de la destination se
                // réduit à son code de retour, et c'est donc **celui-là** qui
                // remonte. Le traduire reviendrait à réinterpréter un verdict
                // qu'on n'a pas rendu ; la cause, elle, a déjà atteint le
                // terminal par l'erreur standard héritée du sous-processus.
                Error::RemoteFailed { code } => *code,
                Error::WeakPassphrase { .. } | Error::InvalidPath | Error::InvalidKdfParams => 2,
                // Corruption, entrée non gérée, dossier peuplé, nom
                // irreprésentable, entrée-sortie : erreur générique.
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
            // CLI-015 : dire que le dossier n'est pas vide n'apprend pas quoi
            // faire. Le nombre de descendants reste tu (C-025) : c'est du
            // contenu du vault.
            Self::Core(Error::DirectoryNotEmpty) => {
                "Ce dossier n'est pas vide. Ajoutez --recursive pour le supprimer avec tout \
ce qu'il contient."
                    .to_owned()
            }
            // XFR-012 : le refus le plus courant de l'import. Le message dit
            // quoi faire, comme celui du dossier peuplé, et ne nomme rien du
            // contenu de la destination (C-025, CLI-021).
            Self::Core(Error::DestinationOccupied) => {
                "Un vault occupe déjà cette destination. Ajoutez --replace pour le remplacer : \
l'ancien sera déplacé, jamais supprimé."
                    .to_owned()
            }
            Self::Core(Error::UnrepresentableName) => {
                "Ce nom de fichier n'est pas représentable sur ce système de fichiers. \
L'entrée reste intacte dans le vault : elle s'extraira sur un système dont les \
règles de nommage l'acceptent."
                    .to_owned()
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
        let cas: [(CliError, i32); 16] = [
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
            (CliError::Core(Error::DestinationOccupied), 8),
            (CliError::Core(Error::TransportFailed), 9),
            (CliError::Core(Error::RemoteFailed { code: 7 }), 7),
            (CliError::Core(Error::UnrepresentableName), 1),
            (CliError::Core(Error::Corrupted), 1),
            (CliError::Usage("mauvais argument".to_owned()), 2),
            (CliError::NotInteractive, 2),
            (CliError::Refused, 2),
        ];

        let codes: Vec<i32> = cas.iter().map(|(erreur, _)| erreur.code()).collect();
        assert_eq!(codes, vec![3, 4, 5, 6, 7, 2, 2, 2, 8, 9, 7, 1, 1, 2, 2, 2]);
        for (erreur, _) in &cas {
            assert!(!erreur.message().is_empty());
            assert!(!format!("{erreur:?}").is_empty());
        }

        let io = CliError::from(std::io::Error::other("disque"));
        assert_eq!(io.code(), 1);
        assert!(io.message().contains("disque"));
        assert_eq!(CliError::from(Error::NotFound).code(), 5);
    }

    /// XFR-060 : les codes 8 et 9 s'ajoutent **sans** que les codes 0 à 7
    /// changent de sens. Le point de vigilance de D-210 se vérifie ici :
    /// `AlreadyExists` — la collision d'entrée d'`add --on-conflict fail` —
    /// rend toujours 1, et `DestinationOccupied` est un variant distinct.
    #[test]
    fn les_codes_ajoutes_ne_deplacent_aucun_code_existant() {
        assert_eq!(CliError::Core(Error::AlreadyExists).code(), 1);
        assert_eq!(CliError::Core(Error::DestinationOccupied).code(), 8);
        assert_eq!(CliError::Core(Error::TransportFailed).code(), 9);

        // Les deux erreurs sont bien distinctes, et pas deux noms de la même.
        assert_ne!(
            CliError::Core(Error::AlreadyExists).code(),
            CliError::Core(Error::DestinationOccupied).code()
        );
        assert_ne!(
            CliError::Core(Error::AlreadyExists).message(),
            CliError::Core(Error::DestinationOccupied).message()
        );

        // XFR-012 : le message dit quoi faire, et ne nomme rien de ce que la
        // destination contient (C-025, CLI-021).
        let message = CliError::Core(Error::DestinationOccupied).message();
        assert!(message.contains("--replace"), "{message}");
        assert!(message.contains("jamais supprimé"), "{message}");
    }

    /// CLI-015 : le message dit quoi faire, et ne dit **pas** combien
    /// d'entrées le dossier contient — ce serait renseigner sur le contenu du
    /// vault dans un message d'erreur (C-025, CLI-021).
    #[test]
    fn le_dossier_peuple_indique_la_solution_sans_dire_le_contenu() {
        let message = CliError::Core(Error::DirectoryNotEmpty).message();
        assert!(message.contains("--recursive"), "{message}");
        assert!(!message.chars().any(|c| c.is_ascii_digit()), "{message}");
        assert_eq!(CliError::Core(Error::DirectoryNotEmpty).code(), 1);
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
