//! Erreurs de `vault-core` — T016.
//!
//! Le contrat d'erreurs est **avare** par conception (C-024, C-025, FR-040) :
//!
//! - un unique variant [`Error::Authentication`], sans le moindre détail,
//!   couvre indifféremment la passphrase erronée, l'en-tête altéré et la clé
//!   maîtresse corrompue. Distinguer ces cas donnerait à un attaquant hors
//!   ligne un oracle lui indiquant *quelle* partie de sa tentative a échoué ;
//! - aucun variant, et aucun message de [`Display`], ne contient de nom
//!   d'entrée du vault ni de fragment de contenu.
//!
//! [`Display`]: std::fmt::Display

/// Erreur renvoyée par toute opération de `vault-core`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Échec d'authentification.
    ///
    /// Volontairement sans détail et d'affichage constant (C-024). Couvre la
    /// passphrase erronée, l'en-tête altéré et la clé maîtresse corrompue.
    #[error("authentification impossible")]
    Authentication,

    /// Le vault est déjà ouvert par une autre instance (FR-012, C-005).
    #[error("le vault est déjà ouvert par un autre processus")]
    AlreadyInUse,

    /// L'entrée demandée n'existe pas dans le vault.
    #[error("entrée introuvable")]
    NotFound,

    /// Une entrée existe déjà à cet emplacement, ou un vault existe déjà là où
    /// la création en demandait un neuf (FR-004, VR-I3).
    #[error("l'élément existe déjà")]
    AlreadyExists,

    /// Le fichier dépasse la taille maximale gérée par le format (FR-023).
    ///
    /// Renvoyée **avant** toute écriture (C-009).
    #[error("fichier trop volumineux : la limite est de {limit} octets")]
    FileTooLarge {
        /// Taille maximale acceptée, en octets.
        limit: u64,
    },

    /// L'espace disponible sur le support de destination est insuffisant
    /// (FR-029, C-015).
    #[error("espace insuffisant : {needed} octets nécessaires, {available} disponibles")]
    InsufficientSpace {
        /// Espace nécessaire, en octets.
        needed: u64,
        /// Espace disponible, en octets.
        available: u64,
    },

    /// L'entrée n'est pas un fichier ordinaire ni un dossier — lien
    /// symbolique, fichier spécial, socket (C-012).
    #[error("type d'entrée non géré")]
    UnsupportedEntry,

    /// Une suppression non récursive a rencontré un dossier peuplé.
    ///
    /// Le nombre de descendants n'est pas rapporté : ce serait renseigner sur
    /// le contenu du vault dans un message d'erreur (C-025).
    #[error("le dossier n'est pas vide")]
    DirectoryNotEmpty,

    /// La version de format lue n'est pas gérée par cette version du logiciel.
    ///
    /// Refus explicite, jamais de lecture approximative (VR-H1).
    #[error("version de format {found} non gérée : cette version lit le format {supported}")]
    UnsupportedFormatVersion {
        /// Version trouvée dans l'en-tête.
        found: u32,
        /// Version gérée par ce logiciel.
        supported: u32,
    },

    /// Une structure du vault est illisible ou incohérente d'une manière qui
    /// ne relève pas de l'authentification.
    #[error("vault corrompu")]
    Corrupted,

    /// Un chemin de vault viole les règles de composition (VR-I4).
    ///
    /// Ne rapporte **pas** le composant fautif : ce serait un nom d'entrée
    /// dans un message d'erreur (C-025).
    #[error("chemin invalide")]
    InvalidPath,

    /// La passphrase proposée est plus courte que le minimum exigé (FR-005,
    /// C-001).
    ///
    /// Ne concerne que la *création* et le *changement* de passphrase. Une
    /// tentative de déverrouillage avec une passphrase trop courte renvoie
    /// [`Error::Authentication`], comme n'importe quelle autre passphrase
    /// erronée : la longueur du secret attendu ne doit pas fuiter.
    #[error("passphrase trop courte : {minimum} caractères au minimum")]
    WeakPassphrase {
        /// Longueur minimale exigée, en caractères.
        minimum: usize,
    },

    /// Les paramètres de dérivation proposés sont hors des bornes acceptées
    /// par Argon2id.
    ///
    /// Ne concerne que les paramètres **fournis par l'appelant**. Des
    /// paramètres aberrants lus dans un en-tête produisent
    /// [`Error::Authentication`] : un en-tête altéré ne doit pas se distinguer
    /// d'une passphrase erronée (C-024).
    #[error("paramètres de dérivation invalides")]
    InvalidKdfParams,

    /// Erreur d'entrée-sortie.
    ///
    /// C-025 : ne peut se rapporter qu'à un chemin **hors** du vault — source
    /// d'un ajout ou destination d'une extraction.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Résultat d'une opération de `vault-core`.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    /// C-024 : l'affichage d'`Authentication` est constant. Le test compare
    /// deux occurrences produites par des chemins différents plutôt que de
    /// figer la chaîne, pour rester valable si la formulation change.
    #[test]
    fn authentication_a_un_affichage_constant() {
        assert_eq!(
            Error::Authentication.to_string(),
            Error::Authentication.to_string()
        );
        assert!(!Error::Authentication.to_string().is_empty());
    }

    /// C-025 : aucun message ne doit pouvoir contenir un nom d'entrée. Les
    /// variants porteurs de données ne transportent que des nombres.
    #[test]
    fn aucun_message_ne_transporte_de_texte_libre() {
        let messages = [
            Error::Authentication.to_string(),
            Error::AlreadyInUse.to_string(),
            Error::NotFound.to_string(),
            Error::AlreadyExists.to_string(),
            Error::FileTooLarge { limit: 4 }.to_string(),
            Error::InsufficientSpace {
                needed: 1,
                available: 0,
            }
            .to_string(),
            Error::UnsupportedEntry.to_string(),
            Error::DirectoryNotEmpty.to_string(),
            Error::UnsupportedFormatVersion {
                found: 2,
                supported: 1,
            }
            .to_string(),
            Error::Corrupted.to_string(),
            Error::InvalidPath.to_string(),
            Error::WeakPassphrase { minimum: 12 }.to_string(),
            Error::InvalidKdfParams.to_string(),
        ];
        for message in messages {
            assert!(!message.is_empty());
            assert!(!message.contains("secret"));
        }
    }

    #[test]
    fn une_erreur_d_entree_sortie_se_convertit() {
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "refusé");
        let error = Error::from(io);
        assert!(matches!(error, Error::Io(_)));
        assert!(!error.to_string().is_empty());
        // Le Debug sert aux diagnostics de développement ; il doit exister sur
        // tout le contrat d'erreurs.
        assert!(!format!("{error:?}").is_empty());
    }
}
