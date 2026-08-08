//! Surfaces de décodage exposées pour l'exploration guidée — 002, T023.
//!
//! **Ce module n'existe que si la fonctionnalité `fuzzing` est demandée**, et
//! elle ne l'est que par le crate `fuzz/`. Une compilation ordinaire — celle du
//! binaire livré, celle de la suite de tests, celle de l'intégration continue —
//! ne le contient pas. Le contrat public de `vault-core` est donc inchangé.
//!
//! # Pourquoi une porte dérobée, fût-elle fermée à clé
//!
//! Les décodeurs du format ne sont pas publics, et c'est délibéré : rien de ce
//! qui lit des octets bruts n'a de raison d'être appelé depuis l'extérieur.
//! Mais une exploration guidée par la couverture a besoin d'entrer **au plus
//! près de la surface**, sans passer par un fichier ni par une dérivation
//! Argon2 : à quelques milliers d'exécutions par seconde près, c'est ce qui
//! sépare une campagne utile d'une campagne décorative.
//!
//! Deux garde-fous rendent la chose acceptable :
//!
//! - la fonctionnalité n'est **jamais activée** dans ce qui est livré ni dans
//!   ce qui est mesuré ; `cargo deny`, la couverture et les portes voient
//!   exactement le même crate qu'avant ;
//! - aucune de ces fonctions n'expose de secret, ne chiffre, ni n'écrit. Elles
//!   ne font que **refuser** — ce qui est précisément ce qu'on veut éprouver.
//!
//! # Ce que chaque surface représente
//!
//! `index_depuis_le_clair` mérite un mot : elle reçoit un index **déjà
//! authentifié**. Ce n'est pas une facilité de test, c'est un scénario réel —
//! celui du vault forgé par un tiers puis remis à sa victime. Le forgeur
//! choisit sa passphrase, produit donc un tag valide, et seul le décodeur peut
//! encore l'arrêter.

use crate::error::Result;
use crate::format::header::Header;
use crate::format::index::Index;
use crate::format::path::VaultPath;

/// Décode un en-tête depuis des octets arbitraires (§3 de `docs/format.md`).
///
/// # Errors
///
/// Celles de la lecture d'en-tête. **Aucune entrée ne doit faire paniquer.**
pub fn en_tete_depuis_octets(octets: &[u8]) -> Result<()> {
    Header::decode(octets).map(drop)
}

/// Décode un index déjà authentifié, invariants compris (§5).
///
/// # Errors
///
/// [`crate::Error::Corrupted`] si le CBOR est illisible ou si les invariants
/// sont violés. **Aucune entrée ne doit faire paniquer.**
pub fn index_depuis_le_clair(octets: &[u8]) -> Result<()> {
    Index::decode_plain(octets).map(drop)
}

/// Construit un chemin de vault depuis des composants arbitraires (§5).
///
/// # Errors
///
/// [`crate::Error::InvalidPath`] si un composant viole les règles de
/// composition. **Aucune entrée ne doit faire paniquer.**
pub fn chemin_depuis_composants(composants: Vec<Vec<u8>>) -> Result<()> {
    VaultPath::from_components(composants).map(drop)
}
