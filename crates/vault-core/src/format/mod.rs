//! Format sur disque — phase 2, T017, T022 à T025.
//!
//! La disposition décrite ici fait foi pour `docs/format.md`, dont le principe
//! IV exige qu'il permette de déchiffrer un vault sans exécuter vault.

pub(crate) mod blob;
pub(crate) mod header;
pub(crate) mod index;
pub(crate) mod path;
pub(crate) mod version;
