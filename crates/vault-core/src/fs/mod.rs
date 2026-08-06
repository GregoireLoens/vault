//! Accès au système de fichiers — phase 2, T026 à T028.
//!
//! Tout ce qui touche au disque passe par ici : écritures atomiques (D-008),
//! verrou d'exclusion mutuelle (D-009) et vérification d'espace (FR-029). Les
//! différences de sémantique entre plateformes y sont cantonnées.

pub(crate) mod atomic;
pub(crate) mod lock;
pub(crate) mod space;
