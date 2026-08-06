//! Cryptographie — phase 2, T018 à T021.
//!
//! Aucune primitive n'est écrite ici (principe II) : ce module assemble celles
//! de `RustCrypto` et de `argon2`, et n'en expose au reste du crate que ce qui
//! est nécessaire.

pub(crate) mod aead;
pub(crate) mod kdf;
pub(crate) mod keys;
pub(crate) mod random;
pub(crate) mod stream;
