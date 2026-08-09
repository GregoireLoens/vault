//! Exploration de l'index déjà authentifié — 002, T024.
//!
//! §5 du format. Cette surface est celle du **vault forgé** : quelqu'un qui
//! choisit sa propre passphrase produit un index parfaitement authentifié, et
//! seul le décodeur peut encore l'arrêter. C'est pourquoi le clair est soumis
//! directement, sans passer par un tag qu'une exploration ne saurait forger.

fn main() {
    afl::fuzz!(|donnees: &[u8]| {
        let _ = vault_core::fuzzing::index_depuis_le_clair(donnees);
    });
}
