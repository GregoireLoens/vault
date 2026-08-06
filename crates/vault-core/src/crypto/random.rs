//! Source d'aléa — principe II.
//!
//! Tout l'aléa du vault sort d'ici, et il vient du **CSPRNG du système
//! d'exploitation** : la constitution interdit tout générateur applicatif,
//! fût-il cryptographiquement solide. `SysRng` est la façade de `getrandom`
//! sur `getrandom(2)`, `arc4random_buf` ou `BCryptGenRandom` selon la
//! plateforme ; aucun état n'est conservé en espace utilisateur.
//!
//! Une panne du CSPRNG système **interrompt le processus**. C'est délibéré :
//! poursuivre reviendrait à écrire un nonce, un sel ou une clé maîtresse
//! prévisibles, c'est-à-dire à produire des données qui *semblent* chiffrées.
//! Sur les systèmes visés, cet échec n'est pas un cas de fonctionnement
//! dégradé mais une défaillance du noyau.

use rand::TryRng;
use rand::rngs::SysRng;

/// Remplit le tampon d'octets aléatoires issus du CSPRNG du système.
///
/// # Panics
///
/// Si le CSPRNG du système est indisponible — voir la note de module.
pub(crate) fn fill(buffer: &mut [u8]) {
    SysRng
        .try_fill_bytes(buffer)
        .expect("le CSPRNG du système doit être disponible");
}

/// Renvoie un tableau d'octets aléatoires.
pub(crate) fn bytes<const N: usize>() -> [u8; N] {
    let mut buffer = [0u8; N];
    fill(&mut buffer);
    buffer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_tampon_est_rempli() {
        // Un tampon de 64 octets nul après remplissage a une probabilité de
        // 2^-512 : l'assertion est sûre, et elle détecte le cas réel qu'on
        // cherche à exclure, celui d'une fonction qui ne remplirait rien.
        let mut buffer = [0u8; 64];
        fill(&mut buffer);
        assert_ne!(buffer, [0u8; 64]);
    }

    #[test]
    fn deux_tirages_different() {
        assert_ne!(bytes::<32>(), bytes::<32>());
    }

    #[test]
    fn un_tampon_vide_est_accepte() {
        let mut vide: [u8; 0] = [];
        fill(&mut vide);
        assert_eq!(bytes::<0>(), [0u8; 0]);
    }
}
