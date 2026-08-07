//! Chiffrement authentifié d'un message unique — T019.
//!
//! XChaCha20-Poly1305 (D-002), employé pour deux choses seulement :
//!
//! - **envelopper la clé maîtresse** dans l'en-tête (D-004) ;
//! - **chiffrer l'index**, qui tient en mémoire par construction.
//!
//! Le contenu des fichiers ne passe **pas** par ici : il est traité en flux
//! par [`crate::crypto::stream`], sans quoi SC-010 — un fichier de 4 Go sur
//! une machine de 2 Go — serait hors d'atteinte.
//!
//! Le nonce de 192 bits est ce qui permet de le tirer aléatoirement sans
//! entretenir de compteur persistant : la probabilité de collision reste
//! négligeable bien au-delà du nombre d'écritures qu'un vault connaîtra.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::crypto::random;
use crate::error::{Error, Result};

/// Longueur d'un nonce XChaCha20-Poly1305, en octets.
pub(crate) const NONCE_LEN: usize = 24;

/// Longueur d'un tag Poly1305, en octets.
pub(crate) const TAG_LEN: usize = 16;

/// Longueur d'une clé symétrique, en octets.
pub(crate) const KEY_LEN: usize = 32;

/// Nonce de 192 bits.
pub(crate) type Nonce = [u8; NONCE_LEN];

/// Domaine de séparation de l'enveloppement de la clé maîtresse.
///
/// Employé comme données associées : un `wrapped_master_key` ne peut pas être
/// rejoué là où un autre chiffré est attendu.
const MASTER_KEY_DOMAIN: &[u8] = b"vault master key v1";

/// Assemble les données associées de l'enveloppement de la clé maîtresse.
///
/// Le contexte est la partie publique de l'en-tête. L'y lier fait que **toute
/// altération du sel, des paramètres de dérivation ou des identifiants
/// d'algorithme fait échouer le désenveloppement**, en [`Error::Authentication`]
/// et non en erreur distincte : c'est ce qui donne à C-024 sa portée réelle
/// plutôt qu'une simple discipline d'écriture des messages.
fn master_key_aad(context: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(MASTER_KEY_DOMAIN.len() + context.len());
    aad.extend_from_slice(MASTER_KEY_DOMAIN);
    aad.extend_from_slice(context);
    aad
}

/// Tire un nonce du CSPRNG du système.
pub(crate) fn random_nonce() -> Nonce {
    random::bytes::<NONCE_LEN>()
}

/// Chiffre et authentifie un message.
///
/// # Errors
///
/// [`Error::Corrupted`] si l'AEAD refuse le message — cas qui suppose une
/// taille absurde, hors d'atteinte des tailles manipulées ici.
pub(crate) fn seal(
    key: &[u8; KEY_LEN],
    nonce: &Nonce,
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let payload = Payload {
        msg: plaintext,
        aad: associated_data,
    };
    cipher
        .encrypt(&XNonce::from(*nonce), payload)
        .map_err(|_| Error::Corrupted)
}

/// Déchiffre et vérifie un message.
///
/// # Errors
///
/// [`Error::Authentication`] si le tag ne correspond pas — clé erronée,
/// chiffré altéré ou données associées différentes. Les trois cas sont
/// indiscernables par construction (C-024).
pub(crate) fn open(
    key: &[u8; KEY_LEN],
    nonce: &Nonce,
    associated_data: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let payload = Payload {
        msg: ciphertext,
        aad: associated_data,
    };
    let plaintext = cipher
        .decrypt(&XNonce::from(*nonce), payload)
        .map_err(|_| Error::Authentication)?;
    Ok(Zeroizing::new(plaintext))
}

/// Enveloppe la clé maîtresse avec la clé d'enveloppe dérivée de la
/// passphrase.
///
/// Le résultat est `nonce ‖ chiffré ‖ tag`, tel qu'il est stocké dans
/// `header.wrapped_master_key`.
///
/// # Errors
///
/// Voir [`seal`].
pub(crate) fn wrap_master_key(
    wrapping_key: &[u8; KEY_LEN],
    master_key: &[u8; KEY_LEN],
    context: &[u8],
) -> Result<Vec<u8>> {
    let nonce = random_nonce();
    let sealed = seal(wrapping_key, &nonce, &master_key_aad(context), master_key)?;
    let mut wrapped = Vec::with_capacity(NONCE_LEN + sealed.len());
    wrapped.extend_from_slice(&nonce);
    wrapped.extend_from_slice(&sealed);
    Ok(wrapped)
}

/// Désenveloppe la clé maîtresse.
///
/// VR-P1 : c'est le **seul** moyen de vérifier une passphrase. Aucune
/// empreinte de vérification n'est stockée, qui offrirait une prise à une
/// attaque hors ligne sans rien apporter.
///
/// # Errors
///
/// [`Error::Authentication`], sans distinction, pour une passphrase erronée,
/// un en-tête altéré ou une clé maîtresse corrompue (C-024, VR-P2). La
/// longueur inattendue du champ produit la même erreur : elle signale un
/// en-tête altéré.
pub(crate) fn unwrap_master_key(
    wrapping_key: &[u8; KEY_LEN],
    wrapped: &[u8],
    context: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if wrapped.len() != NONCE_LEN + KEY_LEN + TAG_LEN {
        return Err(Error::Authentication);
    }
    let (nonce, sealed) = wrapped.split_at(NONCE_LEN);
    let nonce: Nonce = nonce.try_into().map_err(|_| Error::Authentication)?;

    let plaintext = open(wrapping_key, &nonce, &master_key_aad(context), sealed)?;
    let key: [u8; KEY_LEN] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| Error::Authentication)?;
    Ok(Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLE: [u8; KEY_LEN] = [3u8; KEY_LEN];

    #[test]
    fn un_message_fait_l_aller_retour() {
        let nonce = random_nonce();
        let sealed = seal(&CLE, &nonce, b"aad", b"message").expect("chiffrable");
        assert_eq!(sealed.len(), b"message".len() + TAG_LEN);
        assert!(!sealed.windows(7).any(|w| w == b"message"));

        let opened = open(&CLE, &nonce, b"aad", &sealed).expect("déchiffrable");
        assert_eq!(opened.as_slice(), b"message");
    }

    #[test]
    fn un_message_vide_fait_l_aller_retour() {
        let nonce = random_nonce();
        let sealed = seal(&CLE, &nonce, b"", b"").expect("chiffrable");
        assert_eq!(sealed.len(), TAG_LEN);
        assert!(
            open(&CLE, &nonce, b"", &sealed)
                .expect("déchiffrable")
                .is_empty()
        );
    }

    /// Le principe VI exige que toute altération soit détectée, jamais
    /// silencieusement absorbée.
    #[test]
    fn toute_alteration_est_detectee() {
        let nonce = random_nonce();
        let sealed = seal(&CLE, &nonce, b"aad", b"message").expect("chiffrable");

        // Le balayage vérifie qu'aucune altération ne passe ; le variant exact
        // est vérifié par les assertions ponctuelles ci-dessous. Les résultats
        // sont collectés puis comparés d'un bloc plutôt qu'assertés un par un :
        // un bras de diagnostic par itération ne serait jamais pris, donc
        // jamais couvert (principe VIII).
        let detectees: Vec<bool> = (0..sealed.len())
            .map(|position| {
                let mut altere = sealed.clone();
                altere[position] ^= 0x01;
                open(&CLE, &nonce, b"aad", &altere).is_err()
            })
            .collect();
        assert_eq!(detectees, vec![true; sealed.len()], "octets non détectés");

        let mut autre_nonce = nonce;
        autre_nonce[0] ^= 0x01;
        assert!(matches!(
            open(&CLE, &autre_nonce, b"aad", &sealed),
            Err(Error::Authentication)
        ));
        assert!(matches!(
            open(&CLE, &nonce, b"autre", &sealed),
            Err(Error::Authentication)
        ));
        assert!(matches!(
            open(&[4u8; KEY_LEN], &nonce, b"aad", &sealed),
            Err(Error::Authentication)
        ));
        assert!(matches!(
            open(&CLE, &nonce, b"aad", b"tronque"),
            Err(Error::Authentication)
        ));
    }

    #[test]
    fn deux_nonces_tires_different() {
        assert_ne!(random_nonce(), random_nonce());
    }

    #[test]
    fn la_cle_maitresse_fait_l_aller_retour() {
        let maitresse = [9u8; KEY_LEN];
        let wrapped = wrap_master_key(&CLE, &maitresse, b"contexte").expect("enveloppable");
        assert_eq!(wrapped.len(), NONCE_LEN + KEY_LEN + TAG_LEN);
        // La clé maîtresse ne doit apparaître nulle part en clair.
        assert!(!wrapped.windows(KEY_LEN).any(|w| w == maitresse));

        let recuperee = unwrap_master_key(&CLE, &wrapped, b"contexte").expect("désenveloppable");
        assert_eq!(recuperee.as_ref(), &maitresse);
    }

    #[test]
    fn deux_enveloppements_de_la_meme_cle_different() {
        let maitresse = [9u8; KEY_LEN];
        let a = wrap_master_key(&CLE, &maitresse, b"contexte").expect("enveloppable");
        let b = wrap_master_key(&CLE, &maitresse, b"contexte").expect("enveloppable");
        assert_ne!(a, b, "chaque enveloppement doit tirer un nonce neuf");
    }

    /// C-024, VR-P2 : passphrase erronée, en-tête altéré et champ tronqué
    /// donnent tous la même erreur.
    #[test]
    fn un_desenveloppement_impossible_donne_toujours_authentication() {
        let wrapped = wrap_master_key(&CLE, &[9u8; KEY_LEN], b"contexte").expect("enveloppable");

        assert!(matches!(
            unwrap_master_key(&[4u8; KEY_LEN], &wrapped, b"contexte"),
            Err(Error::Authentication)
        ));
        assert!(matches!(
            unwrap_master_key(&CLE, &wrapped, b"contexte altere"),
            Err(Error::Authentication)
        ));
        assert!(matches!(
            unwrap_master_key(&CLE, &wrapped[..wrapped.len() - 1], b"contexte"),
            Err(Error::Authentication)
        ));
        assert!(matches!(
            unwrap_master_key(&CLE, b"", b"contexte"),
            Err(Error::Authentication)
        ));
    }

    /// Les données associées cantonnent chaque chiffré à son rôle : un
    /// `wrapped_master_key` rejoué à la place de l'index ne s'ouvre pas.
    #[test]
    fn le_domaine_de_separation_est_effectif() {
        let nonce = random_nonce();
        let sealed = seal(&CLE, &nonce, MASTER_KEY_DOMAIN, b"secret").expect("chiffrable");
        assert!(matches!(
            open(&CLE, &nonce, b"vault index v1", &sealed),
            Err(Error::Authentication)
        ));
    }
}
