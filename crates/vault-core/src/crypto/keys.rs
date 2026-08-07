//! Gestion des clés — T020.
//!
//! La clé maîtresse est tirée du CSPRNG du système à la création du vault et
//! n'est **jamais** dérivée de la passphrase (D-004). Elle n'existe sur disque
//! que sous forme enveloppée, et en mémoire que le temps d'une session
//! déverrouillée.
//!
//! Chaque blob possède sa propre clé, dérivée de la clé maîtresse et de
//! l'identifiant du blob (D-005). Deux conséquences :
//!
//! - une réutilisation accidentelle de nonce reste cantonnée à un seul blob ;
//! - un transfert sélectif pourra un jour livrer la clé d'un blob sans livrer
//!   la clé maîtresse.
//!
//! FR-041 : tous les secrets de ce module sont enveloppés dans [`Zeroizing`],
//! donc effacés à la libération — **y compris lorsqu'elle résulte d'une
//! erreur ou d'une panique**, puisque c'est le déroulement de pile qui
//! déclenche l'effacement, et non un chemin de code nominal.

use zeroize::Zeroizing;

use crate::crypto::aead::{self, KEY_LEN};
use crate::crypto::random;
use crate::error::Result;

/// Contexte de dérivation des clés par blob.
///
/// BLAKE3 exige une chaîne constante, unique à l'application et au rôle. Elle
/// est figée ici : la modifier rendrait illisibles tous les vaults existants.
const BLOB_KEY_CONTEXT: &str = "vault 2026 blob key v1";

/// Domaine de séparation du chiffrement de l'index.
pub(crate) const INDEX_DOMAIN: &[u8] = b"vault index v1";

/// Clé symétrique de 256 bits, effacée à sa libération.
pub(crate) type SecretKey = Zeroizing<[u8; KEY_LEN]>;

/// Clé maîtresse d'un vault.
///
/// Ne dérive volontairement ni `Clone` ni `Copy` : chaque copie serait un
/// exemplaire de plus à effacer, et un oubli possible.
pub(crate) struct MasterKey(SecretKey);

impl MasterKey {
    /// Tire une clé maîtresse neuve du CSPRNG du système.
    pub(crate) fn generate() -> Self {
        Self(Zeroizing::new(random::bytes::<KEY_LEN>()))
    }

    /// Reconstruit la clé maîtresse depuis son désenveloppement.
    pub(crate) fn from_secret(bytes: SecretKey) -> Self {
        Self(bytes)
    }

    /// Les octets de la clé, pour les primitives qui les exigent.
    pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Enveloppe la clé maîtresse avec une clé d'enveloppe.
    ///
    /// # Errors
    ///
    /// Voir [`aead::wrap_master_key`].
    pub(crate) fn wrap(&self, wrapping_key: &[u8; KEY_LEN], context: &[u8]) -> Result<Vec<u8>> {
        aead::wrap_master_key(wrapping_key, self.expose(), context)
    }

    /// Dérive la clé d'un blob depuis son identifiant.
    ///
    /// La dérivation prend la clé maîtresse **et** l'identifiant : le contexte
    /// BLAKE3 sépare l'usage, la clé maîtresse fournit le secret, et
    /// l'identifiant sépare les blobs entre eux.
    pub(crate) fn blob_key(&self, blob_id: &[u8]) -> SecretKey {
        let mut hasher = blake3::Hasher::new_derive_key(BLOB_KEY_CONTEXT);
        hasher.update(self.expose());
        hasher.update(blob_id);
        Zeroizing::new(*hasher.finalize().as_bytes())
    }
}

/// C-026 : aucun secret ne s'affiche. `MasterKey` implémente `Debug` pour
/// pouvoir figurer dans une structure qui le dérive, sans jamais en révéler le
/// contenu.
impl std::fmt::Debug for MasterKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MasterKey(<effacée de l'affichage>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deux_cles_maitresses_different() {
        let a = MasterKey::generate();
        let b = MasterKey::generate();
        assert_ne!(a.expose(), b.expose());
        assert_ne!(a.expose(), &[0u8; KEY_LEN]);
    }

    #[test]
    fn la_cle_maitresse_survit_a_l_enveloppement() {
        let wrapping = [5u8; KEY_LEN];
        let master = MasterKey::generate();
        let wrapped = master.wrap(&wrapping, b"en-tete").expect("enveloppable");

        let recuperee =
            aead::unwrap_master_key(&wrapping, &wrapped, b"en-tete").expect("désenveloppable");
        let reconstruite = MasterKey::from_secret(recuperee);
        assert_eq!(reconstruite.expose(), master.expose());
    }

    /// D-005 : la clé d'un blob dépend de la clé maîtresse *et* de
    /// l'identifiant du blob. Changer l'un ou l'autre change la clé.
    #[test]
    fn chaque_blob_a_sa_propre_cle() {
        let master = MasterKey::generate();
        let autre = MasterKey::generate();

        let cle = master.blob_key(b"identifiant-a");
        assert_eq!(cle.as_ref(), master.blob_key(b"identifiant-a").as_ref());
        assert_ne!(cle.as_ref(), master.blob_key(b"identifiant-b").as_ref());
        assert_ne!(cle.as_ref(), autre.blob_key(b"identifiant-a").as_ref());
        assert_ne!(cle.as_ref(), master.expose());
    }

    /// C-026 : le `Debug` d'une clé maîtresse ne laisse rien filtrer. Il est
    /// constant, donc indépendant du secret — la propriété la plus forte
    /// qu'on puisse tester ici.
    #[test]
    fn le_debug_ne_revele_rien() {
        let affichage = format!("{:?}", MasterKey::generate());
        assert_eq!(affichage, format!("{:?}", MasterKey::generate()));
        assert!(affichage.contains("MasterKey"));
    }

    #[test]
    fn le_domaine_de_l_index_est_distinct_de_celui_des_blobs() {
        assert_ne!(INDEX_DOMAIN, BLOB_KEY_CONTEXT.as_bytes());
    }
}
