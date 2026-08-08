//! Changement de passphrase — T062.
//!
//! FR-033 à FR-035. L'opération est courte parce que le format a été conçu
//! pour qu'elle le soit.
//!
//! **C-021, D-004 : seule l'enveloppe change.** La clé maîtresse est tirée du
//! CSPRNG à la création et n'est **jamais** dérivée de la passphrase ; celle-ci
//! ne sert qu'à produire la clé qui l'enveloppe. Changer de passphrase revient
//! donc à réenvelopper trente-deux octets, et rien d'autre du vault n'est lu,
//! écrit ni même ouvert. C'est ce qui rend l'opération indépendante de la
//! taille du vault (FR-034) : un vault de quatre cents gigaoctets change de
//! passphrase aussi vite qu'un vault vide.
//!
//! **C-022, FR-035 : le remplacement de l'en-tête est atomique.** Après une
//! interruption, le vault s'ouvre avec l'ancienne **ou** la nouvelle
//! passphrase, jamais avec aucune. Deux choses le garantissent, et il faut les
//! deux :
//!
//! - le nouvel en-tête n'est produit **en entier** qu'avant d'être écrit —
//!   [`crate::format::header::Header::rewrap`] ne remplace l'en-tête en mémoire
//!   qu'une fois le réenveloppement réussi, si bien qu'un échec de dérivation
//!   laisse l'ancien intact ;
//! - l'écriture passe par [`crate::fs::atomic::write`], donc par un temporaire
//!   validé par un `rename`. Le fichier `header` n'est jamais tronqué ni
//!   réécrit sur place : à tout instant, il contient l'ancien en-tête complet
//!   ou le nouveau.
//!
//! **C-019 bis : aucune confirmation, aucune invite.** La passphrase actuelle
//! n'est pas redemandée ici — la session est déjà déverrouillée, donc déjà
//! prouvée. C'est la ligne de commande qui la redemande (CLI-016), parce qu'un
//! terminal laissé sans surveillance n'est pas la même chose qu'une session
//! ouverte.

use secrecy::{ExposeSecret, SecretString};

use crate::MIN_PASSPHRASE_LEN;
use crate::UnlockedVault;
use crate::crypto::kdf::KdfParams;
use crate::error::{Error, Result};
use crate::fs::atomic;
use crate::ops::HEADER_FILE;

impl UnlockedVault {
    /// Remplace la passphrase du vault, et éventuellement ses paramètres de
    /// coût.
    ///
    /// `params` à `None` conserve ceux du vault : changer de passphrase ne doit
    /// pas rabaisser silencieusement un coût que l'utilisateur avait relevé.
    ///
    /// Ne déchiffre ni ne rechiffre le contenu (C-021). Ne demande aucune
    /// confirmation — elle incombe à l'appelant.
    ///
    /// # Errors
    ///
    /// - [`Error::WeakPassphrase`] si la nouvelle fait moins de
    ///   [`MIN_PASSPHRASE_LEN`] caractères, **avant** toute écriture ;
    /// - [`Error::Authentication`] si Argon2id refuse les paramètres ;
    /// - [`Error::Io`] si l'en-tête ne peut pas être remplacé. Dans ce cas
    ///   l'ancienne passphrase ouvre toujours : l'en-tête sur le disque n'a pas
    ///   été touché.
    // La passphrase est prise **par valeur** pour être libérée — donc effacée
    // par `secrecy` — au retour de l'appel, plutôt que de rester vivante chez
    // l'appelant. Voir la note de `Vault::create`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn change_passphrase(
        &mut self,
        new_passphrase: SecretString,
        params: Option<KdfParams>,
    ) -> Result<()> {
        // La longueur se compte en caractères, comme à la création : une règle
        // exprimée en octets serait plus permissive pour les uns que pour les
        // autres.
        if new_passphrase.expose_secret().chars().count() < MIN_PASSPHRASE_LEN {
            return Err(Error::WeakPassphrase {
                minimum: MIN_PASSPHRASE_LEN,
            });
        }

        // Le candidat est construit à part : tant que le réenveloppement n'a
        // pas abouti, l'en-tête de la session reste celui d'avant.
        let mut candidat = self.header.clone();
        candidat.rewrap(
            &self.master_key,
            &new_passphrase,
            params.unwrap_or_else(|| self.header.kdf_params()),
        )?;

        atomic::write(&self.path.join(HEADER_FILE), &candidat.encode()?)?;

        // L'en-tête en mémoire ne suit qu'une fois celui du disque remplacé :
        // un échec d'écriture laisse la session cohérente avec le disque.
        self.header = candidat;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::Vault;

    fn params() -> KdfParams {
        KdfParams::new(64, 1, 1).expect("paramètres valides")
    }

    fn secret(texte: &str) -> SecretString {
        SecretString::from(texte.to_owned())
    }

    const ANCIENNE: &str = "passphrase de test bien assez longue";
    const NOUVELLE: &str = "une toute autre passphrase, tout aussi longue";

    fn coffre_neuf(racine: &Path) -> std::path::PathBuf {
        let coffre = racine.join("coffre");
        Vault::create(&coffre, secret(ANCIENNE), params())
            .expect("créable")
            .lock();
        coffre
    }

    #[test]
    fn la_nouvelle_passphrase_remplace_l_ancienne() {
        let racine = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(racine.path());

        let mut session = Vault::open(&coffre)
            .expect("ouvrable")
            .unlock(secret(ANCIENNE))
            .expect("déverrouillable");
        session
            .change_passphrase(secret(NOUVELLE), None)
            .expect("changeable");
        // La session reste exploitable : elle détient toujours la clé maîtresse.
        assert!(session.list(None).is_empty());
        session.lock();

        assert!(matches!(
            Vault::open(&coffre)
                .expect("ouvrable")
                .unlock(secret(ANCIENNE)),
            Err(Error::Authentication)
        ));
        assert!(
            Vault::open(&coffre)
                .expect("ouvrable")
                .unlock(secret(NOUVELLE))
                .is_ok()
        );
    }

    #[test]
    fn une_passphrase_trop_courte_est_refusee_avant_toute_ecriture() {
        let racine = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(racine.path());
        let avant = std::fs::read(coffre.join(HEADER_FILE)).expect("lisible");

        let mut session = Vault::open(&coffre)
            .expect("ouvrable")
            .unlock(secret(ANCIENNE))
            .expect("déverrouillable");
        assert!(matches!(
            session.change_passphrase(secret("éàèùéàèùéàè"), None),
            Err(Error::WeakPassphrase { minimum: 12 })
        ));

        // Onze caractères accentués : la garde compte bien des caractères.
        assert!(
            session
                .change_passphrase(secret("éàèùéàèùéàèù"), None)
                .is_ok()
        );
        assert_ne!(
            std::fs::read(coffre.join(HEADER_FILE)).expect("lisible"),
            avant
        );
    }

    /// C-023 : les paramètres fournis remplacent ceux du vault ; leur absence
    /// les conserve.
    #[test]
    fn les_parametres_suivent_l_instruction() {
        let racine = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(racine.path());
        let releves = KdfParams::new(128, 2, 1).expect("valides");

        let mut session = Vault::open(&coffre)
            .expect("ouvrable")
            .unlock(secret(ANCIENNE))
            .expect("déverrouillable");

        session
            .change_passphrase(secret(NOUVELLE), Some(releves))
            .expect("changeable");
        assert_eq!(session.kdf_params(), releves);

        session
            .change_passphrase(secret(ANCIENNE), None)
            .expect("changeable");
        assert_eq!(
            session.kdf_params(),
            releves,
            "conservés faute d'instruction"
        );
    }

    /// Des paramètres aberrants font échouer la dérivation, et l'en-tête reste
    /// celui d'avant — sur le disque comme en mémoire.
    #[test]
    fn des_parametres_aberrants_laissent_l_en_tete_intact() {
        let racine = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(racine.path());
        let avant = std::fs::read(coffre.join(HEADER_FILE)).expect("lisible");

        let mut session = Vault::open(&coffre)
            .expect("ouvrable")
            .unlock(secret(ANCIENNE))
            .expect("déverrouillable");
        assert!(matches!(
            session.change_passphrase(secret(NOUVELLE), Some(KdfParams::from_header(0, 0, 0))),
            Err(Error::Authentication)
        ));
        session.lock();

        assert_eq!(
            std::fs::read(coffre.join(HEADER_FILE)).expect("lisible"),
            avant
        );
        assert!(
            Vault::open(&coffre)
                .expect("ouvrable")
                .unlock(secret(ANCIENNE))
                .is_ok()
        );
    }

    /// C-022 : si l'écriture échoue, l'en-tête du disque **et** celui de la
    /// session restent ceux d'avant. Le vault s'ouvre encore avec l'ancienne.
    #[cfg(unix)]
    #[test]
    fn un_echec_d_ecriture_laisse_l_ancienne_passphrase_valide() {
        use std::os::unix::fs::PermissionsExt;

        let racine = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(racine.path());
        let avant = std::fs::read(coffre.join(HEADER_FILE)).expect("lisible");

        let mut session = Vault::open(&coffre)
            .expect("ouvrable")
            .unlock(secret(ANCIENNE))
            .expect("déverrouillable");

        let initiales = std::fs::metadata(&coffre).expect("lisible").permissions();
        let mut verrouillees = initiales.clone();
        verrouillees.set_mode(0o500);
        std::fs::set_permissions(&coffre, verrouillees).expect("modifiable");

        let resultat = session.change_passphrase(secret(NOUVELLE), None);

        std::fs::set_permissions(&coffre, initiales).expect("modifiable");

        assert!(matches!(resultat, Err(Error::Io(_))), "{resultat:?}");
        assert_eq!(
            std::fs::read(coffre.join(HEADER_FILE)).expect("lisible"),
            avant
        );
        session.lock();
        assert!(
            Vault::open(&coffre)
                .expect("ouvrable")
                .unlock(secret(ANCIENNE))
                .is_ok()
        );
    }
}
