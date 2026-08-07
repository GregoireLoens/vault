//! Invites et confirmations — T044.
//!
//! Ce module porte les mises en garde que la bibliothèque n'affiche
//! délibérément pas : `vault-core` ne parle pas à l'utilisateur, et c'est
//! l'appelant qui doit présenter l'irréversibilité (FR-003) et les limites de
//! l'effacement (FR-020).
//!
//! **CLI-002 est la règle la plus stricte du contrat** : l'avertissement de
//! création exige la saisie littérale de `OUI`, et `--yes` ne le contourne pas.
//! C'est le seul consentement que la ligne de commande refuse d'automatiser,
//! parce que c'est le seul dont la conséquence — la perte définitive des
//! données — est irréversible et non détectable au moment où elle se produit.

use vault_core::{ExposeSecret, MIN_PASSPHRASE_LEN, SecretString};

use crate::console::Console;
use crate::error::{CliError, CliResult};

/// Réponse littérale exigée par l'avertissement d'irréversibilité.
const CONFIRMATION_LITTERALE: &str = "OUI";

/// Texte de l'avertissement d'irréversibilité (FR-003).
const AVERTISSEMENT: &str = "\n  ⚠  Si vous perdez cette passphrase, vos données seront définitivement\n     perdues. Il n'existe aucun moyen de les récupérer : ni question de\n     secours, ni réinitialisation, ni assistance possible.\n";

/// Présente l'avertissement d'irréversibilité et exige `OUI`.
///
/// **`--yes` n'est pas un paramètre de cette fonction, et c'est délibéré**
/// (CLI-002).
///
/// # Errors
///
/// - [`CliError::NotInteractive`] sans terminal ;
/// - [`CliError::Refused`] si la réponse n'est pas exactement `OUI`.
pub fn avertir_irreversibilite(console: &mut dyn Console) -> CliResult<()> {
    console.warn(AVERTISSEMENT);
    let reponse = console.read_line("Tapez OUI pour confirmer que vous avez compris : ")?;
    if reponse.trim() != CONFIRMATION_LITTERALE {
        return Err(CliError::Refused);
    }
    Ok(())
}

/// Demande une passphrase neuve, avec confirmation.
///
/// # Errors
///
/// - [`CliError::NotInteractive`] sans terminal ;
/// - [`CliError::Usage`] si les deux saisies diffèrent ;
/// - [`vault_core::Error::WeakPassphrase`] si elle est trop courte (CLI-003).
pub fn passphrase_neuve(console: &mut dyn Console) -> CliResult<SecretString> {
    let premiere = console.read_passphrase("Passphrase : ")?;
    let seconde = console.read_passphrase("Confirmez la passphrase : ")?;

    if premiere.expose_secret() != seconde.expose_secret() {
        return Err(CliError::Usage(
            "Les deux saisies diffèrent : rien n'a été créé.".to_owned(),
        ));
    }
    if premiere.expose_secret().chars().count() < MIN_PASSPHRASE_LEN {
        return Err(CliError::Core(vault_core::Error::WeakPassphrase {
            minimum: MIN_PASSPHRASE_LEN,
        }));
    }

    // CLI-003 : au-delà du minimum, on apprécie sans rejeter. Refuser une
    // passphrase que l'utilisateur juge suffisante reviendrait à décider à sa
    // place, et pousse en pratique à des passphrases notées puis oubliées.
    console.info(&format!("Robustesse : {}", apprecier(&premiere)));
    Ok(premiere)
}

/// Demande la passphrase d'un vault existant.
///
/// # Errors
///
/// [`CliError::NotInteractive`] sans terminal.
pub fn passphrase_existante(console: &mut dyn Console) -> CliResult<SecretString> {
    console.read_passphrase("Passphrase : ")
}

/// Demande une confirmation ordinaire, que `--yes` peut préaccorder.
///
/// # Errors
///
/// [`CliError::NotInteractive`] sans terminal et sans `--yes` (CLI-022).
pub fn confirmer(console: &mut dyn Console, question: &str, yes: bool) -> CliResult<bool> {
    if yes {
        return Ok(true);
    }
    let reponse = console.read_line(&format!("{question} [o/N] : "))?;
    Ok(matches!(reponse.trim(), "o" | "O" | "oui" | "OUI"))
}

/// Appréciation de la robustesse d'une passphrase.
///
/// Volontairement grossière, et fondée sur la longueur et la variété plutôt que
/// sur un dictionnaire : un dictionnaire embarqué gonflerait le binaire, et une
/// vérification en ligne est exclue par le principe III.
#[must_use]
pub fn apprecier(passphrase: &SecretString) -> &'static str {
    let secret = passphrase.expose_secret();
    let longueur = secret.chars().count();
    let varietes = [
        secret.chars().any(char::is_lowercase),
        secret.chars().any(char::is_uppercase),
        secret.chars().any(|c| c.is_ascii_digit()),
        secret.chars().any(|c| !c.is_alphanumeric()),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();

    match (longueur, varietes) {
        (0..=15, 0..=1) => "faible — quelques mots de plus la rendraient bien plus coûteuse",
        (0..=19, _) | (_, 0..=1) => "correcte",
        (20..=29, _) => "bonne",
        _ => "excellente",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::console::fake::FakeConsole;

    /// CLI-002 : seul `OUI` littéral passe.
    #[test]
    fn l_avertissement_exige_oui_litteral() {
        for accepte in ["OUI", " OUI "] {
            let mut console = FakeConsole::new(&[], &[accepte]);
            assert!(avertir_irreversibilite(&mut console).is_ok());
            assert!(
                console.tout_affiche().contains("définitivement"),
                "l'avertissement doit avoir été présenté"
            );
        }

        let refuses = ["oui", "o", "y", "yes", "", "NON"];
        let verdicts: Vec<bool> = refuses
            .iter()
            .map(|refuse| {
                let mut console = FakeConsole::new(&[], &[refuse]);
                avertir_irreversibilite(&mut console).is_err()
            })
            .collect();
        assert_eq!(verdicts, vec![true; refuses.len()], "{refuses:?}");
    }

    /// CLI-002, CLI-022 : sans terminal, l'avertissement ne peut pas être
    /// donné, donc rien n'est créé.
    #[test]
    fn l_avertissement_echoue_sans_terminal() {
        let mut console = FakeConsole::non_interactive();
        assert!(matches!(
            avertir_irreversibilite(&mut console),
            Err(CliError::NotInteractive)
        ));
    }

    #[test]
    fn la_passphrase_neuve_exige_deux_saisies_concordantes() {
        let bonne = "une passphrase bien assez longue";

        let mut console = FakeConsole::new(&[bonne, bonne], &[]);
        let obtenue = passphrase_neuve(&mut console).expect("acceptée");
        assert_eq!(obtenue.expose_secret(), bonne);
        assert!(console.tout_affiche().contains("Robustesse"));

        let mut console = FakeConsole::new(&[bonne, "autre chose entierement"], &[]);
        assert!(matches!(
            passphrase_neuve(&mut console),
            Err(CliError::Usage(_))
        ));
    }

    /// CLI-003 : en dessous du minimum, refus net.
    #[test]
    fn une_passphrase_trop_courte_est_refusee() {
        let mut console = FakeConsole::new(&["onze carac", "onze carac"], &[]);
        assert!(matches!(
            passphrase_neuve(&mut console),
            Err(CliError::Core(vault_core::Error::WeakPassphrase {
                minimum: 12
            }))
        ));
    }

    #[test]
    fn la_passphrase_existante_est_demandee_une_seule_fois() {
        let mut console = FakeConsole::new(&["secret bien assez long"], &[]);
        assert_eq!(
            passphrase_existante(&mut console)
                .expect("lisible")
                .expose_secret(),
            "secret bien assez long"
        );
        assert_eq!(console.invites.len(), 1);

        let mut muette = FakeConsole::non_interactive();
        assert!(matches!(
            passphrase_existante(&mut muette),
            Err(CliError::NotInteractive)
        ));
    }

    /// CLI-022 : `--yes` préaccorde les confirmations ordinaires, y compris
    /// sans terminal ; sans lui, l'absence de terminal fait échouer.
    #[test]
    fn la_confirmation_ordinaire_suit_yes() {
        let mut muette = FakeConsole::non_interactive();
        assert!(confirmer(&mut muette, "Continuer ?", true).expect("préaccordée"));
        assert!(matches!(
            confirmer(&mut muette, "Continuer ?", false),
            Err(CliError::NotInteractive)
        ));

        for (reponse, attendu) in [
            ("o", true),
            ("O", true),
            ("oui", true),
            ("OUI", true),
            ("n", false),
            ("", false),
        ] {
            let mut console = FakeConsole::new(&[], &[reponse]);
            assert_eq!(
                confirmer(&mut console, "Continuer ?", false).expect("répondue"),
                attendu,
                "réponse {reponse:?}"
            );
        }
    }

    #[test]
    fn l_appreciation_distingue_les_degres() {
        let apprecier_texte = |texte: &str| apprecier(&SecretString::from(texte.to_owned()));

        assert!(apprecier_texte("motdepasse").starts_with("faible"));
        assert_eq!(apprecier_texte("motdepasse Longue!"), "correcte");
        assert_eq!(apprecier_texte("aaaaaaaaaaaaaaaaaaaaaaaaa"), "correcte");
        assert_eq!(apprecier_texte("Mot De Passe Longue 1!"), "bonne");
        assert_eq!(
            apprecier_texte("Une Phrase Secrete Vraiment Longue 42 !"),
            "excellente"
        );
    }
}
