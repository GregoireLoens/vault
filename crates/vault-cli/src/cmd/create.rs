//! `vault create` — T045.
//!
//! FR-001 à FR-006, CLI-002 à CLI-004.
//!
//! L'ordre des étapes est celui du contrat, et il n'est pas indifférent :
//! l'avertissement d'irréversibilité vient **avant** la création, pas après.
//! Un utilisateur qui découvrirait la conséquence une fois le vault créé aurait
//! déjà pris le risque.

use std::path::Path;

use vault_core::{KdfParams, Vault};

use crate::cmd::Contexte;
use crate::error::CliResult;
use crate::prompt;

/// Paramètres de coût passés en ligne de commande (CLI-004).
#[derive(Clone, Copy, Debug, Default)]
pub struct OptionsKdf {
    /// `--kdf-memory`, en kibioctets.
    pub memory_kib: Option<u32>,
    /// `--kdf-iterations`.
    pub iterations: Option<u32>,
    /// `--kdf-parallelism`.
    pub parallelism: Option<u32>,
}

impl OptionsKdf {
    /// Combine ces options avec les valeurs par défaut du format.
    ///
    /// # Errors
    ///
    /// [`vault_core::Error::InvalidKdfParams`] si la combinaison est hors des
    /// bornes admises par Argon2id.
    pub fn resoudre(self) -> CliResult<KdfParams> {
        let defaut = KdfParams::default();
        Ok(KdfParams::new(
            self.memory_kib.unwrap_or_else(|| defaut.memory_kib()),
            self.iterations.unwrap_or_else(|| defaut.iterations()),
            self.parallelism.unwrap_or_else(|| defaut.parallelism()),
        )?)
    }
}

/// Crée un vault à l'emplacement demandé.
///
/// # Errors
///
/// - [`crate::error::CliError::Refused`] si l'avertissement n'est pas accepté ;
/// - [`crate::error::CliError::NotInteractive`] sans terminal (CLI-022) ;
/// - celles de [`Vault::create`].
pub fn executer(contexte: &mut Contexte, emplacement: &Path, kdf: OptionsKdf) -> CliResult<()> {
    let params = kdf.resoudre()?;

    let passphrase = prompt::passphrase_neuve(contexte.console)?;
    // CLI-002 : `--yes` n'est pas consulté ici, et ne doit jamais l'être.
    prompt::avertir_irreversibilite(contexte.console)?;

    let session = Vault::create(emplacement, passphrase, params)?;
    let emplacement = session.path().display().to_string();
    session.lock();

    if contexte.json {
        contexte.console.output(&format!(
            "{{\"created\":\"{}\"}}",
            crate::cmd::json_echappe(&emplacement)
        ));
    } else {
        contexte
            .console
            .info(&format!("Vault créé : {emplacement}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::console::fake::FakeConsole;
    use crate::error::CliError;

    const PASSPHRASE: &str = "une passphrase bien assez longue";

    /// Paramètres minuscules : ces tests vérifient l'enchaînement des invites,
    /// pas le coût de la dérivation.
    fn kdf_rapide() -> OptionsKdf {
        OptionsKdf {
            memory_kib: Some(64),
            iterations: Some(1),
            parallelism: Some(1),
        }
    }

    fn contexte<'a>(console: &'a mut FakeConsole, racine: &Path) -> Contexte<'a> {
        Contexte {
            console,
            vault_dir: racine.to_path_buf(),
            yes: false,
            json: false,
            idle_timeout: None,
        }
    }

    #[test]
    fn un_vault_se_cree_apres_confirmation() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        let mut console = FakeConsole::new(&[PASSPHRASE, PASSPHRASE], &["OUI"]);

        executer(
            &mut contexte(&mut console, atelier.path()),
            &coffre,
            kdf_rapide(),
        )
        .expect("créable");

        assert!(coffre.join("header").is_file());
        assert!(console.tout_affiche().contains("Vault créé"));
        assert!(console.tout_affiche().contains("définitivement"));
    }

    /// CLI-002 : un refus laisse le disque intact.
    #[test]
    fn un_refus_ne_cree_rien() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        let mut console = FakeConsole::new(&[PASSPHRASE, PASSPHRASE], &["non"]);

        assert!(matches!(
            executer(
                &mut contexte(&mut console, atelier.path()),
                &coffre,
                kdf_rapide()
            ),
            Err(CliError::Refused)
        ));
        assert!(!coffre.exists());
    }

    /// CLI-003 : une passphrase trop courte est refusée avant l'avertissement,
    /// donc avant toute écriture.
    #[test]
    fn une_passphrase_trop_courte_arrete_tout() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        let mut console = FakeConsole::new(&["court", "court"], &["OUI"]);

        assert!(matches!(
            executer(
                &mut contexte(&mut console, atelier.path()),
                &coffre,
                kdf_rapide()
            ),
            Err(CliError::Core(vault_core::Error::WeakPassphrase { .. }))
        ));
        assert!(!coffre.exists());
        assert!(
            !console.tout_affiche().contains("définitivement"),
            "l'avertissement n'a pas lieu d'être si la passphrase est déjà refusée"
        );
    }

    #[test]
    fn la_sortie_json_annonce_l_emplacement() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        let mut console = FakeConsole::new(&[PASSPHRASE, PASSPHRASE], &["OUI"]);
        let mut ctx = contexte(&mut console, atelier.path());
        ctx.json = true;

        executer(&mut ctx, &coffre, kdf_rapide()).expect("créable");
        assert!(console.tout_affiche().contains("\"created\""));
    }

    /// CLI-004 : les paramètres se relèvent, et une combinaison impossible est
    /// refusée avant qu'on demande quoi que ce soit à l'utilisateur.
    #[test]
    fn les_parametres_de_cout_sont_repris_ou_refuses() {
        let defaut = OptionsKdf::default().resoudre().expect("valides");
        assert_eq!(defaut, KdfParams::default());

        let releves = OptionsKdf {
            memory_kib: Some(262_144),
            iterations: Some(4),
            parallelism: None,
        }
        .resoudre()
        .expect("valides");
        assert_eq!(releves.memory_kib(), 262_144);
        assert_eq!(releves.iterations(), 4);
        assert_eq!(releves.parallelism(), KdfParams::default().parallelism());

        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let mut console = FakeConsole::new(&[], &[]);
        let aberrants = OptionsKdf {
            memory_kib: Some(0),
            iterations: Some(0),
            parallelism: Some(0),
        };
        assert!(matches!(
            executer(
                &mut contexte(&mut console, atelier.path()),
                &atelier.path().join("coffre"),
                aberrants
            ),
            Err(CliError::Core(vault_core::Error::InvalidKdfParams))
        ));
        assert!(console.invites.is_empty(), "rien n'a été demandé");
    }

    #[test]
    fn un_emplacement_occupe_est_signale() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        std::fs::create_dir(&coffre).expect("créable");
        let mut console = FakeConsole::new(&[PASSPHRASE, PASSPHRASE], &["OUI"]);

        assert!(matches!(
            executer(
                &mut contexte(&mut console, atelier.path()),
                &coffre,
                kdf_rapide()
            ),
            Err(CliError::Core(vault_core::Error::AlreadyExists))
        ));
    }

    #[test]
    fn les_options_de_cout_ont_un_debug() {
        assert!(format!("{:?}", kdf_rapide()).contains("OptionsKdf"));
    }
}
