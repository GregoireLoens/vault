//! `vault export` — T034 à T036, T038, T039.
//!
//! XFR-001 à XFR-008. Deux règles gouvernent cette commande, et elles ne se
//! négocient pas :
//!
//! **XFR-002 : l'avertissement est présenté à chaque export.** Avec ou sans
//! `--new-passphrase`, et `--quiet` ne le supprime pas — il passe par
//! [`Console::warn`], que le mode silencieux laisse passer. Choisir une
//! passphrase distincte pour le conteneur n'y change rien : la clé maîtresse
//! transportée est la même dans les deux cas, et une passphrase distincte ne
//! rend donc pas le conteneur partageable (FR-006a). Il est affiché **avant**
//! le travail, pour être vu même d'un export qui échoue ensuite.
//!
//! **XFR-006 : le conteneur sort seul sur la sortie standard.** Progression,
//! avertissements et erreurs passent par l'erreur standard. Sans cette
//! séparation, un tube produirait un conteneur corrompu par la première ligne
//! de progression. C'est [`crate::console::Terminal`] qui l'applique ; cette
//! commande écrit ses octets sur la sortie standard et n'y écrit rien d'autre.
//!
//! [`Console::warn`]: crate::console::Console::warn

use std::io::Write;
use std::path::{Path, PathBuf};

use vault_core::{ExportEnvelope, Vault};

use crate::cmd::{Contexte, taille_lisible};
use crate::error::{CliError, CliResult};
use crate::prompt;

/// FR-006, XFR-002 : ce que l'utilisateur doit savoir de tout conteneur.
const AVERTISSEMENT: &str = "\n  ⚠  Ce conteneur porte la clé maîtresse de votre vault : qui l'ouvre peut\n     aussi ouvrir le vault d'origine. C'est une sauvegarde ou un déplacement,\n     pas un moyen de partager avec quelqu'un.\n";

/// Désigne la sortie standard plutôt qu'un fichier.
const SORTIE_STANDARD: &str = "-";

/// Options de `vault export`.
pub struct Options {
    /// `--to` : fichier de sortie, ou `-` pour la sortie standard.
    pub destination: PathBuf,
    /// `--new-passphrase` : protéger le conteneur par une passphrase distincte.
    pub new_passphrase: bool,
}

/// Produit un conteneur depuis le vault désigné par `--vault`.
///
/// `standard` est la sortie standard du processus, et `standard_est_terminal`
/// dit si elle en est un. Les deux sont passés plutôt que lus ici : c'est ce
/// qui rend le refus de XFR-005 vérifiable sans terminal.
///
/// # Errors
///
/// - [`CliError::Usage`] si `--to -` viserait un terminal (XFR-005), ou si
///   `--json` est demandé avec `--to -` — le rendu machine corromprait le
///   conteneur ;
/// - [`CliError::NotInteractive`] si une passphrase doit être saisie et que
///   l'entrée standard n'est pas un terminal (XFR-018) ;
/// - celles de [`Vault::export`] : [`vault_core::Error::AlreadyInUse`] si le
///   vault est déjà ouvert, [`vault_core::Error::NotFound`] s'il n'y a pas de
///   vault, [`vault_core::Error::Authentication`] si la passphrase source est
///   erronée.
pub fn executer(
    contexte: &mut Contexte,
    options: &Options,
    standard: &mut dyn Write,
    standard_est_terminal: bool,
) -> CliResult<()> {
    // XFR-002 : à chaque export, sans que l'utilisateur ait à le demander, et
    // avant tout le reste.
    contexte.console.warn(AVERTISSEMENT);

    let vers_la_sortie_standard = options.destination == Path::new(SORTIE_STANDARD);
    if vers_la_sortie_standard {
        // XFR-005 : presque toujours une erreur de commande, et jamais ce que
        // l'utilisateur voulait.
        if standard_est_terminal {
            return Err(CliError::Usage(
                "Un conteneur ne s'écrit pas sur un terminal. Redirigez la sortie vers un \
fichier, ou donnez un chemin à --to."
                    .to_owned(),
            ));
        }
        if contexte.json {
            return Err(CliError::Usage(
                "--json et --to - sont incompatibles : le rendu machine sortirait au milieu du \
conteneur."
                    .to_owned(),
            ));
        }
    }

    let envelope = if options.new_passphrase {
        // XFR-003 : la passphrase du vault source d'abord — la variante exige
        // d'ouvrir le vault —, la nouvelle ensuite, saisie et confirmée, sa
        // robustesse appréciée comme à `create`.
        let current = prompt::passphrase_existante(contexte.console)?;
        let new = prompt::passphrase_neuve(contexte.console)?;
        ExportEnvelope::NewPassphrase { current, new }
    } else {
        ExportEnvelope::Source
    };

    let vault_dir = contexte.vault_dir.clone();
    let resume = if vers_la_sortie_standard {
        let resume = Vault::export(&vault_dir, envelope, standard)?;
        standard.flush()?;
        resume
    } else {
        let mut fichier = std::fs::File::create(&options.destination)?;
        let resume = Vault::export(&vault_dir, envelope, &mut fichier)?;
        fichier.sync_all()?;
        resume
    };

    if contexte.json {
        contexte.console.output(&format!(
            "{{\"blob_count\":{},\"payload_bytes\":{}}}",
            resume.blob_count, resume.payload_bytes
        ));
    } else {
        contexte.console.info(&format!(
            "1 vault exporté, {}, {} blob(s).",
            taille_lisible(resume.payload_bytes),
            resume.blob_count
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::console::fake::FakeConsole;

    const PASSPHRASE: &str = "une passphrase bien assez longue";
    const NOUVELLE: &str = "une toute autre passphrase, aussi longue";

    fn coffre_peuple(atelier: &Path) -> PathBuf {
        let coffre = atelier.join("coffre");
        let mut vault = vault_core::Vault::create(
            &coffre,
            vault_core::SecretString::from(PASSPHRASE.to_owned()),
            vault_core::KdfParams::new(64, 1, 1).expect("valides"),
        )
        .expect("créable");
        let source = atelier.join("note.txt");
        std::fs::write(&source, b"une note").expect("écrivable");
        vault
            .add_file(
                &source,
                &vault_core::VaultPath::from_components([b"note.txt".to_vec()]).expect("valide"),
                vault_core::AddMode::Copy,
                vault_core::OnConflict::Fail,
            )
            .expect("ajoutable");
        vault.lock();
        coffre
    }

    fn contexte<'a>(console: &'a mut FakeConsole, coffre: &Path) -> Contexte<'a> {
        Contexte {
            console,
            vault_dir: coffre.to_path_buf(),
            yes: false,
            json: false,
            idle_timeout: None,
        }
    }

    /// XFR-001, XFR-002 : aucune passphrase n'est demandée, et l'avertissement
    /// est là quand même.
    #[test]
    fn un_export_par_defaut_ne_demande_rien_et_avertit() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());
        let cible = atelier.path().join("sauvegarde.vaultx");

        let mut console = FakeConsole::non_interactive();
        executer(
            &mut contexte(&mut console, &coffre),
            &Options {
                destination: cible.clone(),
                new_passphrase: false,
            },
            &mut Vec::new(),
            false,
        )
        .expect("exportable");

        assert!(
            console.invites.is_empty(),
            "aucune saisie ne doit être demandée : {:?}",
            console.invites
        );
        assert!(console.tout_affiche().contains("clé maîtresse"));
        assert!(console.tout_affiche().contains("1 vault exporté"));
        assert!(cible.is_file());
    }

    /// XFR-002 : l'avertissement passe par les avertissements, que `--quiet` ne
    /// supprime pas — et il est présenté **avec** `--new-passphrase` aussi
    /// (FR-006a).
    #[test]
    fn l_avertissement_survit_a_quiet_et_a_la_passphrase_distincte() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());

        let mut console = FakeConsole::new(&[PASSPHRASE, NOUVELLE, NOUVELLE], &[]);
        executer(
            &mut contexte(&mut console, &coffre),
            &Options {
                destination: atelier.path().join("avec-passphrase.vaultx"),
                new_passphrase: true,
            },
            &mut Vec::new(),
            false,
        )
        .expect("exportable");

        // L'avertissement vit dans les avertissements, et non dans la
        // progression : c'est ce qui le rend insensible à `--quiet`.
        assert!(
            console
                .avertissements
                .iter()
                .any(|texte| texte.contains("clé maîtresse")),
            "{:?}",
            console.avertissements
        );
        // XFR-003 : trois saisies, dans cet ordre.
        assert_eq!(console.invites.len(), 3);
        assert!(console.tout_affiche().contains("Robustesse"));
    }

    /// XFR-005 : un conteneur ne s'écrit pas sur un terminal.
    #[test]
    fn la_sortie_standard_refuse_un_terminal() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());

        let mut console = FakeConsole::non_interactive();
        let mut sortie = Vec::new();
        assert!(matches!(
            executer(
                &mut contexte(&mut console, &coffre),
                &Options {
                    destination: PathBuf::from(SORTIE_STANDARD),
                    new_passphrase: false,
                },
                &mut sortie,
                true,
            ),
            Err(CliError::Usage(message)) if message.contains("terminal")
        ));
        assert!(sortie.is_empty(), "aucun octet ne doit avoir été écrit");
    }

    /// XFR-006 : hors terminal, le conteneur sort **seul** sur la sortie
    /// standard, et tout le reste par la console.
    #[test]
    fn le_conteneur_sort_seul_sur_la_sortie_standard() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());

        let mut console = FakeConsole::non_interactive();
        let mut sortie = Vec::new();
        executer(
            &mut contexte(&mut console, &coffre),
            &Options {
                destination: PathBuf::from(SORTIE_STANDARD),
                new_passphrase: false,
            },
            &mut sortie,
            false,
        )
        .expect("exportable");

        // La magie suit immédiatement l'en-tête de carte CBOR et le nom du
        // champ : elle est dans les tout premiers octets, et rien ne la
        // précède qui vienne de la commande.
        let tete = &sortie[..16];
        assert!(
            tete.windows(vault_core::CONTAINER_MAGIC.len())
                .any(|fenetre| fenetre == vault_core::CONTAINER_MAGIC),
            "les premiers octets ne portent pas la magie du conteneur"
        );
        // Le résumé et l'avertissement sont passés par la console, pas par là.
        let affiche = console.tout_affiche();
        assert!(affiche.contains("1 vault exporté"));
        assert!(
            !String::from_utf8_lossy(&sortie).contains("vault exporté"),
            "rien d'autre que le conteneur"
        );
    }

    /// `--json` et `--to -` sont incompatibles : le rendu machine sortirait au
    /// milieu du conteneur.
    #[test]
    fn le_rendu_machine_et_la_sortie_standard_s_excluent() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());

        let mut console = FakeConsole::non_interactive();
        let mut ctx = contexte(&mut console, &coffre);
        ctx.json = true;
        let mut sortie = Vec::new();
        assert!(matches!(
            executer(
                &mut ctx,
                &Options {
                    destination: PathBuf::from(SORTIE_STANDARD),
                    new_passphrase: false,
                },
                &mut sortie,
                false,
            ),
            Err(CliError::Usage(message)) if message.contains("--json")
        ));
        assert!(sortie.is_empty());
    }

    /// Vers un fichier, `--json` rend le résumé sur la sortie machine.
    #[test]
    fn le_rendu_machine_resume_l_export_vers_un_fichier() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());

        let mut console = FakeConsole::non_interactive();
        let mut ctx = contexte(&mut console, &coffre);
        ctx.json = true;
        executer(
            &mut ctx,
            &Options {
                destination: atelier.path().join("s.vaultx"),
                new_passphrase: false,
            },
            &mut Vec::new(),
            false,
        )
        .expect("exportable");

        let affiche = console.tout_affiche();
        assert!(affiche.contains("\"blob_count\":1"), "{affiche}");
        assert!(affiche.contains("\"payload_bytes\":"), "{affiche}");
    }

    /// XFR-018, CLI-022 : sans terminal, `--new-passphrase` échoue au lieu de
    /// lire l'entrée standard — qui peut porter tout autre chose.
    #[test]
    fn sans_terminal_la_passphrase_distincte_echoue() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());

        let mut console = FakeConsole::non_interactive();
        assert!(matches!(
            executer(
                &mut contexte(&mut console, &coffre),
                &Options {
                    destination: atelier.path().join("s.vaultx"),
                    new_passphrase: true,
                },
                &mut Vec::new(),
                false,
            ),
            Err(CliError::NotInteractive)
        ));
    }

    /// Un chemin de sortie impossible remonte une erreur d'entrée-sortie, et le
    /// vault n'est pas touché.
    #[test]
    fn un_fichier_de_sortie_impossible_est_signale() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());

        let mut console = FakeConsole::non_interactive();
        assert!(matches!(
            executer(
                &mut contexte(&mut console, &coffre),
                &Options {
                    destination: atelier.path().join("absent").join("s.vaultx"),
                    new_passphrase: false,
                },
                &mut Vec::new(),
                false,
            ),
            Err(CliError::Io(_))
        ));
    }

    /// XFR-004 : un vault déjà ouvert par une autre instance rend 4, et
    /// l'avertissement a quand même été présenté.
    #[test]
    fn un_vault_deja_ouvert_est_refuse() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        let session = vault_core::Vault::create(
            &coffre,
            vault_core::SecretString::from(PASSPHRASE.to_owned()),
            vault_core::KdfParams::new(64, 1, 1).expect("valides"),
        )
        .expect("créable");

        let mut console = FakeConsole::non_interactive();
        let erreur = executer(
            &mut contexte(&mut console, &coffre),
            &Options {
                destination: atelier.path().join("s.vaultx"),
                new_passphrase: false,
            },
            &mut Vec::new(),
            false,
        )
        .expect_err("refus attendu");

        assert_eq!(erreur.code(), 4);
        assert!(console.tout_affiche().contains("clé maîtresse"));
        session.lock();
    }
}
