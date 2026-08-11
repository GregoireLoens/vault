//! `vault fetch` — T058.
//!
//! XFR-030 à XFR-032. Symétrique de [`crate::cmd::send`], et le sens compte :
//! c'est celui où le vault dort sur un serveur que rien ne permet de joindre en
//! retour, et où l'utilisateur est assis devant l'autre poste.
//!
//! **XFR-031 : `--new-passphrase` n'est pas offerte, et le refus nomme la
//! raison.** La variante exige d'ouvrir le vault source pour réenvelopper sa
//! clé maîtresse — donc que la passphrase parvienne au poste distant, ce que
//! FR-023 interdit sans exception. L'option existe donc dans la grammaire
//! **pour être refusée** : la retirer laisserait clap répondre « argument
//! inattendu », ce qui n'apprend rien.
//!
//! **L'avertissement de XFR-002 n'est pas répété ici.** L'export a lieu sur le
//! poste distant, et le vault de là-bas le présente déjà sur sa sortie
//! d'erreur — que vault n'intercepte pas (XFR-021). Il atteint donc le terminal
//! de l'utilisateur, une fois, et l'écrire une seconde fois localement en
//! ferait du bruit plutôt qu'une garantie.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use vault_core::{ImportPolicy, ImportSummary, RemoteTarget, SshOptions};

use crate::cmd::Contexte;
use crate::error::{CliError, CliResult};

/// Options de `vault fetch`.
// `ssh_options` répète le nom de la structure, et c'est voulu : c'est le nom
// de l'option de ligne de commande qu'il porte, `--ssh-option`, et le renommer
// éloignerait le champ de ce que l'utilisateur écrit.
#[allow(clippy::struct_field_names)]
pub struct Options {
    /// Source distante, `[utilisateur@]hôte:chemin`.
    pub source: OsString,
    /// Répertoire du vault à créer localement.
    pub destination: PathBuf,
    /// `--replace` : remplacer un vault existant à la destination.
    pub replace: bool,
    /// `--ssh-option`, répétable : passées telles quelles au client ssh.
    pub ssh_options: Vec<OsString>,
    /// `--remote-command` : commande vault à invoquer à distance.
    pub remote_command: Option<String>,
    /// `--new-passphrase` : acceptée par la grammaire **pour être refusée**.
    pub new_passphrase: bool,
}

/// Rapatrie un vault depuis un poste distant.
///
/// # Errors
///
/// - [`CliError::Usage`] si `--new-passphrase` est demandée (XFR-031), si la
///   destination ressemble à une cible distante, ou si la source est mal
///   formée ;
/// - [`vault_core::Error::DestinationOccupied`] si un vault occupe la
///   destination locale et que `--replace` n'a pas été demandé — **avant**
///   qu'aucune session ssh ne soit ouverte ;
/// - [`vault_core::Error::TransportFailed`] ou
///   [`vault_core::Error::RemoteFailed`], comme pour `send` (XFR-032).
pub fn executer(contexte: &mut Contexte, options: &Options) -> CliResult<()> {
    // XFR-031 : le refus nomme la raison, plutôt que de laisser croire à un
    // oubli.
    if options.new_passphrase {
        return Err(CliError::Usage(
            "--new-passphrase n'est pas offerte au rapatriement : elle exigerait d'ouvrir le \
vault distant, donc que votre passphrase traverse le canal. Rapatriez d'abord, puis employez \
`vault passwd` en local."
                .to_owned(),
        ));
    }
    if RemoteTarget::looks_remote(options.destination.as_os_str()) {
        return Err(CliError::Usage(
            "La destination de `fetch` est **locale**. Pour envoyer vers un poste distant, \
employez `send`."
                .to_owned(),
        ));
    }
    let source = RemoteTarget::parse(&options.source).map_err(|_| {
        CliError::Usage(
            "Source distante invalide : attendu `[utilisateur@]hôte:chemin`, en UTF-8.".to_owned(),
        )
    })?;

    let policy = if options.replace {
        ImportPolicy::Replace
    } else {
        ImportPolicy::Refuse
    };
    let ssh = SshOptions {
        options: options.ssh_options.clone(),
        remote_command: options
            .remote_command
            .clone()
            .unwrap_or_else(|| SshOptions::default().remote_command),
    };

    contexte.console.info("Vérification du poste distant…");
    // Voir la note jumelle de [`crate::cmd::send`].
    crate::cmd::transport::rapatrier_et_rendre_compte(
        contexte,
        &source,
        &options.destination,
        &ssh,
        policy,
    )
}

/// Dit ce qui est arrivé, où, et — s'il y a lieu — où l'ancien vault a été mis.
///
/// Séparée du rapatriement pour être éprouvable **sans** poste distant. Voir la
/// note jumelle de [`crate::cmd::send`].
pub(crate) fn rendre_compte(contexte: &mut Contexte, destination: &Path, resume: &ImportSummary) {
    // FR-013b : là comme ailleurs, vault dit où il a mis le vault remplacé, et
    // `--quiet` ne doit pas le faire disparaître.
    if let Some(ecarte) = &resume.replaced {
        contexte.console.warn(&format!(
            "L'ancien vault n'a pas été supprimé : il est en {}",
            ecarte.display()
        ));
    }

    if contexte.json {
        contexte.console.output(&format!(
            "{{\"blob_count\":{},\"payload_bytes\":{}}}",
            resume.blob_count, resume.payload_bytes
        ));
    } else {
        contexte.console.info(&format!(
            "Vault rapatrié : {} — {} blob(s), sceau vérifié.",
            destination.display(),
            resume.blob_count
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::console::fake::FakeConsole;

    fn contexte(console: &mut FakeConsole) -> Contexte<'_> {
        Contexte {
            console,
            vault_dir: PathBuf::from("."),
            yes: false,
            json: false,
            idle_timeout: None,
        }
    }

    fn options(source: &str, destination: &Path) -> Options {
        Options {
            source: OsString::from(source),
            destination: destination.to_path_buf(),
            replace: false,
            ssh_options: Vec::new(),
            remote_command: None,
            new_passphrase: false,
        }
    }

    /// XFR-031 : le refus **nomme la raison**, et cette raison est FR-023.
    #[test]
    fn la_passphrase_distincte_est_refusee_en_nommant_la_raison() {
        let mut console = FakeConsole::non_interactive();
        let erreur = executer(
            &mut contexte(&mut console),
            &Options {
                new_passphrase: true,
                ..options("poste-b:/coffre", Path::new("/local"))
            },
        )
        .expect_err("refus attendu");

        assert_eq!(erreur.code(), 2);
        let message = erreur.message();
        assert!(message.contains("traverse le canal"), "{message}");
        assert!(message.contains("passwd"), "{message}");
    }

    /// XFR-030 : la combinaison inverse est inexprimable, et une destination
    /// qui ressemble à une cible distante est refusée en disant quoi employer.
    #[test]
    fn une_destination_qui_ressemble_a_une_cible_est_refusee() {
        let mut console = FakeConsole::non_interactive();
        let erreur = executer(
            &mut contexte(&mut console),
            &options("poste-b:/coffre", Path::new("poste-c:/coffre")),
        )
        .expect_err("refus attendu");

        let message = erreur.message();
        assert_eq!(erreur.code(), 2);
        assert!(message.contains("send"), "{message}");
    }

    #[test]
    fn une_source_mal_formee_est_refusee() {
        for source in ["poste-b", "poste-b:", "@hote:/coffre", "/local/coffre"] {
            let mut console = FakeConsole::non_interactive();
            let erreur = executer(
                &mut contexte(&mut console),
                &options(source, Path::new("/local")),
            )
            .expect_err("refus attendu");
            assert_eq!(erreur.code(), 2, "{source}");
            assert!(erreur.message().contains("hôte:chemin"), "{source}");
        }
    }

    /// Le compte rendu dit ce qui est arrivé, et **où l'ancien vault a été
    /// mis** lorsqu'il y en avait un (FR-013b).
    #[test]
    fn le_compte_rendu_annonce_le_vault_ecarte() {
        let sans_remplacement = ImportSummary {
            blob_count: 3,
            payload_bytes: 2_400_000,
            replaced: None,
        };
        let mut console = FakeConsole::non_interactive();
        rendre_compte(
            &mut contexte(&mut console),
            Path::new("/local/coffre"),
            &sans_remplacement,
        );
        let affiche = console.tout_affiche();
        assert!(
            affiche.contains("Vault rapatrié : /local/coffre"),
            "{affiche}"
        );
        assert!(affiche.contains("3 blob(s)"), "{affiche}");
        assert!(!affiche.contains("pas été supprimé"), "{affiche}");

        let avec_remplacement = ImportSummary {
            replaced: Some(PathBuf::from("/local/coffre.vault-remplace-1234")),
            ..sans_remplacement.clone()
        };
        let mut console = FakeConsole::non_interactive();
        let mut ctx = contexte(&mut console);
        ctx.json = true;
        rendre_compte(&mut ctx, Path::new("/local/coffre"), &avec_remplacement);
        // L'annonce passe par les avertissements — `--quiet` ne la supprime
        // pas — tandis que le rendu machine sort seul sur la sortie.
        let avertissements = console.avertissements.join("\n");
        assert!(
            avertissements.contains(".vault-remplace-1234"),
            "{avertissements}"
        );
        assert!(
            console
                .sortie
                .iter()
                .any(|t| t.contains("\"blob_count\":3"))
        );
    }

    /// La **commande distante par défaut** est employée quand
    /// `--remote-command` est absente — cas que tous les autres tests évitent,
    /// et qui laissait donc sa fermeture jamais exécutée.
    ///
    /// L'hôte est sous le domaine réservé `.invalid` (RFC 2606) : il ne se
    /// résout **jamais**, sur aucune machine. Le lancement échoue donc tout de
    /// suite, sans tenter de joindre quoi que ce soit — c'est ce qui rend ce
    /// test sûr partout, y compris là où un vrai client ssh existe.
    #[test]
    fn la_commande_distante_par_defaut_est_employee() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let mut console = FakeConsole::non_interactive();

        let resultat = executer(
            &mut contexte(&mut console),
            &options(
                "hote-inexistant.invalid:/coffre",
                &atelier.path().join("libre"),
            ),
        );

        // XFR-027 : le transport a échoué, et c'est bien un échec **de
        // transport** — code 9 — et non un refus du vault.
        let erreur = resultat.expect_err("le transport devait échouer");
        assert_eq!(erreur.code(), 9);
        assert!(
            console
                .tout_affiche()
                .contains("Vérification du poste distant")
        );
    }

    /// `--replace` au rapatriement : la branche existe et doit être prise.
    #[test]
    fn un_rapatriement_avec_remplacement_va_jusqu_au_transport() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let mut console = FakeConsole::non_interactive();

        let erreur = executer(
            &mut contexte(&mut console),
            &Options {
                replace: true,
                ..options(
                    "hote-inexistant.invalid:/coffre",
                    &atelier.path().join("libre"),
                )
            },
        )
        .expect_err("le transport devait échouer");

        assert_eq!(erreur.code(), 9);
    }

    /// La destination locale est contrôlée **avant** qu'aucune session ssh ne
    /// soit ouverte : un vault qui l'occupe fait échouer sans réseau.
    #[test]
    fn une_destination_occupee_echoue_sans_ouvrir_de_session() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        vault_core::Vault::create(
            &coffre,
            vault_core::SecretString::from("une passphrase bien assez longue".to_owned()),
            vault_core::KdfParams::new(64, 1, 1).expect("valides"),
        )
        .expect("créable")
        .lock();

        let mut console = FakeConsole::non_interactive();
        let erreur = executer(
            &mut contexte(&mut console),
            &options("poste-b:/coffre", &coffre),
        )
        .expect_err("refus attendu");

        assert_eq!(erreur.code(), 8);
        assert!(erreur.message().contains("--replace"));
    }
}
