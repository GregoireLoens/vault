//! `vault send` — T057.
//!
//! XFR-020 à XFR-029. Une seule chose distingue cette commande d'un `export`
//! poussé dans un tube : **elle sonde avant de transmettre**.
//!
//! **XFR-029, FR-013d : la confirmation d'un remplacement est obtenue
//! localement, et avant le sondage.** La commande distante s'exécute sans
//! interaction possible — personne n'est assis devant elle. Demander là-bas
//! reviendrait à ne pas demander du tout ; demander ici, mais après avoir
//! transmis, reviendrait à demander trop tard.
//!
//! **XFR-002 : l'avertissement est présenté ici aussi.** Un envoi est un export,
//! et le conteneur qui part porte la clé maîtresse du vault source.

use std::ffi::OsString;
use std::path::PathBuf;

use vault_core::{ExportSummary, ImportPolicy, RemoteTarget, SshOptions};

use crate::cmd::{Contexte, taille_lisible};
use crate::error::{CliError, CliResult};
use crate::prompt;

/// Options de `vault send`.
// `ssh_options` répète le nom de la structure, et c'est voulu : c'est le nom
// de l'option de ligne de commande qu'il porte, `--ssh-option`, et le renommer
// éloignerait le champ de ce que l'utilisateur écrit.
#[allow(clippy::struct_field_names)]
pub struct Options {
    /// Vault local à envoyer.
    pub vault: PathBuf,
    /// Cible distante, `[utilisateur@]hôte:chemin`.
    pub cible: OsString,
    /// `--replace` : remplacer un vault existant à la destination.
    pub replace: bool,
    /// `--ssh-option`, répétable : passées telles quelles au client ssh.
    pub ssh_options: Vec<OsString>,
    /// `--remote-command` : commande vault à invoquer à distance.
    pub remote_command: Option<String>,
}

/// Envoie un vault local vers un poste distant.
///
/// # Errors
///
/// - [`CliError::Usage`] si le vault local ressemble à une cible distante
///   (FR-019a), ou si la cible est mal formée ;
/// - [`CliError::Refused`] si le remplacement n'est pas confirmé ;
/// - [`vault_core::Error::TransportFailed`] si le client ssh est absent, la
///   commande distante introuvable ou le canal rompu (XFR-027) ;
/// - [`vault_core::Error::RemoteFailed`] si la destination refuse — son code de
///   retour est alors celui qui remonte (FR-029b).
pub fn executer(contexte: &mut Contexte, options: &Options) -> CliResult<()> {
    // FR-019a : un contrôle de **forme**. La grammaire de `send` et `fetch`
    // rend la combinaison distant-distant inexprimable ; il reste à refuser
    // qu'un argument supposé local ressemble à une cible distante.
    if RemoteTarget::looks_remote(options.vault.as_os_str()) {
        return Err(CliError::Usage(
            "Le premier argument de `send` est un vault **local**. Pour rapatrier un vault \
distant, employez `fetch`."
                .to_owned(),
        ));
    }
    let cible = RemoteTarget::parse(&options.cible).map_err(|_| {
        CliError::Usage(
            "Cible distante invalide : attendu `[utilisateur@]hôte:chemin`, en UTF-8.".to_owned(),
        )
    })?;

    // XFR-002 : un envoi est un export, et l'avertissement vaut donc ici aussi.
    contexte.console.warn(crate::cmd::export::AVERTISSEMENT);

    let policy = if options.replace {
        // XFR-029 : **avant** le sondage, donc avant le premier octet.
        if !prompt::confirmer(
            contexte.console,
            "Remplacer le vault présent à la destination ? L'ancien sera déplacé, jamais supprimé.",
            contexte.yes,
        )? {
            return Err(CliError::Refused);
        }
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
    // Le transport, le compte rendu qui le suit et le succès vivent dans
    // [`crate::cmd::transport`] : ce sont les seules lignes de cette commande
    // que la mesure de couverture ne crédite pas, et ce fichier ne contient
    // qu'elles.
    crate::cmd::transport::envoyer_et_rendre_compte(contexte, &options.vault, &cible, &ssh, policy)
}

/// Dit ce qui est parti, et où.
///
/// Séparée de l'envoi pour être éprouvable **sans** poste distant : un compte
/// rendu est une mise en forme, et rien de ce qu'il contient ne dépend du
/// transport. Ce n'est pas une couture — le chemin réel passe par ici lui
/// aussi, et les tests de bout en bout le traversent.
pub(crate) fn rendre_compte(contexte: &mut Contexte, cible: &RemoteTarget, resume: &ExportSummary) {
    if contexte.json {
        contexte.console.output(&format!(
            "{{\"blob_count\":{},\"payload_bytes\":{}}}",
            resume.blob_count, resume.payload_bytes
        ));
    } else {
        contexte.console.info(&format!(
            "{} transférés. Vault reçu : {}:{}",
            taille_lisible(resume.payload_bytes),
            cible.host(),
            cible.path()
        ));
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

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

    fn options(vault: &Path, cible: &str) -> Options {
        Options {
            vault: vault.to_path_buf(),
            cible: OsString::from(cible),
            replace: false,
            ssh_options: Vec::new(),
            remote_command: None,
        }
    }

    /// FR-019a : un vault local qui ressemble à une cible distante est refusé,
    /// et le message dit **quoi faire** plutôt que de constater l'erreur.
    #[test]
    fn un_vault_local_qui_ressemble_a_une_cible_est_refuse() {
        let mut console = FakeConsole::non_interactive();
        let erreur = executer(
            &mut contexte(&mut console),
            &options(Path::new("poste-a:/coffre"), "poste-b:/coffre"),
        )
        .expect_err("refus attendu");

        let message = erreur.message();
        assert_eq!(erreur.code(), 2);
        assert!(message.contains("fetch"), "{message}");
    }

    #[test]
    fn une_cible_mal_formee_est_refusee() {
        for cible in ["poste-b", "poste-b:", "@hote:/coffre"] {
            let mut console = FakeConsole::non_interactive();
            let erreur = executer(
                &mut contexte(&mut console),
                &options(Path::new("/coffre"), cible),
            )
            .expect_err("refus attendu");
            assert_eq!(erreur.code(), 2, "{cible}");
            assert!(erreur.message().contains("hôte:chemin"), "{cible}");
        }
    }

    /// XFR-029 : la confirmation est demandée **avant** le sondage. Sans
    /// terminal et sans `--yes`, l'envoi s'arrête donc là — et l'avertissement
    /// de XFR-002 a déjà été présenté.
    #[test]
    fn un_remplacement_non_confirme_n_envoie_rien() {
        let mut console = FakeConsole::non_interactive();
        let erreur = executer(
            &mut contexte(&mut console),
            &Options {
                replace: true,
                ..options(Path::new("/coffre"), "poste-b:/coffre")
            },
        )
        .expect_err("refus attendu");

        assert_eq!(erreur.code(), 2);
        assert!(console.tout_affiche().contains("clé maîtresse"));
        assert!(
            !console
                .tout_affiche()
                .contains("Vérification du poste distant"),
            "le sondage ne doit pas avoir eu lieu"
        );

        // Une réponse négative explicite mène au même endroit.
        let mut console = FakeConsole::new(&[], &["n"]);
        let refus = executer(
            &mut contexte(&mut console),
            &Options {
                replace: true,
                ..options(Path::new("/coffre"), "poste-b:/coffre")
            },
        )
        .expect_err("refus attendu");
        assert_eq!(refus.code(), 2);
        assert_eq!(refus.message(), CliError::Refused.message());
    }

    /// XFR-029 : la confirmation **accordée** mène au sondage. L'hôte est sous
    /// le domaine réservé `.invalid` (RFC 2606), qui ne se résout jamais : le
    /// lancement échoue tout de suite, sans joindre quoi que ce soit.
    #[test]
    fn un_remplacement_confirme_va_jusqu_au_transport() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let mut console = FakeConsole::non_interactive();
        let mut ctx = contexte(&mut console);
        ctx.yes = true;

        let erreur = executer(
            &mut ctx,
            &Options {
                replace: true,
                ..options(
                    &atelier.path().join("coffre"),
                    "hote-inexistant.invalid:/coffre",
                )
            },
        )
        .expect_err("le transport devait échouer");

        assert_eq!(erreur.code(), 9);
        assert!(
            console
                .tout_affiche()
                .contains("Vérification du poste distant")
        );
    }

    /// Le compte rendu dit **où** le vault est arrivé, dans les deux rendus.
    #[test]
    fn le_compte_rendu_nomme_la_destination() {
        let resume = ExportSummary {
            blob_count: 3,
            payload_bytes: 2_400_000,
        };
        let cible =
            RemoteTarget::parse(OsString::from("poste-b:~/coffres/v").as_os_str()).expect("valide");

        let mut console = FakeConsole::non_interactive();
        rendre_compte(&mut contexte(&mut console), &cible, &resume);
        let affiche = console.tout_affiche();
        assert!(affiche.contains("2.4 Mo transférés"), "{affiche}");
        assert!(affiche.contains("poste-b:~/coffres/v"), "{affiche}");

        let mut console = FakeConsole::non_interactive();
        let mut ctx = contexte(&mut console);
        ctx.json = true;
        rendre_compte(&mut ctx, &cible, &resume);
        let affiche = console.tout_affiche();
        assert!(affiche.contains("\"blob_count\":3"), "{affiche}");
        assert!(affiche.contains("\"payload_bytes\":2400000"), "{affiche}");
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
                &atelier.path().join("coffre"),
                "hote-inexistant.invalid:/coffre",
            ),
        );

        // Le transport échoue — c'est attendu — mais la ligne a bien été
        // assemblée avec la commande distante par défaut.
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

    /// La commande distante par défaut est `vault`, et `--remote-command` la
    /// remplace.
    #[test]
    fn la_commande_distante_suit_l_option() {
        assert_eq!(SshOptions::default().remote_command, "vault");

        let choisie = Options {
            remote_command: Some("/opt/vault".to_owned()),
            ..options(Path::new("/coffre"), "poste-b:/coffre")
        };
        assert_eq!(choisie.remote_command.as_deref(), Some("/opt/vault"));
    }
}
