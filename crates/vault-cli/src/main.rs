//! `vault` — interface en ligne de commande.
//!
//! Habillage de `vault-core` : aucune logique cryptographique ici. Le rôle de
//! ce binaire est de convertir des arguments en appels de bibliothèque, de
//! gérer la saisie de la passphrase, et de porter les avertissements et
//! confirmations que la bibliothèque n'affiche délibérément pas.
//!
//! **CLI-001** : la passphrase n'est **jamais** acceptée en argument. Elle
//! apparaîtrait dans l'historique du shell et dans la table des processus. Le
//! contrat prévoit qu'une variable d'environnement dédiée pourra être ajoutée
//! plus tard pour les usages scriptés ; ce n'est pas le cas ici.

mod cmd;
mod console;
mod error;
mod prompt;

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use vault_core::{AddMode, OnConflict};

use crate::cmd::Contexte;
use crate::console::{Console, Terminal};
use crate::error::{CliError, CliResult};

/// Coffre-fort local, chiffré de bout en bout.
#[derive(Parser)]
#[command(name = "vault", version, about, long_about = None)]
struct Cli {
    /// Emplacement du vault. Par défaut, le répertoire courant.
    #[arg(long, global = true, value_name = "CHEMIN")]
    vault: Option<PathBuf>,

    /// Répond oui aux confirmations. Sans effet sur l'avertissement de création.
    #[arg(long, global = true)]
    yes: bool,

    /// Sortie lisible par une machine.
    #[arg(long, global = true)]
    json: bool,

    /// Supprime la progression, conserve les erreurs et les avertissements.
    #[arg(long, global = true)]
    quiet: bool,

    /// Délai d'inactivité, en secondes. Accepté et conservé, sans effet.
    #[arg(long, global = true, value_name = "SECONDES")]
    idle_timeout: Option<u64>,

    #[command(subcommand)]
    commande: Commande,
}

#[derive(Subcommand)]
enum Commande {
    /// Crée un vault.
    Create {
        /// Emplacement du vault à créer.
        emplacement: PathBuf,
        /// Coût mémoire d'Argon2id, en kibioctets.
        #[arg(long, value_name = "KIO")]
        kdf_memory: Option<u32>,
        /// Nombre de passes d'Argon2id.
        #[arg(long, value_name = "N")]
        kdf_iterations: Option<u32>,
        /// Degré de parallélisme d'Argon2id.
        #[arg(long, value_name = "N")]
        kdf_parallelism: Option<u32>,
    },
    /// Ajoute des fichiers ou des dossiers.
    Add {
        /// Sources à ajouter.
        #[arg(required = true)]
        sources: Vec<PathBuf>,
        /// Destination dans le vault.
        #[arg(long = "as", value_name = "CHEMIN")]
        destination: Option<PathBuf>,
        /// Supprime l'original après ajout vérifié. C'est le défaut.
        #[arg(long, conflicts_with = "copy")]
        r#move: bool,
        /// Conserve l'original en clair sur le disque.
        #[arg(long)]
        copy: bool,
        /// Résolution des collisions.
        #[arg(long, value_name = "MODE", value_parser = ["fail", "replace", "rename"])]
        on_conflict: Option<String>,
    },
    /// Liste le contenu.
    Ls {
        /// Chemin à lister. La racine par défaut.
        chemin: Option<PathBuf>,
        /// Ajoute l'identifiant de blob et la taille après remplissage.
        #[arg(long)]
        long: bool,
    },
    /// Supprime des entrées. Définitif : ni corbeille, ni annulation.
    Rm {
        /// Entrées à supprimer.
        #[arg(required = true)]
        chemins: Vec<PathBuf>,
        /// Emporte la descendance d'un dossier.
        #[arg(long, short = 'r')]
        recursive: bool,
    },
    /// Change la passphrase. Immédiat : le contenu n'est pas réécrit.
    Passwd,
    /// Affiche les paramètres publics d'un vault ou d'un conteneur.
    Info {
        /// Conteneur à interroger. Sans lui, c'est le vault de `--vault`.
        conteneur: Option<PathBuf>,
    },
    /// Extrait vers le disque, en clair.
    Extract {
        /// Entrées à extraire.
        #[arg(required = true)]
        chemins: Vec<PathBuf>,
        /// Répertoire de destination.
        #[arg(long = "to", value_name = "CHEMIN")]
        destination: PathBuf,
    },
    /// Produit un conteneur portable depuis le vault.
    Export {
        /// Fichier de sortie. `-` désigne la sortie standard.
        #[arg(long = "to", value_name = "CHEMIN", required_unless_present = "probe")]
        destination: Option<PathBuf>,
        /// Protège le conteneur par une passphrase distincte.
        #[arg(long)]
        new_passphrase: bool,
        /// Sonde le vault sans rien produire. Employée par `fetch` (D-205).
        #[arg(long, hide = true)]
        probe: bool,
    },
    /// Reconstitue un vault depuis un conteneur.
    Import {
        /// Conteneur à lire. `-` désigne l'entrée standard.
        #[arg(required_unless_present = "probe")]
        source: Option<PathBuf>,
        /// Répertoire du vault à créer.
        #[arg(long = "to", value_name = "CHEMIN")]
        destination: PathBuf,
        /// Remplace un vault existant à cette destination.
        #[arg(long)]
        replace: bool,
        /// Contrôle en outre tous les tags AEAD. Demande la passphrase.
        #[arg(long)]
        verify_content: bool,
        /// Sonde la destination sans rien recevoir. Employée par `send` (D-205).
        #[arg(long, hide = true)]
        probe: bool,
        /// Version de conteneur que l'émetteur annonce, pour le sondage.
        #[arg(long, value_name = "N", hide = true)]
        container_version: Option<u32>,
    },
    /// Envoie un vault local vers un poste distant, par ssh.
    Send {
        /// Vault local à envoyer.
        vault: PathBuf,
        /// Cible distante, `[utilisateur@]hôte:chemin`.
        cible: std::ffi::OsString,
        /// Remplace un vault existant à la destination.
        #[arg(long)]
        replace: bool,
        /// Option passée telle quelle au client ssh. Répétable.
        ///
        /// `allow_hyphen_values` est indispensable : ces valeurs commencent
        /// presque toujours par un tiret — `-p2222`, `-oControlMaster=auto` —
        /// et clap les prendrait sinon pour des drapeaux de vault (FR-027).
        #[arg(long = "ssh-option", value_name = "OPT", allow_hyphen_values = true)]
        ssh_options: Vec<std::ffi::OsString>,
        /// Commande vault à invoquer à distance. `vault` par défaut.
        #[arg(long, value_name = "CMD")]
        remote_command: Option<String>,
    },
    /// Rapatrie un vault depuis un poste distant, par ssh.
    Fetch {
        /// Source distante, `[utilisateur@]hôte:chemin`.
        source: std::ffi::OsString,
        /// Répertoire du vault à créer localement.
        destination: PathBuf,
        /// Remplace un vault existant à la destination.
        #[arg(long)]
        replace: bool,
        /// Option passée telle quelle au client ssh. Répétable.
        ///
        /// `allow_hyphen_values` est indispensable : ces valeurs commencent
        /// presque toujours par un tiret — `-p2222`, `-oControlMaster=auto` —
        /// et clap les prendrait sinon pour des drapeaux de vault (FR-027).
        #[arg(long = "ssh-option", value_name = "OPT", allow_hyphen_values = true)]
        ssh_options: Vec<std::ffi::OsString>,
        /// Commande vault à invoquer à distance. `vault` par défaut.
        #[arg(long, value_name = "CMD")]
        remote_command: Option<String>,
        /// Refusée : elle exigerait que la passphrase traverse le canal.
        #[arg(long)]
        new_passphrase: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    let mut console = Terminal::new(std::io::stdout(), std::io::stderr(), cli.quiet);
    let code = match executer(&cli, &mut console) {
        Ok(()) => 0,
        Err(erreur) => {
            console.warn(&format!("Erreur : {}", erreur.message()));
            erreur.code()
        }
    };
    std::process::exit(code);
}

/// Exécute la commande demandée.
///
/// Cette fonction est **longue par nature** : c'est une table d'aiguillage, et
/// elle gagne une entrée par commande. La découper ne la raccourcirait pas —
/// elle déplacerait les entrées ailleurs, en ajoutant au passage un bras
/// inatteignable dans chaque moitié, que la porte de couverture refuserait à
/// juste titre. Chaque bras y tient en une expression, et se lit seul.
#[allow(clippy::too_many_lines)]
fn executer(cli: &Cli, console: &mut dyn Console) -> CliResult<()> {
    let mut contexte = Contexte {
        console,
        vault_dir: cli.vault.clone().unwrap_or_else(|| PathBuf::from(".")),
        yes: cli.yes,
        json: cli.json,
        idle_timeout: cli.idle_timeout.map(Duration::from_secs),
    };

    match &cli.commande {
        Commande::Create {
            emplacement,
            kdf_memory,
            kdf_iterations,
            kdf_parallelism,
        } => cmd::create::executer(
            &mut contexte,
            emplacement,
            cmd::create::OptionsKdf {
                memory_kib: *kdf_memory,
                iterations: *kdf_iterations,
                parallelism: *kdf_parallelism,
            },
        ),
        Commande::Add {
            sources,
            destination,
            r#move,
            copy,
            on_conflict,
        } => {
            let mode = if *copy { AddMode::Copy } else { AddMode::Move };
            debug_assert!(!(*r#move && *copy), "clap exclut déjà les deux ensemble");
            cmd::add::executer(
                &mut contexte,
                &cmd::add::Options {
                    sources: sources.clone(),
                    destination: destination.clone(),
                    mode,
                    on_conflict: politique(on_conflict.as_deref())?,
                    quiet: cli.quiet,
                    seuil_progression: cmd::add::SEUIL_PROGRESSION,
                },
            )
        }
        Commande::Ls { chemin, long } => cmd::ls::executer(
            &mut contexte,
            &cmd::ls::Options {
                chemin: chemin.clone(),
                long: *long,
            },
        ),
        Commande::Rm { chemins, recursive } => cmd::rm::executer(
            &mut contexte,
            &cmd::rm::Options {
                chemins: chemins.clone(),
                recursive: *recursive,
            },
        ),
        Commande::Passwd => cmd::passwd::executer(&mut contexte),
        Commande::Info { conteneur } => cmd::info::executer(
            &mut contexte,
            &cmd::info::Options {
                conteneur: conteneur.clone(),
            },
        ),
        Commande::Extract {
            chemins,
            destination,
        } => cmd::extract::executer(
            &mut contexte,
            &cmd::extract::Options {
                chemins: chemins.clone(),
                destination: destination.clone(),
            },
        ),
        Commande::Export {
            destination,
            new_passphrase,
            probe,
        } => exporter(
            &mut contexte,
            &cmd::export::Options {
                destination: destination.clone().unwrap_or_default(),
                new_passphrase: *new_passphrase,
                probe: *probe,
            },
        ),
        Commande::Import {
            source,
            destination,
            replace,
            verify_content,
            probe,
            container_version,
        } => importer(
            &mut contexte,
            &cmd::import::Options {
                source: source.clone().unwrap_or_default(),
                destination: destination.clone(),
                replace: *replace,
                verify_content: *verify_content,
                probe: *probe,
                container_version: *container_version,
            },
        ),
        Commande::Send {
            vault,
            cible,
            replace,
            ssh_options,
            remote_command,
        } => cmd::send::executer(
            &mut contexte,
            &cmd::send::Options {
                vault: vault.clone(),
                cible: cible.clone(),
                replace: *replace,
                ssh_options: ssh_options.clone(),
                remote_command: remote_command.clone(),
            },
        ),
        Commande::Fetch {
            source,
            destination,
            replace,
            ssh_options,
            remote_command,
            new_passphrase,
        } => cmd::fetch::executer(
            &mut contexte,
            &cmd::fetch::Options {
                source: source.clone(),
                destination: destination.clone(),
                replace: *replace,
                ssh_options: ssh_options.clone(),
                remote_command: remote_command.clone(),
                new_passphrase: *new_passphrase,
            },
        ),
    }
}

/// Branche `vault export` sur la sortie standard du processus.
///
/// Le conteneur y sort **seul** (XFR-006). La détection de terminal vit dans
/// `console::tty`, seul fichier exclu de la couverture ; la **décision** qui en
/// découle est dans la commande, donc mesurée (XFR-005).
fn exporter(contexte: &mut Contexte, options: &cmd::export::Options) -> CliResult<()> {
    let mut sortie = std::io::stdout().lock();
    cmd::export::executer(
        contexte,
        options,
        &mut sortie,
        crate::console::tty::stdout_is_terminal(),
    )
}

/// Branche `vault import` sur l'entrée standard du processus, d'où le conteneur
/// peut venir (FR-036).
fn importer(contexte: &mut Contexte, options: &cmd::import::Options) -> CliResult<()> {
    let mut entree = std::io::stdin().lock();
    cmd::import::executer(contexte, options, &mut entree)
}

/// Traduit `--on-conflict` en politique de la bibliothèque.
fn politique(demandee: Option<&str>) -> CliResult<OnConflict> {
    match demandee {
        None | Some("fail") => Ok(OnConflict::Fail),
        Some("replace") => Ok(OnConflict::Replace),
        Some("rename") => Ok(OnConflict::Rename),
        Some(autre) => Err(CliError::Usage(format!(
            "Résolution de collision inconnue : {autre}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;
    use crate::console::fake::FakeConsole;

    const PASSPHRASE: &str = "une passphrase bien assez longue";
    const NOUVELLE: &str = "une toute autre passphrase, aussi longue";

    fn analyser(arguments: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("vault").chain(arguments.iter().copied()))
            .expect("arguments valides")
    }

    #[test]
    fn la_ligne_de_commande_est_conforme_au_contrat() {
        Cli::command().debug_assert();
    }

    #[test]
    fn les_options_communes_sont_globales() {
        let cli = analyser(&["ls", "--vault", "/tmp/coffre", "--json", "--quiet", "--yes"]);
        assert_eq!(cli.vault, Some(PathBuf::from("/tmp/coffre")));
        assert!(cli.json && cli.quiet && cli.yes);
        assert!(matches!(cli.commande, Commande::Ls { .. }));
    }

    /// CLI-023 : `--idle-timeout` est accepté et conservé, sans effet.
    #[test]
    fn le_delai_d_inactivite_est_accepte() {
        let cli = analyser(&["ls", "--idle-timeout", "300"]);
        assert_eq!(cli.idle_timeout, Some(300));
    }

    /// FR-018 : `--move` est le défaut, et `--copy` l'inverse.
    #[test]
    fn le_deplacement_est_le_mode_par_defaut() {
        for (arguments, attendu) in [
            (vec!["add", "x"], AddMode::Move),
            (vec!["add", "--move", "x"], AddMode::Move),
            (vec!["add", "--copy", "x"], AddMode::Copy),
        ] {
            let cli = analyser(&arguments);
            let attendu_copy = attendu == AddMode::Copy;
            assert!(
                matches!(&cli.commande, Commande::Add { r#move, copy, .. }
                    if *copy == attendu_copy && !(*r#move && *copy)),
                "{arguments:?}"
            );
        }

        assert!(Cli::try_parse_from(["vault", "add", "--move", "--copy", "x"]).is_err());
    }

    #[test]
    fn les_politiques_de_collision_sont_traduites() {
        assert_eq!(politique(None).expect("valide"), OnConflict::Fail);
        assert_eq!(politique(Some("fail")).expect("valide"), OnConflict::Fail);
        assert_eq!(
            politique(Some("replace")).expect("valide"),
            OnConflict::Replace
        );
        assert_eq!(
            politique(Some("rename")).expect("valide"),
            OnConflict::Rename
        );
        assert!(matches!(politique(Some("autre")), Err(CliError::Usage(_))));

        // clap refuse la valeur en amont, avant même d'appeler `politique`.
        assert!(Cli::try_parse_from(["vault", "add", "--on-conflict", "autre", "x"]).is_err());
    }

    #[test]
    fn les_arguments_obligatoires_sont_exiges() {
        assert!(Cli::try_parse_from(["vault"]).is_err());
        assert!(Cli::try_parse_from(["vault", "create"]).is_err());
        assert!(Cli::try_parse_from(["vault", "add"]).is_err());
        assert!(Cli::try_parse_from(["vault", "extract"]).is_err());
        assert!(Cli::try_parse_from(["vault", "extract", "x"]).is_err());
    }

    /// Le vault visé est le répertoire courant par défaut.
    #[test]
    fn le_vault_par_defaut_est_le_repertoire_courant() {
        let cli = analyser(&["ls"]);
        let mut console = FakeConsole::non_interactive();
        // Le déverrouillage échoue faute de terminal, mais l'emplacement a bien
        // été résolu avant : l'erreur est celle de la saisie, pas d'un chemin.
        assert!(matches!(
            executer(&cli, &mut console),
            Err(CliError::NotInteractive | CliError::Core(vault_core::Error::NotFound))
        ));
    }

    /// CLI-019, sous sa forme la plus exigeante : **le code et le message
    /// produits par une passphrase erronée et par un vault altéré sont
    /// identiques, octet pour octet**.
    ///
    /// La vérification a lieu ici plutôt que dans `tests/cli.rs` parce qu'elle
    /// exige une passphrase, donc un terminal, qu'un processus de test n'a pas
    /// (CLI-022). Ce chemin-ci traverse pourtant le même `executer` et le même
    /// `CliError` que le binaire : c'est bien la sortie réelle qui est comparée.
    #[test]
    fn le_code_3_est_indiscernable_de_ses_deux_causes() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        vault_core::Vault::create(
            &coffre,
            vault_core::SecretString::from(PASSPHRASE.to_owned()),
            vault_core::KdfParams::new(64, 1, 1).expect("valides"),
        )
        .expect("créable")
        .lock();

        let listage = analyser(&["ls", "--vault", coffre.to_str().expect("UTF-8")]);
        let echouer = |saisie: &str| {
            let mut console = FakeConsole::new(&[saisie], &[]);
            let erreur = executer(&listage, &mut console).expect_err("refus attendu");
            (erreur.code(), erreur.message().into_bytes())
        };

        let reference = echouer("une passphrase parfaitement fausse");
        assert_eq!(reference.0, 3);

        // Chaque altération de l'en-tête qui mène jusqu'à l'authentification
        // doit rendre exactement la même chose, avec la **bonne** passphrase.
        let en_tete = coffre.join("header");
        let original = std::fs::read(&en_tete).expect("lisible");
        let mut verdicts = Vec::new();
        for position in 0..original.len() {
            let mut altere = original.clone();
            altere[position] ^= 0x01;
            std::fs::write(&en_tete, &altere).expect("écrivable");

            let obtenu = echouer(PASSPHRASE);
            if obtenu.0 == 3 {
                verdicts.push(obtenu == reference);
            }
        }
        std::fs::write(&en_tete, &original).expect("écrivable");

        assert!(
            !verdicts.is_empty(),
            "aucune altération n'a produit un code 3"
        );
        assert_eq!(verdicts, vec![true; verdicts.len()]);
    }

    /// Le parcours complet des sept commandes, sur un vault jetable.
    #[test]
    fn les_sept_commandes_s_enchainent() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        let source = atelier.path().join("note.txt");
        std::fs::write(&source, b"contenu").expect("écrivable");
        let sortie = atelier.path().join("sortie");

        let creation = analyser(&[
            "create",
            coffre.to_str().expect("UTF-8"),
            "--kdf-memory",
            "64",
            "--kdf-iterations",
            "1",
            "--kdf-parallelism",
            "1",
        ]);
        let mut console = FakeConsole::new(&[PASSPHRASE, PASSPHRASE], &["OUI"]);
        executer(&creation, &mut console).expect("créable");

        let ajout = analyser(&[
            "add",
            source.to_str().expect("UTF-8"),
            "--copy",
            "--vault",
            coffre.to_str().expect("UTF-8"),
        ]);
        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        executer(&ajout, &mut console).expect("ajoutable");

        let listage = analyser(&["ls", "--vault", coffre.to_str().expect("UTF-8"), "--long"]);
        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        executer(&listage, &mut console).expect("listable");
        assert!(console.tout_affiche().contains("note.txt"));

        // CLI-018 : seule commande à n'exiger aucune saisie.
        let information = analyser(&["info", "--vault", coffre.to_str().expect("UTF-8")]);
        let mut console = FakeConsole::non_interactive();
        executer(&information, &mut console).expect("consultable");
        assert!(console.tout_affiche().contains("argon2id"));

        let extraction = analyser(&[
            "extract",
            "note.txt",
            "--to",
            sortie.to_str().expect("UTF-8"),
            "--vault",
            coffre.to_str().expect("UTF-8"),
        ]);
        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        executer(&extraction, &mut console).expect("extractible");
        assert_eq!(
            std::fs::read(sortie.join("note.txt")).expect("lisible"),
            b"contenu"
        );

        // La passphrase change avant la suppression : la suite du parcours doit
        // s'en servir, ce qui prouve que le changement a bien pris.
        let changement = analyser(&["passwd", "--vault", coffre.to_str().expect("UTF-8")]);
        let mut console = FakeConsole::new(&[PASSPHRASE, NOUVELLE, NOUVELLE], &[]);
        executer(&changement, &mut console).expect("changeable");
        assert!(console.tout_affiche().contains("ne réécrit pas le contenu"));

        let suppression = analyser(&[
            "rm",
            "note.txt",
            "--yes",
            "--vault",
            coffre.to_str().expect("UTF-8"),
        ]);
        let mut console = FakeConsole::new(&[NOUVELLE], &[]);
        executer(&suppression, &mut console).expect("supprimable");
        assert!(console.tout_affiche().contains("1 entrée(s) supprimée(s)"));

        // Le vault est vide, et la copie extraite plus tôt est intacte.
        let listage = analyser(&["ls", "--vault", coffre.to_str().expect("UTF-8")]);
        let mut console = FakeConsole::new(&[NOUVELLE], &[]);
        executer(&listage, &mut console).expect("listable");
        assert!(
            console
                .tout_affiche()
                .contains("0 dossier(s), 0 fichier(s)")
        );
        assert!(sortie.join("note.txt").is_file());
    }

    /// Les deux commandes de transfert, prises par le même chemin que le
    /// binaire — **sans qu'aucune session ssh ne soit ouverte**.
    ///
    /// C'est délibéré, et c'est ce qui rend ce test sûr partout : chaque cas
    /// échoue **avant** le lancement du sous-processus. Un test qui laisserait
    /// `send` atteindre le client tenterait de joindre un hôte nommé
    /// `poste-b` sur la machine de qui l'exécute. Les transferts qui vont
    /// jusqu'au bout vivent dans `tests/transfer.rs`, contre le faux client.
    #[test]
    fn les_transferts_s_arretent_avant_toute_session() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        vault_core::Vault::create(
            &coffre,
            vault_core::SecretString::from(PASSPHRASE.to_owned()),
            vault_core::KdfParams::new(64, 1, 1).expect("valides"),
        )
        .expect("créable")
        .lock();

        // XFR-029 : sans terminal et sans `--yes`, le remplacement ne peut pas
        // être confirmé — et rien ne part.
        let envoi = analyser(&[
            "send",
            coffre.to_str().expect("UTF-8"),
            "poste-b:/coffres/v",
            "--replace",
            "--ssh-option",
            "-p2222",
            "--remote-command",
            "/opt/vault",
        ]);
        let mut console = FakeConsole::non_interactive();
        assert_eq!(
            executer(&envoi, &mut console)
                .expect_err("refus attendu")
                .code(),
            2
        );

        // La destination d'un rapatriement est locale : occupée, elle fait
        // échouer avant qu'aucune session ne soit ouverte.
        let rapatriement = analyser(&[
            "fetch",
            "poste-b:/coffres/v",
            coffre.to_str().expect("UTF-8"),
            "--ssh-option",
            "-p2222",
            "--remote-command",
            "/opt/vault",
        ]);
        let mut console = FakeConsole::non_interactive();
        assert_eq!(
            executer(&rapatriement, &mut console)
                .expect_err("refus attendu")
                .code(),
            8
        );
    }

    /// Le sondage passe par le même aiguillage que les commandes ordinaires.
    #[test]
    fn le_sondage_passe_par_l_aiguillage() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        vault_core::Vault::create(
            &coffre,
            vault_core::SecretString::from(PASSPHRASE.to_owned()),
            vault_core::KdfParams::new(64, 1, 1).expect("valides"),
        )
        .expect("créable")
        .lock();

        let sondage_export = analyser(&[
            "export",
            "--probe",
            "--vault",
            coffre.to_str().expect("UTF-8"),
        ]);
        let mut console = FakeConsole::non_interactive();
        executer(&sondage_export, &mut console).expect("le vault est lisible");

        let sondage_import = analyser(&[
            "import",
            "--probe",
            "--to",
            coffre.to_str().expect("UTF-8"),
            "--container-version",
            "1",
        ]);
        let mut console = FakeConsole::non_interactive();
        assert_eq!(
            executer(&sondage_import, &mut console)
                .expect_err("destination occupée")
                .code(),
            8
        );
    }

    /// Les deux commandes de la feature 003, prises par le même chemin que le
    /// binaire : `Cli` → `executer` → `cmd::export` / `cmd::import`.
    ///
    /// Elles vivent ici, et non dans `tests/cli.rs`, parce que le binaire écrit
    /// alors sur la **vraie** sortie standard : un test de processus ne pourrait
    /// pas distinguer un conteneur d'un message. Ce chemin-ci traverse pourtant
    /// le même `executer`, donc la même construction d'options et le même
    /// verrouillage de flux.
    #[test]
    fn l_export_et_l_import_s_enchainent() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        let source = atelier.path().join("note.txt");
        std::fs::write(&source, b"contenu").expect("écrivable");
        let conteneur = atelier.path().join("sauvegarde.vaultx");
        let restaure = atelier.path().join("restaure");

        let creation = analyser(&[
            "create",
            coffre.to_str().expect("UTF-8"),
            "--kdf-memory",
            "64",
            "--kdf-iterations",
            "1",
            "--kdf-parallelism",
            "1",
        ]);
        let mut console = FakeConsole::new(&[PASSPHRASE, PASSPHRASE], &["OUI"]);
        executer(&creation, &mut console).expect("créable");

        let ajout = analyser(&[
            "add",
            source.to_str().expect("UTF-8"),
            "--copy",
            "--vault",
            coffre.to_str().expect("UTF-8"),
        ]);
        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        executer(&ajout, &mut console).expect("ajoutable");

        // XFR-001, XFR-002 : aucune saisie, et l'avertissement quand même.
        let export = analyser(&[
            "export",
            "--to",
            conteneur.to_str().expect("UTF-8"),
            "--vault",
            coffre.to_str().expect("UTF-8"),
        ]);
        let mut console = FakeConsole::non_interactive();
        executer(&export, &mut console).expect("exportable");
        assert!(console.invites.is_empty(), "{:?}", console.invites);
        assert!(console.tout_affiche().contains("clé maîtresse"));
        assert!(conteneur.is_file());

        // XFR-010 : aucune saisie non plus à l'import.
        let import = analyser(&[
            "import",
            conteneur.to_str().expect("UTF-8"),
            "--to",
            restaure.to_str().expect("UTF-8"),
        ]);
        let mut console = FakeConsole::non_interactive();
        executer(&import, &mut console).expect("importable");
        assert!(console.tout_affiche().contains("sceau vérifié"));

        // Le vault restitué s'ouvre avec la passphrase du vault source, et son
        // contenu est celui qu'on y avait déposé.
        let listage = analyser(&["ls", "--vault", restaure.to_str().expect("UTF-8")]);
        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        executer(&listage, &mut console).expect("listable");
        assert!(console.tout_affiche().contains("note.txt"));

        // XFR-012 : réimporter par-dessus rend 8 ; avec --replace, l'ancien est
        // déplacé et son emplacement annoncé.
        let mut console = FakeConsole::non_interactive();
        assert_eq!(
            executer(&import, &mut console)
                .expect_err("refus attendu")
                .code(),
            8
        );

        let remplacement = analyser(&[
            "import",
            conteneur.to_str().expect("UTF-8"),
            "--to",
            restaure.to_str().expect("UTF-8"),
            "--replace",
        ]);
        let mut console = FakeConsole::non_interactive();
        executer(&remplacement, &mut console).expect("remplaçable");
        assert!(
            console
                .avertissements
                .iter()
                .any(|texte| texte.contains(".vault-remplace-")),
            "{:?}",
            console.avertissements
        );
    }
}
