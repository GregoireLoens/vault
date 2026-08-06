//! `vault add` — T046.
//!
//! FR-013 à FR-023, CLI-005 à CLI-008.
//!
//! Deux avertissements incombent à la ligne de commande, parce que la
//! bibliothèque ne parle pas à l'utilisateur :
//!
//! - **CLI-005** : en mode déplacement, dire que l'original a été supprimé mais
//!   que des traces peuvent subsister. `vault-core` répond honnêtement qu'il ne
//!   garantit rien (FR-020) ; ne pas le répéter à l'utilisateur reviendrait à
//!   lui laisser croire à un effacement sûr.
//! - **CLI-006** : en mode copie, rappeler que l'original reste en clair. C'est
//!   le cas le plus facile à oublier, et il annule le bénéfice de l'opération.

use std::path::{Path, PathBuf};

use vault_core::{AddMode, EntryKind, OnConflict, ShredCapability, shred_capability};

use crate::cmd::{Contexte, chemin_de_vault, taille_lisible};
use crate::error::{CliError, CliResult};

/// Seuil au-delà duquel la progression est affichée (CLI-007).
///
/// C'est `main.rs` qui l'installe dans les options : le porter là plutôt que de
/// le lire ici permet de vérifier les deux comportements — avec et sans
/// progression — sans fabriquer un fichier de cent mégaoctets par test.
pub const SEUIL_PROGRESSION: u64 = 100 * 1000 * 1000;

/// Options de `vault add`.
#[derive(Clone, Debug)]
pub struct Options {
    /// Sources à ajouter.
    pub sources: Vec<PathBuf>,
    /// `--as` : destination dans le vault.
    pub destination: Option<PathBuf>,
    /// Mode d'ajout. `Move` est le défaut (FR-018).
    pub mode: AddMode,
    /// Résolution des collisions.
    pub on_conflict: OnConflict,
    /// `--quiet` : supprime la progression, pas les avertissements.
    pub quiet: bool,
    /// Volume au-delà duquel la progression s'affiche (CLI-007).
    pub seuil_progression: u64,
}

/// Ajoute des fichiers ou des dossiers au vault.
///
/// # Errors
///
/// - [`CliError::Usage`] si aucune source n'est donnée, ou si `--as` est
///   employé avec plusieurs sources ;
/// - celles de [`vault_core::UnlockedVault::add_file`] et `add_dir`.
pub fn executer(contexte: &mut Contexte, options: &Options) -> CliResult<()> {
    // Le premier chemin sert aussi de support de référence pour la mise en
    // garde d'effacement : le lier ici évite un cas « aucune source » qui ne
    // peut pas se produire une fois cette garde franchie.
    let Some(support) = options.sources.first() else {
        return Err(CliError::Usage("Aucune source à ajouter.".to_owned()));
    };
    crate::cmd::refuser_si(
        options.destination.is_some() && options.sources.len() > 1,
        "--as ne peut viser qu'une seule source.",
    )?;

    let volume = volume_total(&options.sources);
    let bavard = !options.quiet && volume > options.seuil_progression;

    let mut session = contexte.deverrouiller()?;
    let mut total_fichiers = 0usize;

    for source in &options.sources {
        let destination = destination_de(source, options.destination.as_deref())?;
        let metadata = std::fs::symlink_metadata(source)?;

        if metadata.is_dir() {
            let ajoutees = session.add_dir(
                source,
                &destination,
                options.mode,
                options.on_conflict,
                &mut |chemin| {
                    if bavard {
                        // La progression sort sur la console, jamais dans un
                        // fichier : CLI-021 interdit d'écrire un nom d'entrée
                        // dans une trace.
                        eprintln!("  {}", chemin.display());
                    }
                },
            )?;
            total_fichiers += ajoutees
                .iter()
                .filter(|entree| entree.kind == EntryKind::File)
                .count();
        } else {
            if bavard {
                eprintln!("  {}", source.display());
            }
            session.add_file(source, &destination, options.mode, options.on_conflict)?;
            total_fichiers += 1;
        }
    }

    avertir_du_mode(contexte, options.mode, support);

    if contexte.json {
        contexte.console.output(&format!(
            "{{\"added\":{total_fichiers},\"bytes\":{volume}}}"
        ));
    } else {
        contexte.console.info(&format!(
            "{total_fichiers} fichier(s) ajouté(s), {}.",
            taille_lisible(volume)
        ));
    }
    Ok(())
}

/// Présente les mises en garde propres au mode (CLI-005, CLI-006).
fn avertir_du_mode(contexte: &mut Contexte, mode: AddMode, support: &Path) {
    let message = match mode {
        AddMode::Move => message_effacement(shred_capability(support)),
        AddMode::Copy => MESSAGE_COPIE,
    };
    contexte.console.warn(message);
}

/// Message d'effacement, selon ce que le support permet de promettre.
///
/// La décision est isolée dans une fonction pure pour être vérifiable dans les
/// deux cas : `vault-core` ne renvoie jamais [`ShredCapability::Guaranteed`]
/// dans cette version, et une condition écrite en ligne aurait laissé la
/// branche favorable sans test le jour où elle deviendra atteignable.
fn message_effacement(capacite: ShredCapability) -> &'static str {
    match capacite {
        ShredCapability::Guaranteed => MESSAGE_EFFACEMENT_GARANTI,
        _ => MESSAGE_EFFACEMENT_INCERTAIN,
    }
}

/// CLI-006 : l'original reste en clair, et c'est le piège le plus facile à
/// ne pas voir.
const MESSAGE_COPIE: &str = "  ⚠  L'original demeure en clair sur le disque et n'est protégé par rien.\n     Employez --move pour qu'il soit retiré après vérification.";

/// CLI-005 : l'effacement a eu lieu, la garantie non.
const MESSAGE_EFFACEMENT_INCERTAIN: &str = "  ⚠  L'original a été supprimé, mais des traces peuvent subsister sur ce\n     support : ni un disque à mémoire flash, ni un système de fichiers à copie\n     sur écriture ne garantissent qu'une réécriture atteigne l'emplacement\n     d'origine.";

/// Réservé au jour où une plateforme permettra d'établir la garantie.
const MESSAGE_EFFACEMENT_GARANTI: &str =
    "  ✓  L'original a été supprimé et son contenu écrasé de façon irrécupérable.";

/// Destination d'une source dans le vault.
fn destination_de(source: &Path, demandee: Option<&Path>) -> CliResult<vault_core::VaultPath> {
    if let Some(chemin) = demandee {
        return chemin_de_vault(chemin);
    }
    let nom = source
        .file_name()
        .ok_or_else(|| CliError::Usage("Source sans nom exploitable.".to_owned()))?;
    chemin_de_vault(Path::new(nom))
}

/// Volume total des sources, dossiers compris.
fn volume_total(sources: &[PathBuf]) -> u64 {
    sources
        .iter()
        .map(|source| {
            walkdir::WalkDir::new(source)
                .into_iter()
                .filter_map(std::result::Result::ok)
                .filter_map(|entree| entree.metadata().ok())
                .filter(std::fs::Metadata::is_file)
                .map(|metadata| metadata.len())
                .sum::<u64>()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::console::fake::FakeConsole;

    const PASSPHRASE: &str = "une passphrase bien assez longue";

    fn options(sources: Vec<PathBuf>, mode: AddMode) -> Options {
        Options {
            sources,
            destination: None,
            mode,
            on_conflict: OnConflict::Fail,
            quiet: false,
            seuil_progression: SEUIL_PROGRESSION,
        }
    }

    /// Prépare un vault et rend son emplacement.
    fn coffre(atelier: &Path) -> PathBuf {
        let coffre = atelier.join("coffre");
        vault_core::Vault::create(
            &coffre,
            vault_core::SecretString::from(PASSPHRASE.to_owned()),
            vault_core::KdfParams::new(64, 1, 1).expect("valides"),
        )
        .expect("créable")
        .lock();
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

    #[test]
    fn un_fichier_s_ajoute_et_l_avertissement_de_copie_apparait() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre(atelier.path());
        let source = atelier.path().join("note.txt");
        std::fs::write(&source, b"contenu").expect("écrivable");

        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        executer(
            &mut contexte(&mut console, &coffre),
            &options(vec![source.clone()], AddMode::Copy),
        )
        .expect("ajoutable");

        assert!(source.exists(), "le mode copie conserve l'original");
        let affiche = console.tout_affiche();
        assert!(affiche.contains("demeure en clair"), "CLI-006 : {affiche}");
        assert!(affiche.contains("1 fichier(s)"));
    }

    /// CLI-005 : en mode déplacement, l'utilisateur est prévenu que
    /// l'effacement n'est pas garanti.
    #[test]
    fn le_mode_deplacement_avertit_des_traces_residuelles() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre(atelier.path());
        let source = atelier.path().join("note.txt");
        std::fs::write(&source, b"contenu").expect("écrivable");

        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        executer(
            &mut contexte(&mut console, &coffre),
            &options(vec![source.clone()], AddMode::Move),
        )
        .expect("ajoutable");

        assert!(!source.exists());
        assert!(console.tout_affiche().contains("traces peuvent subsister"));
    }

    #[test]
    fn un_dossier_s_ajoute_recursivement() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre(atelier.path());
        let source = atelier.path().join("arbre");
        std::fs::create_dir_all(source.join("a")).expect("créable");
        std::fs::write(source.join("a/feuille.txt"), b"feuille").expect("écrivable");
        std::fs::write(source.join("racine.txt"), b"racine").expect("écrivable");

        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        let mut ctx = contexte(&mut console, &coffre);
        ctx.json = true;
        executer(&mut ctx, &options(vec![source], AddMode::Copy)).expect("ajoutable");

        assert!(console.tout_affiche().contains("\"added\":2"));
    }

    #[test]
    fn les_usages_invalides_sont_refuses() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre(atelier.path());
        let mut console = FakeConsole::new(&[PASSPHRASE, PASSPHRASE], &[]);

        assert!(matches!(
            executer(
                &mut contexte(&mut console, &coffre),
                &options(Vec::new(), AddMode::Copy)
            ),
            Err(CliError::Usage(_))
        ));

        let mut avec_as = options(
            vec![atelier.path().join("a"), atelier.path().join("b")],
            AddMode::Copy,
        );
        avec_as.destination = Some(PathBuf::from("cible"));
        assert!(matches!(
            executer(&mut contexte(&mut console, &coffre), &avec_as),
            Err(CliError::Usage(message)) if message.contains("--as")
        ));
    }

    #[test]
    fn la_destination_suit_le_nom_de_la_source_ou_l_option() {
        assert_eq!(
            destination_de(Path::new("/tmp/note.txt"), None)
                .expect("valide")
                .to_display_string(),
            "note.txt"
        );
        assert_eq!(
            destination_de(
                Path::new("/tmp/note.txt"),
                Some(Path::new("docs/autre.txt"))
            )
            .expect("valide")
            .to_display_string(),
            "docs/autre.txt"
        );
        assert!(matches!(
            destination_de(Path::new("/"), None),
            Err(CliError::Usage(_))
        ));
        assert!(matches!(
            destination_de(Path::new("x"), Some(Path::new("../evasion"))),
            Err(CliError::Core(vault_core::Error::InvalidPath))
        ));
    }

    #[test]
    fn le_volume_total_couvre_les_arborescences() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let arbre = atelier.path().join("arbre");
        std::fs::create_dir_all(arbre.join("a")).expect("créable");
        std::fs::write(arbre.join("a/x"), vec![0u8; 100]).expect("écrivable");
        std::fs::write(arbre.join("y"), vec![0u8; 50]).expect("écrivable");

        assert_eq!(volume_total(&[arbre]), 150);
        assert_eq!(volume_total(&[atelier.path().join("absent")]), 0);
        assert_eq!(volume_total(&[]), 0);
    }

    /// CLI-007 : la progression s'affiche au-delà du seuil, et `--quiet` la
    /// supprime sans faire taire les avertissements. Le seuil est abaissé pour
    /// le test plutôt que de fabriquer un fichier de cent mégaoctets.
    #[test]
    fn la_progression_suit_le_seuil_et_le_mode_silencieux() {
        assert_eq!(SEUIL_PROGRESSION, 100_000_000, "seuil du contrat");

        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre(atelier.path());
        let arbre = atelier.path().join("arbre");
        std::fs::create_dir(&arbre).expect("créable");
        std::fs::write(arbre.join("feuille.txt"), b"contenu").expect("écrivable");
        let isole = atelier.path().join("isole.txt");
        std::fs::write(&isole, b"contenu").expect("écrivable");

        let mut bavard = options(vec![arbre, isole.clone()], AddMode::Copy);
        bavard.seuil_progression = 0;
        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        executer(&mut contexte(&mut console, &coffre), &bavard).expect("ajoutable");

        let mut silencieux = options(vec![isole], AddMode::Copy);
        silencieux.quiet = true;
        silencieux.seuil_progression = 0;
        silencieux.on_conflict = vault_core::OnConflict::Replace;
        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        executer(&mut contexte(&mut console, &coffre), &silencieux).expect("ajoutable");

        assert!(
            console.tout_affiche().contains("demeure en clair"),
            "`--quiet` ne doit pas faire taire l'avertissement"
        );
    }

    /// L'échec d'un ajout récursif remonte tel quel.
    #[test]
    fn un_ajout_recursif_en_echec_remonte() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre(atelier.path());
        let arbre = atelier.path().join("arbre");
        std::fs::create_dir(&arbre).expect("créable");
        std::fs::write(arbre.join("feuille.txt"), b"contenu").expect("écrivable");

        let mut console = FakeConsole::new(&[PASSPHRASE, PASSPHRASE], &[]);
        executer(
            &mut contexte(&mut console, &coffre),
            &options(vec![arbre.clone()], AddMode::Copy),
        )
        .expect("ajoutable");

        assert!(matches!(
            executer(
                &mut contexte(&mut console, &coffre),
                &options(vec![arbre], AddMode::Copy)
            ),
            Err(CliError::Core(vault_core::Error::AlreadyExists))
        ));
    }

    #[test]
    fn une_collision_refusee_remonte() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre(atelier.path());
        let source = atelier.path().join("note.txt");
        std::fs::write(&source, b"contenu").expect("écrivable");

        let mut console = FakeConsole::new(&[PASSPHRASE, PASSPHRASE], &[]);
        executer(
            &mut contexte(&mut console, &coffre),
            &options(vec![source.clone()], AddMode::Copy),
        )
        .expect("ajoutable");

        assert!(matches!(
            executer(
                &mut contexte(&mut console, &coffre),
                &options(vec![source], AddMode::Copy)
            ),
            Err(CliError::Core(vault_core::Error::AlreadyExists))
        ));
    }

    #[test]
    fn une_source_absente_remonte() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre(atelier.path());
        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);

        assert!(matches!(
            executer(
                &mut contexte(&mut console, &coffre),
                &options(vec![atelier.path().join("absente")], AddMode::Copy)
            ),
            Err(CliError::Io(_))
        ));
    }

    /// CLI-005 : les deux messages d'effacement existent et diffèrent. Le
    /// message favorable n'est pas atteignable par `vault-core` aujourd'hui —
    /// il est vérifié ici pour que la branche ne soit pas écrite à l'aveugle.
    #[test]
    fn les_messages_d_effacement_couvrent_les_deux_cas() {
        assert_eq!(
            message_effacement(ShredCapability::BestEffort),
            MESSAGE_EFFACEMENT_INCERTAIN
        );
        assert_eq!(
            message_effacement(ShredCapability::Guaranteed),
            MESSAGE_EFFACEMENT_GARANTI
        );
        assert!(MESSAGE_EFFACEMENT_GARANTI.contains("irrécupérable"));
        assert!(MESSAGE_COPIE.contains("en clair"));
    }

    #[test]
    fn les_options_ont_un_debug() {
        assert!(format!("{:?}", options(Vec::new(), AddMode::Move)).contains("Options"));
    }
}
