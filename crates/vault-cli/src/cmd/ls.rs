//! `vault ls` — T047.
//!
//! FR-024, FR-025, CLI-009, CLI-010.
//!
//! **C-014 : la consultation n'écrit rien sur le disque**, pas même un
//! temporaire. Elle se contente de parcourir l'index déjà déchiffré en mémoire.
//!
//! **CLI-010** : `--long` ajoute l'identifiant de blob et la taille après
//! remplissage. Ces deux valeurs sont déjà visibles pour quiconque inspecte le
//! répertoire du vault — les afficher ne révèle rien de plus, et rend le
//! diagnostic possible sans outil tiers.

use std::fmt::Write as _;
use std::path::PathBuf;

use vault_core::{Entry, EntryKind, UnlockedVault, VaultPath};

use crate::cmd::{Contexte, chemin_de_vault, json_echappe, taille_lisible};
use crate::error::CliResult;

/// Options de `vault ls`.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Chemin à lister. La racine par défaut.
    pub chemin: Option<PathBuf>,
    /// `--long` : ajoute l'identifiant de blob et la taille remplie.
    pub long: bool,
}

/// Liste le contenu du vault.
///
/// # Errors
///
/// Celles du déverrouillage, et [`vault_core::Error::InvalidPath`] si le chemin
/// demandé viole VR-I4.
pub fn executer(contexte: &mut Contexte, options: &Options) -> CliResult<()> {
    let sous = match &options.chemin {
        Some(chemin) => Some(chemin_de_vault(chemin)?),
        None => None,
    };

    let session = contexte.deverrouiller()?;
    let entrees = session.list(sous.as_ref());

    if contexte.json {
        contexte
            .console
            .output(&en_json(&session, &entrees, options.long));
    } else {
        for ligne in en_texte(&session, &entrees, options.long) {
            contexte.console.output(&ligne);
        }
        contexte.console.info(&resume(&entrees));
    }
    Ok(())
}

/// Rendu textuel, indenté selon la profondeur.
fn en_texte(session: &UnlockedVault, entrees: &[Entry], long: bool) -> Vec<String> {
    entrees
        .iter()
        .map(|entree| {
            let indentation = "  ".repeat(entree.path.depth().saturating_sub(1));
            let nom = String::from_utf8_lossy(entree.path.file_name().unwrap_or(b"")).into_owned();
            let mut ligne = match entree.kind {
                EntryKind::Directory => format!("{indentation}{nom}/"),
                EntryKind::File => format!(
                    "{indentation}{nom}  {}",
                    taille_lisible(entree.size.unwrap_or(0))
                ),
            };
            if long {
                let _ = write!(ligne, "  {}", diagnostic(session, &entree.path));
            }
            ligne
        })
        .collect()
}

/// Rendu JSON (CLI-009).
///
/// Chaque entrée porte son chemin sous deux formes : une chaîne lisible, qui
/// peut être approximative pour un nom non-UTF-8, et la suite d'octets exacte.
/// Sans la seconde, une sortie destinée à une machine perdrait la fidélité que
/// VR-I1 s'attache à préserver.
fn en_json(session: &UnlockedVault, entrees: &[Entry], long: bool) -> String {
    let objets: Vec<String> = entrees
        .iter()
        .map(|entree| {
            let chemin = json_echappe(&entree.path.to_display_string());
            let octets: Vec<String> = entree
                .path
                .components()
                .flat_map(|composant| composant.iter().map(u8::to_string))
                .collect();
            let genre = match entree.kind {
                EntryKind::File => "file",
                EntryKind::Directory => "directory",
            };
            let taille = entree
                .size
                .map_or_else(|| "null".to_owned(), |taille| taille.to_string());
            let mut objet = format!(
                "{{\"path\":\"{chemin}\",\"path_bytes\":[{}],\"kind\":\"{genre}\",\"size\":{taille}}}",
                octets.join(",")
            );
            if long {
                let diagnostic = json_echappe(&diagnostic(session, &entree.path));
                objet.truncate(objet.len() - 1);
                let _ = write!(objet, ",\"blob\":\"{diagnostic}\"}}");
            }
            objet
        })
        .collect();
    format!("[{}]", objets.join(","))
}

/// Identifiant de blob et taille remplie, pour `--long`.
fn diagnostic(session: &UnlockedVault, chemin: &VaultPath) -> String {
    match session.blob_of(chemin) {
        Ok(Some((blob_id, rempli))) => format!("{} ({rempli} o)", blob_id.to_hex()),
        // Un dossier n'occupe aucun blob ; une entrée disparue entre le
        // listage et le diagnostic n'existe pas, la session étant exclusive.
        _ => "-".to_owned(),
    }
}

/// Ligne de résumé.
fn resume(entrees: &[Entry]) -> String {
    let dossiers = entrees
        .iter()
        .filter(|entree| entree.kind == EntryKind::Directory)
        .count();
    let fichiers = entrees.len() - dossiers;
    let volume: u64 = entrees.iter().filter_map(|entree| entree.size).sum();
    format!(
        "{dossiers} dossier(s), {fichiers} fichier(s), {}",
        taille_lisible(volume)
    )
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::console::fake::FakeConsole;
    use crate::error::CliError;

    const PASSPHRASE: &str = "une passphrase bien assez longue";

    /// Prépare un vault peuplé et rend son emplacement.
    fn coffre_peuple(atelier: &Path) -> PathBuf {
        let coffre = atelier.join("coffre");
        let source = atelier.join("source");
        std::fs::create_dir_all(source.join("photos")).expect("créable");
        std::fs::write(source.join("photos/plage.jpg"), vec![0u8; 2400]).expect("écrivable");
        std::fs::write(source.join("note.txt"), b"une note").expect("écrivable");

        let mut vault = vault_core::Vault::create(
            &coffre,
            vault_core::SecretString::from(PASSPHRASE.to_owned()),
            vault_core::KdfParams::new(64, 1, 1).expect("valides"),
        )
        .expect("créable");
        vault
            .add_dir(
                &source,
                &VaultPath::root(),
                vault_core::AddMode::Copy,
                vault_core::OnConflict::Fail,
                &mut |_| {},
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

    #[test]
    fn le_listage_textuel_montre_l_arborescence() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());
        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);

        executer(&mut contexte(&mut console, &coffre), &Options::default()).expect("listable");

        let affiche = console.tout_affiche();
        assert!(affiche.contains("note.txt"));
        assert!(affiche.contains("photos/"));
        assert!(affiche.contains("  plage.jpg"), "indentation : {affiche}");
        assert!(affiche.contains("1 dossier(s), 2 fichier(s)"));
    }

    /// CLI-009 : la sortie JSON porte les octets exacts du nom, pas seulement
    /// sa forme lisible.
    #[test]
    fn le_listage_json_conserve_les_octets_du_nom() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());
        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        let mut ctx = contexte(&mut console, &coffre);
        ctx.json = true;

        executer(&mut ctx, &Options::default()).expect("listable");

        let affiche = console.tout_affiche();
        assert!(affiche.starts_with('['));
        assert!(affiche.contains("\"kind\":\"directory\""));
        assert!(affiche.contains("\"kind\":\"file\""));
        assert!(
            affiche.contains("\"size\":null"),
            "un dossier n'a pas de taille"
        );
        assert!(affiche.contains("\"path_bytes\":["));
    }

    /// CLI-010 : `--long` ajoute l'identifiant de blob, et un dossier n'en a
    /// pas.
    #[test]
    fn le_mode_long_ajoute_le_diagnostic() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());

        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        executer(
            &mut contexte(&mut console, &coffre),
            &Options {
                chemin: None,
                long: true,
            },
        )
        .expect("listable");
        let texte = console.tout_affiche();
        assert!(texte.contains(" o)"), "taille remplie attendue : {texte}");
        assert!(texte.contains(" -"), "un dossier n'a pas de blob");

        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        let mut ctx = contexte(&mut console, &coffre);
        ctx.json = true;
        executer(
            &mut ctx,
            &Options {
                chemin: None,
                long: true,
            },
        )
        .expect("listable");
        assert!(console.tout_affiche().contains("\"blob\":"));
    }

    #[test]
    fn un_sous_chemin_restreint_le_listage() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());
        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);

        executer(
            &mut contexte(&mut console, &coffre),
            &Options {
                chemin: Some(PathBuf::from("photos")),
                long: false,
            },
        )
        .expect("listable");

        let affiche = console.tout_affiche();
        assert!(affiche.contains("plage.jpg"));
        assert!(!affiche.contains("note.txt"));
    }

    #[test]
    fn un_chemin_hostile_est_refuse_avant_la_passphrase() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());
        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);

        assert!(matches!(
            executer(
                &mut contexte(&mut console, &coffre),
                &Options {
                    chemin: Some(PathBuf::from("../evasion")),
                    long: false,
                }
            ),
            Err(CliError::Core(vault_core::Error::InvalidPath))
        ));
        assert!(console.invites.is_empty(), "rien n'a été demandé");
    }

    #[test]
    fn une_passphrase_erronee_remonte_en_authentification() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());
        let mut console = FakeConsole::new(&["une passphrase parfaitement fausse"], &[]);

        assert!(matches!(
            executer(&mut contexte(&mut console, &coffre), &Options::default()),
            Err(CliError::Core(vault_core::Error::Authentication))
        ));
    }

    #[test]
    fn un_vault_vide_se_liste_aussi() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("vide");
        vault_core::Vault::create(
            &coffre,
            vault_core::SecretString::from(PASSPHRASE.to_owned()),
            vault_core::KdfParams::new(64, 1, 1).expect("valides"),
        )
        .expect("créable")
        .lock();

        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        executer(&mut contexte(&mut console, &coffre), &Options::default()).expect("listable");
        assert!(
            console
                .tout_affiche()
                .contains("0 dossier(s), 0 fichier(s)")
        );

        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        let mut ctx = contexte(&mut console, &coffre);
        ctx.json = true;
        executer(&mut ctx, &Options::default()).expect("listable");
        assert!(console.tout_affiche().contains("[]"));
    }

    #[test]
    fn les_options_ont_un_debug() {
        assert!(format!("{:?}", Options::default()).contains("Options"));
    }
}
