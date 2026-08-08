//! `vault info` — T056.
//!
//! CLI-018. Cette commande est la seule à ne **jamais** demander la
//! passphrase : tout ce qu'elle affiche vient de l'en-tête, qui est en clair
//! par conception (VR-H2). C'est ce qui la rend utile — savoir si un vault est
//! lisible par cette version du logiciel, et sous quels paramètres de coût, ne
//! devrait pas exiger d'ouvrir le coffre.
//!
//! **Ce qu'elle n'affiche pas est aussi précis que ce qu'elle affiche.** Ni
//! nombre d'entrées, ni taille du contenu, ni date : ces informations vivent
//! dans l'index chiffré, et les publier reviendrait à déchiffrer pour un
//! renseignement que VR-H3 s'attache justement à tenir hors de l'en-tête. La
//! conséquence se vérifie : la sortie d'un vault vide et celle du même vault
//! une fois peuplé sont identiques.

use vault_core::Vault;

use crate::cmd::Contexte;
use crate::error::CliResult;

/// Affiche les paramètres publics du vault.
///
/// # Errors
///
/// Celles de [`Vault::open`] : [`vault_core::Error::NotFound`] s'il n'y a pas
/// de vault à cet emplacement, [`vault_core::Error::Corrupted`] si l'en-tête
/// est illisible, [`vault_core::Error::UnsupportedFormatVersion`] si le format
/// dépasse ce que cette version sait lire.
pub fn executer(contexte: &mut Contexte) -> CliResult<()> {
    let vault = Vault::open(&contexte.vault_dir)?;

    if contexte.json {
        contexte.console.output(&en_json(&vault));
    } else {
        for ligne in en_texte(&vault) {
            contexte.console.output(&ligne);
        }
    }
    Ok(())
}

/// Rendu textuel.
fn en_texte(vault: &Vault) -> Vec<String> {
    let params = vault.kdf_params();
    vec![
        format!("Version du format   : {}", vault.format_version()),
        format!("Dérivation de clé   : {}", vault.kdf_algorithm()),
        format!(
            "  mémoire           : {}",
            memoire_lisible(params.memory_kib())
        ),
        format!("  passes            : {}", params.iterations()),
        format!("  parallélisme      : {}", params.parallelism()),
        format!("Chiffrement         : {}", vault.aead_algorithm()),
    ]
}

/// Coût mémoire d'Argon2id, en kibioctets, avec son équivalent lisible.
///
/// La valeur brute est conservée : c'est elle qui figure dans l'en-tête, et
/// c'est elle qu'il faut pour reproduire la dérivation à la main. L'équivalent
/// n'est ajouté que lorsqu'il est exact — un arrondi dans une sortie de
/// diagnostic vaudrait moins que rien.
fn memoire_lisible(kib: u32) -> String {
    if kib >= 1024 && kib.is_multiple_of(1024) {
        format!("{kib} Kio ({} Mio)", kib / 1024)
    } else {
        format!("{kib} Kio")
    }
}

/// Rendu JSON.
fn en_json(vault: &Vault) -> String {
    let params = vault.kdf_params();
    format!(
        "{{\"format_version\":{},\"kdf_algorithm\":\"{}\",\"kdf_memory_kib\":{},\
\"kdf_iterations\":{},\"kdf_parallelism\":{},\"aead_algorithm\":\"{}\"}}",
        vault.format_version(),
        vault.kdf_algorithm(),
        params.memory_kib(),
        params.iterations(),
        params.parallelism(),
        vault.aead_algorithm()
    )
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::console::fake::FakeConsole;
    use crate::error::CliError;

    const PASSPHRASE: &str = "une passphrase bien assez longue";

    fn coffre_neuf(atelier: &Path) -> PathBuf {
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

    /// Ajoute un fichier au vault et le referme.
    fn peupler(atelier: &Path, coffre: &Path) {
        let source = atelier.join("note.txt");
        std::fs::write(&source, vec![0x7e; 50_000]).expect("écrivable");

        let mut vault = vault_core::Vault::open(coffre)
            .expect("ouvrable")
            .unlock(vault_core::SecretString::from(PASSPHRASE.to_owned()))
            .expect("déverrouillable");
        vault
            .add_file(
                &source,
                &vault_core::VaultPath::from_components([b"note.txt".to_vec()]).expect("valide"),
                vault_core::AddMode::Copy,
                vault_core::OnConflict::Fail,
            )
            .expect("ajoutable");
        vault.lock();
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

    /// CLI-018 : la commande n'ouvre pas le vault, donc ne demande rien.
    #[test]
    fn les_parametres_publics_s_affichent_sans_passphrase() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());
        let mut console = FakeConsole::non_interactive();

        executer(&mut contexte(&mut console, &coffre)).expect("consultable");

        let affiche = console.tout_affiche();
        assert!(affiche.contains("argon2id"));
        assert!(affiche.contains("xchacha20poly1305"));
        assert!(affiche.contains("64 Kio"));
        assert!(
            console.invites.is_empty(),
            "aucune saisie ne doit être demandée : {affiche}"
        );
    }

    /// CLI-018, dans sa forme vérifiable : le contenu ne transparaît pas. Le
    /// même vault, vide puis peuplé de 50 Ko, rend **exactement** la même
    /// sortie.
    #[test]
    fn la_sortie_ne_depend_pas_du_contenu() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());

        let mut console = FakeConsole::non_interactive();
        executer(&mut contexte(&mut console, &coffre)).expect("consultable");
        let vide = console.tout_affiche();

        peupler(atelier.path(), &coffre);

        let mut console = FakeConsole::non_interactive();
        executer(&mut contexte(&mut console, &coffre)).expect("consultable");
        assert_eq!(console.tout_affiche(), vide);

        // Et en JSON, où une machine pourrait lire ce qu'un humain ne verrait
        // pas.
        let mut console = FakeConsole::non_interactive();
        let mut ctx = contexte(&mut console, &coffre);
        ctx.json = true;
        executer(&mut ctx).expect("consultable");
        let json = console.tout_affiche();
        assert!(json.contains("\"format_version\":1"));
        assert!(json.contains("\"kdf_memory_kib\":64"));
        assert!(!json.contains("entries"));
        assert!(!json.contains("size"));
    }

    /// L'équivalent en mébioctets n'apparaît que lorsqu'il est exact.
    #[test]
    fn le_cout_memoire_reste_exact() {
        assert_eq!(memoire_lisible(131_072), "131072 Kio (128 Mio)");
        assert_eq!(memoire_lisible(1024), "1024 Kio (1 Mio)");
        assert_eq!(memoire_lisible(64), "64 Kio");
        assert_eq!(memoire_lisible(1500), "1500 Kio");
    }

    #[test]
    fn un_emplacement_sans_vault_est_signale() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let mut console = FakeConsole::non_interactive();

        assert!(matches!(
            executer(&mut contexte(
                &mut console,
                &atelier.path().join("nulle-part")
            )),
            Err(CliError::Core(vault_core::Error::NotFound))
        ));
    }
}
