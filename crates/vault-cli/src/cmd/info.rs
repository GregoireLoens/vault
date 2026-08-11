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

use std::path::{Path, PathBuf};

use vault_core::{ContainerHeader, Vault};

use crate::cmd::{Contexte, taille_lisible};
use crate::error::{CliError, CliResult};

/// Options de `vault info`.
#[derive(Default)]
pub struct Options {
    /// Conteneur à interroger. Sans lui, c'est le vault de `--vault`.
    pub conteneur: Option<PathBuf>,
}

/// Affiche les paramètres publics du vault.
///
/// # Errors
///
/// Celles de [`Vault::open`] : [`vault_core::Error::NotFound`] s'il n'y a pas
/// de vault à cet emplacement, [`vault_core::Error::Corrupted`] si l'en-tête
/// est illisible, [`vault_core::Error::UnsupportedFormatVersion`] si le format
/// dépasse ce que cette version sait lire.
pub fn executer(contexte: &mut Contexte, options: &Options) -> CliResult<()> {
    if let Some(conteneur) = &options.conteneur {
        return inspecter_conteneur(contexte, conteneur);
    }

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

/// Affiche l'en-tête d'un conteneur d'export — XFR-040, XFR-041.
///
/// **Ce qu'elle n'affiche pas est aussi précis que ce qu'elle affiche.** Ni ce
/// que le conteneur contient, ni combien d'entrées le vault porte : ces
/// informations vivent dans l'index chiffré, et l'en-tête d'un conteneur n'en
/// dit pas plus que celui d'un vault — c'est la promesse de FR-010.
///
/// Le nombre de **membres** et le **volume**, eux, y figurent : ce sont les
/// mêmes grandeurs qu'un `ls` révélerait du répertoire `objects/`, et le
/// cadrage public les porte de toute façon.
fn inspecter_conteneur(contexte: &mut Contexte, chemin: &Path) -> CliResult<()> {
    let mut fichier = match std::fs::File::open(chemin) {
        Ok(fichier) => fichier,
        Err(erreur) if erreur.kind() == std::io::ErrorKind::NotFound => {
            return Err(CliError::Core(vault_core::Error::NotFound));
        }
        Err(erreur) => return Err(CliError::Io(erreur)),
    };

    // La constante de tête est lue **avant toute autre chose** : un fichier qui
    // n'est pas un conteneur est refusé sans qu'une seule de ses valeurs ait
    // été interprétée. Le cas le plus probable — un en-tête de vault, dont la
    // constante est `VAULTFMT` — mérite d'être nommé, plutôt que renvoyé à un
    // « fichier corrompu » qui enverrait chercher au mauvais endroit.
    let entete = ContainerHeader::read(&mut fichier).map_err(|erreur| match erreur {
        vault_core::Error::Corrupted => CliError::Usage(
            "Ce fichier n'est pas un conteneur d'export. Pour un vault sur disque, donnez son \
répertoire à --vault plutôt que ce chemin."
                .to_owned(),
        ),
        autre => CliError::Core(autre),
    })?;

    if contexte.json {
        contexte.console.output(&format!(
            "{{\"container_version\":{},\"vault_format_version\":{},\"member_count\":{},\
\"payload_bytes\":{}}}",
            entete.container_version,
            entete.vault_format_version,
            entete.member_count,
            entete.payload_bytes
        ));
    } else {
        for ligne in [
            format!("Version du conteneur : {}", entete.container_version),
            format!("Version du vault     : {}", entete.vault_format_version),
            format!("Membres              : {}", entete.member_count),
            format!(
                "Volume               : {}",
                taille_lisible(entete.payload_bytes)
            ),
        ] {
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

        executer(&mut contexte(&mut console, &coffre), &Options::default()).expect("consultable");

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
        executer(&mut contexte(&mut console, &coffre), &Options::default()).expect("consultable");
        let vide = console.tout_affiche();

        peupler(atelier.path(), &coffre);

        let mut console = FakeConsole::non_interactive();
        executer(&mut contexte(&mut console, &coffre), &Options::default()).expect("consultable");
        assert_eq!(console.tout_affiche(), vide);

        // Et en JSON, où une machine pourrait lire ce qu'un humain ne verrait
        // pas.
        let mut console = FakeConsole::non_interactive();
        let mut ctx = contexte(&mut console, &coffre);
        ctx.json = true;
        executer(&mut ctx, &Options::default()).expect("consultable");
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

    /// Produit un conteneur d'export depuis un vault, et rend son chemin.
    fn conteneur_de(atelier: &Path, coffre: &Path) -> PathBuf {
        let chemin = atelier.join("sauvegarde.vaultx");
        let mut octets = Vec::new();
        vault_core::Vault::export(coffre, vault_core::ExportEnvelope::Source, &mut octets)
            .expect("exportable");
        std::fs::write(&chemin, &octets).expect("écrivable");
        chemin
    }

    /// XFR-040 : l'en-tête d'un conteneur s'affiche **sans passphrase**.
    #[test]
    fn un_conteneur_livre_son_en_tete_sans_passphrase() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());
        peupler(atelier.path(), &coffre);
        let conteneur = conteneur_de(atelier.path(), &coffre);

        let mut console = FakeConsole::non_interactive();
        executer(
            &mut contexte(&mut console, &coffre),
            &Options {
                conteneur: Some(conteneur.clone()),
            },
        )
        .expect("consultable");

        let affiche = console.tout_affiche();
        assert!(affiche.contains("Version du conteneur : 1"), "{affiche}");
        assert!(affiche.contains("Version du vault     : 1"), "{affiche}");
        assert!(affiche.contains("Membres              : 3"), "{affiche}");
        assert!(affiche.contains("Volume"), "{affiche}");
        assert!(console.invites.is_empty(), "aucune saisie : {affiche}");

        // XFR-041 : rien de ce que le conteneur **contient** n'est dit.
        let mut console = FakeConsole::non_interactive();
        let mut ctx = contexte(&mut console, &coffre);
        ctx.json = true;
        executer(
            &mut ctx,
            &Options {
                conteneur: Some(conteneur),
            },
        )
        .expect("consultable");
        let json = console.tout_affiche();
        assert!(json.contains("\"container_version\":1"), "{json}");
        assert!(json.contains("\"member_count\":3"), "{json}");
        assert!(!json.contains("note.txt"), "{json}");
        assert!(!json.contains("entries"), "{json}");
    }

    /// T064 : la distinction se fait sur la **constante de tête**, et le refus
    /// nomme le cas le plus probable — un vault désigné par erreur.
    #[test]
    fn un_fichier_qui_n_est_pas_un_conteneur_est_refuse_en_disant_quoi_faire() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());

        // L'en-tête d'un vault porte `VAULTFMT`, pas `VAULTXFR`.
        let mut console = FakeConsole::non_interactive();
        let erreur = executer(
            &mut contexte(&mut console, &coffre),
            &Options {
                conteneur: Some(coffre.join("header")),
            },
        )
        .expect_err("refus attendu");
        let message = erreur.message();
        assert_eq!(erreur.code(), 2);
        assert!(message.contains("--vault"), "{message}");

        // Et un fichier quelconque, de même.
        let etranger = atelier.path().join("quelconque.bin");
        std::fs::write(&etranger, b"ceci n'est pas un conteneur").expect("écrivable");
        let mut console = FakeConsole::non_interactive();
        assert_eq!(
            executer(
                &mut contexte(&mut console, &coffre),
                &Options {
                    conteneur: Some(etranger)
                },
            )
            .expect_err("refus attendu")
            .code(),
            2
        );
    }

    /// Une défaillance de lecture qui n'est **pas** une absence remonte telle
    /// quelle, et non déguisée en « introuvable » : dire qu'il n'y a rien là
    /// où il y a un fichier illisible enverrait chercher au mauvais endroit.
    #[cfg(unix)]
    #[test]
    fn un_conteneur_illisible_par_permission_remonte_l_erreur() {
        use std::os::unix::fs::PermissionsExt;

        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());
        let conteneur = conteneur_de(atelier.path(), &coffre);

        let mut permissions = std::fs::metadata(&conteneur)
            .expect("lisible")
            .permissions();
        permissions.set_mode(0o000);
        std::fs::set_permissions(&conteneur, permissions).expect("modifiable");

        let mut console = FakeConsole::non_interactive();
        let resultat = executer(
            &mut contexte(&mut console, &coffre),
            &Options {
                conteneur: Some(conteneur.clone()),
            },
        );

        let mut permissions = std::fs::metadata(&conteneur)
            .expect("lisible")
            .permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&conteneur, permissions).expect("modifiable");

        assert!(matches!(resultat, Err(CliError::Io(_))), "{resultat:?}");
    }

    /// Un conteneur introuvable est un « introuvable » : code 5.
    #[test]
    fn un_conteneur_introuvable_est_signale() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());

        let mut console = FakeConsole::non_interactive();
        assert_eq!(
            executer(
                &mut contexte(&mut console, &coffre),
                &Options {
                    conteneur: Some(atelier.path().join("nulle-part.vaultx"))
                },
            )
            .expect_err("refus attendu")
            .code(),
            5
        );
    }

    /// Une version de conteneur inconnue rend 7, en nommant la version.
    #[test]
    fn un_conteneur_de_version_inconnue_rend_sept() {
        /// La clé du champ dans l'en-tête CBOR, précédée de son en-tête de
        /// texte `0x71` (17 octets) : la repérer ainsi évite de tomber sur une
        /// suite d'octets qui figurerait ailleurs.
        const CLE: &[u8] = b"\x71container_version";

        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_neuf(atelier.path());
        let conteneur = conteneur_de(atelier.path(), &coffre);

        let mut octets = std::fs::read(&conteneur).expect("lisible");
        let position = octets
            .windows(CLE.len())
            .position(|fenetre| fenetre == CLE)
            .expect("le champ figure dans l'en-tête")
            + CLE.len();
        octets[position] = 0x02;
        std::fs::write(&conteneur, &octets).expect("écrivable");

        let mut console = FakeConsole::non_interactive();
        assert_eq!(
            executer(
                &mut contexte(&mut console, &coffre),
                &Options {
                    conteneur: Some(conteneur)
                },
            )
            .expect_err("refus attendu")
            .code(),
            7
        );
    }

    #[test]
    fn un_emplacement_sans_vault_est_signale() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let mut console = FakeConsole::non_interactive();

        assert!(matches!(
            executer(
                &mut contexte(&mut console, &atelier.path().join("nulle-part")),
                &Options::default()
            ),
            Err(CliError::Core(vault_core::Error::NotFound))
        ));
    }
}
