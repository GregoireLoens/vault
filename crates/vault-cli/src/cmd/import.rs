//! `vault import` — T037 à T039.
//!
//! XFR-010 à XFR-019.
//!
//! **XFR-010 : aucune passphrase n'est demandée** sans `--verify-content`. Le
//! conteneur est transposé sans être ouvert, et le sceau se contrôle sur le
//! cadrage public. C'est ce qui rend un import possible là où la passphrase
//! n'est pas — à l'autre bout d'un tube, par exemple.
//!
//! **XFR-018 : la saisie passe par le terminal, jamais par l'entrée standard.**
//! Sans cette règle, `vault import -` serait inutilisable : l'entrée standard
//! porte le conteneur, et la lire comme une passphrase reviendrait à en
//! consommer les premiers octets. En l'absence de terminal, la commande échoue
//! au lieu de deviner.
//!
//! # Ce que le sceau établit, et ce que `--verify-content` ajoute
//!
//! Le sceau dit que **ce qui est arrivé est complet et non corrompu**. Il ne
//! dit pas que c'est authentique : il n'est pas authentifié par une clé, et
//! quiconque réécrit un conteneur peut le recalculer. `--verify-content`
//! contrôle les tags AEAD, ce qui exige la passphrase — et c'est pourquoi ce
//! n'est pas le défaut.

use std::io::Read;
use std::path::{Path, PathBuf};

use vault_core::{Error, ImportPolicy, Vault};

use crate::cmd::Contexte;
use crate::error::{CliError, CliResult};
use crate::prompt;

/// Désigne l'entrée standard plutôt qu'un fichier.
const ENTREE_STANDARD: &str = "-";

/// Options de `vault import`.
pub struct Options {
    /// Conteneur à lire, ou `-` pour l'entrée standard.
    pub source: PathBuf,
    /// `--to` : répertoire du vault à créer.
    pub destination: PathBuf,
    /// `--replace` : remplacer un vault existant à cette destination.
    pub replace: bool,
    /// `--verify-content` : contrôler en outre tous les tags AEAD.
    pub verify_content: bool,
    /// `--probe` : sonder la destination sans rien recevoir (D-205).
    pub probe: bool,
    /// `--container-version` : version de conteneur que l'émetteur annonce.
    pub container_version: Option<u32>,
}

/// Reconstitue un vault depuis un conteneur.
///
/// `standard` est l'entrée standard du processus, passée plutôt que lue ici
/// pour que la commande reste vérifiable sans terminal.
///
/// # Errors
///
/// - [`CliError::Usage`] si la destination existe **sans** être un vault
///   (XFR-014) ;
/// - [`vault_core::Error::DestinationOccupied`] si un vault l'occupe et que
///   `--replace` n'a pas été demandé (XFR-012) ;
/// - [`vault_core::Error::Corrupted`] si le conteneur est tronqué, altéré,
///   désordonné ou suivi d'octets (XFR-017) ;
/// - [`vault_core::Error::UnsupportedFormatVersion`] si sa version est inconnue
///   (XFR-016) ;
/// - [`vault_core::Error::InsufficientSpace`] si la place manque (XFR-019) ;
/// - [`CliError::NotInteractive`] si `--verify-content` exige une passphrase
///   que l'entrée standard ne peut pas fournir (XFR-018).
pub fn executer(
    contexte: &mut Contexte,
    options: &Options,
    standard: &mut dyn Read,
) -> CliResult<()> {
    let policy = if options.replace {
        ImportPolicy::Replace
    } else {
        ImportPolicy::Refuse
    };

    if options.probe {
        return sonder(options, policy);
    }

    let resume = if options.source == Path::new(ENTREE_STANDARD) {
        Vault::import(standard, &options.destination, policy)
    } else {
        let mut fichier = match std::fs::File::open(&options.source) {
            Ok(fichier) => fichier,
            // Un conteneur introuvable est un « introuvable », comme un vault
            // absent : code 5, et non une erreur générique.
            Err(erreur) if erreur.kind() == std::io::ErrorKind::NotFound => {
                return Err(CliError::Core(Error::NotFound));
            }
            Err(erreur) => return Err(CliError::Io(erreur)),
        };
        Vault::import(&mut fichier, &options.destination, policy)
    };

    let resume = resume.map_err(destination_inutilisable)?;

    // FR-013b : vault annonce où il a mis le vault remplacé. C'est un
    // avertissement et non une progression : `--quiet` ne doit pas le faire
    // disparaître, sans quoi le seul filet de sécurité de l'opération serait
    // invisible.
    if let Some(ecarte) = &resume.replaced {
        contexte.console.warn(&format!(
            "L'ancien vault n'a pas été supprimé : il est en {}",
            ecarte.display()
        ));
    }

    let verifies = if options.verify_content {
        // XFR-018 : sur le terminal, jamais sur l'entrée standard — qui vient
        // peut-être de porter le conteneur.
        let passphrase = prompt::passphrase_existante(contexte.console)?;
        let session = Vault::open(&options.destination)?.unlock(passphrase)?;
        Some(session.verify_content()?)
    } else {
        None
    };

    if contexte.json {
        contexte.console.output(&format!(
            "{{\"blob_count\":{},\"payload_bytes\":{},\"replaced\":{},\"verified\":{}}}",
            resume.blob_count,
            resume.payload_bytes,
            resume.replaced.as_ref().map_or_else(
                || "null".to_owned(),
                |chemin| format!(
                    "\"{}\"",
                    crate::cmd::json_echappe(&chemin.to_string_lossy())
                )
            ),
            verifies.map_or_else(|| "null".to_owned(), |n| n.to_string())
        ));
    } else {
        contexte.console.info(&format!(
            "Vault reconstitué : {} — {} blob(s), sceau vérifié.",
            options.destination.display(),
            resume.blob_count
        ));
        if let Some(verifies) = verifies {
            contexte.console.info(&format!(
                "Contenu vérifié : {verifies} fichier(s) authentifiés."
            ));
        }
    }
    Ok(())
}

/// Mode de sondage — D-205, XFR-023.
///
/// **Il n'écrit rien sur la sortie standard, et rend un code de retour, un
/// seul.** C'est la seule chose qu'un émetteur apprend de la destination avant
/// de transmettre, et c'est délibéré : FR-029a interdit tout protocole entre
/// vault et vault, et un rang de membre ne tiendrait de toute façon pas dans
/// huit bits.
///
/// | Code | Ce qu'il dit |
/// |---|---|
/// | 0 | La destination est libre, la version annoncée est lisible |
/// | 7 | La version de conteneur annoncée n'est pas gérée |
/// | 8 | La destination est occupée par un vault |
/// | 2 | Le chemin existe sans être un vault, ou l'usage est invalide |
fn sonder(options: &Options, policy: ImportPolicy) -> CliResult<()> {
    // La version est contrôlée **avant** la destination : un émetteur trop
    // récent doit l'apprendre même si la destination est par ailleurs libre.
    if let Some(annoncee) = options.container_version
        && !vault_core::is_container_version_readable(annoncee)
    {
        return Err(CliError::Core(Error::UnsupportedFormatVersion {
            found: annoncee,
            supported: vault_core::CONTAINER_VERSION,
        }));
    }
    Vault::check_destination(&options.destination, policy).map_err(destination_inutilisable)
}

/// XFR-014 : une destination qui existe **sans** être un vault est un problème
/// d'usage, pas une collision d'entrée — et le contrat lui réserve le code 2.
///
/// La traduction a lieu ici plutôt que dans la bibliothèque parce que c'est un
/// choix de présentation : `vault-core` dit correctement « l'élément existe
/// déjà », et c'est la ligne de commande qui décide qu'un chemin mal désigné
/// relève de l'usage.
fn destination_inutilisable(erreur: Error) -> CliError {
    match erreur {
        Error::AlreadyExists => CliError::Usage(
            "Cette destination existe et n'est pas un vault. --replace ne s'applique qu'à un \
vault reconnu comme tel : choisissez un autre chemin."
                .to_owned(),
        ),
        autre => CliError::Core(autre),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::console::fake::FakeConsole;

    const PASSPHRASE: &str = "une passphrase bien assez longue";

    /// Un vault peuplé, refermé, et le conteneur qu'il produit.
    fn coffre_et_conteneur(atelier: &Path) -> (PathBuf, Vec<u8>) {
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

        let mut conteneur = Vec::new();
        vault_core::Vault::export(&coffre, vault_core::ExportEnvelope::Source, &mut conteneur)
            .expect("exportable");
        (coffre, conteneur)
    }

    fn contexte<'a>(console: &'a mut FakeConsole, atelier: &Path) -> Contexte<'a> {
        Contexte {
            console,
            vault_dir: atelier.to_path_buf(),
            yes: false,
            json: false,
            idle_timeout: None,
        }
    }

    fn options(source: &Path, destination: &Path) -> Options {
        Options {
            source: source.to_path_buf(),
            destination: destination.to_path_buf(),
            replace: false,
            verify_content: false,
            probe: false,
            container_version: None,
        }
    }

    /// XFR-010 : **aucune passphrase n'est demandée**, et le vault reconstitué
    /// s'ouvre avec celle du vault source.
    #[test]
    fn un_import_ne_demande_rien_et_restitue_un_vault() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let (_, conteneur) = coffre_et_conteneur(atelier.path());
        let source = atelier.path().join("s.vaultx");
        std::fs::write(&source, &conteneur).expect("écrivable");
        let restaure = atelier.path().join("restaure");

        let mut console = FakeConsole::non_interactive();
        executer(
            &mut contexte(&mut console, atelier.path()),
            &options(&source, &restaure),
            &mut std::io::empty(),
        )
        .expect("importable");

        assert!(console.invites.is_empty(), "{:?}", console.invites);
        assert!(console.tout_affiche().contains("sceau vérifié"));
        assert!(
            vault_core::Vault::open(&restaure)
                .expect("ouvrable")
                .unlock(vault_core::SecretString::from(PASSPHRASE.to_owned()))
                .is_ok()
        );
    }

    /// Le conteneur peut venir de l'entrée standard : c'est ce qui rend le tube
    /// nu possible.
    #[test]
    fn un_conteneur_se_lit_sur_l_entree_standard() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let (_, conteneur) = coffre_et_conteneur(atelier.path());
        let restaure = atelier.path().join("restaure");

        let mut console = FakeConsole::non_interactive();
        executer(
            &mut contexte(&mut console, atelier.path()),
            &options(Path::new(ENTREE_STANDARD), &restaure),
            &mut &conteneur[..],
        )
        .expect("importable");

        assert!(restaure.join("header").is_file());
    }

    /// XFR-012 : une destination occupée par un vault rend 8, sans rien écrire.
    #[test]
    fn une_destination_occupee_rend_huit() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let (coffre, conteneur) = coffre_et_conteneur(atelier.path());

        let mut console = FakeConsole::non_interactive();
        let erreur = executer(
            &mut contexte(&mut console, atelier.path()),
            &options(Path::new(ENTREE_STANDARD), &coffre),
            &mut &conteneur[..],
        )
        .expect_err("refus attendu");

        assert_eq!(erreur.code(), 8);
        assert!(erreur.message().contains("--replace"));
    }

    /// XFR-014 : une destination qui existe sans être un vault rend 2, avec ou
    /// sans `--replace`.
    #[test]
    fn une_destination_qui_n_est_pas_un_vault_rend_deux() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let (_, conteneur) = coffre_et_conteneur(atelier.path());
        let fichier = atelier.path().join("fichier-ordinaire");
        std::fs::write(&fichier, b"contenu etranger").expect("écrivable");

        for replace in [false, true] {
            let mut console = FakeConsole::non_interactive();
            let erreur = executer(
                &mut contexte(&mut console, atelier.path()),
                &Options {
                    replace,
                    ..options(Path::new(ENTREE_STANDARD), &fichier)
                },
                &mut &conteneur[..],
            )
            .expect_err("refus attendu");

            assert_eq!(erreur.code(), 2, "--replace = {replace}");
            assert!(erreur.message().contains("n'est pas un vault"));
        }
        assert_eq!(
            std::fs::read(&fichier).expect("lisible"),
            b"contenu etranger"
        );
    }

    /// XFR-013 : l'ancien vault est déplacé, jamais supprimé, et son chemin est
    /// **annoncé** — par un avertissement, que `--quiet` ne supprime pas.
    #[test]
    fn un_remplacement_annonce_ou_l_ancien_vault_se_trouve() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let (coffre, conteneur) = coffre_et_conteneur(atelier.path());

        let mut console = FakeConsole::non_interactive();
        executer(
            &mut contexte(&mut console, atelier.path()),
            &Options {
                replace: true,
                ..options(Path::new(ENTREE_STANDARD), &coffre)
            },
            &mut &conteneur[..],
        )
        .expect("remplaçable");

        let annonce = console
            .avertissements
            .iter()
            .find(|texte| texte.contains("pas été supprimé"))
            .expect("le chemin doit être annoncé");
        assert!(annonce.contains(".vault-remplace-"), "{annonce}");

        let ecarte = annonce
            .rsplit_once(" en ")
            .expect("le chemin suit le message")
            .1;
        assert!(Path::new(ecarte).is_dir(), "{ecarte}");
    }

    /// XFR-017 : un conteneur altéré rend 1, sans laisser de vault.
    #[test]
    fn un_conteneur_altere_rend_un() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let (_, conteneur) = coffre_et_conteneur(atelier.path());
        let restaure = atelier.path().join("restaure");

        let mut console = FakeConsole::non_interactive();
        let erreur = executer(
            &mut contexte(&mut console, atelier.path()),
            &options(Path::new(ENTREE_STANDARD), &restaure),
            &mut &conteneur[..conteneur.len() - 5],
        )
        .expect_err("refus attendu");

        assert_eq!(erreur.code(), 1);
        assert!(!restaure.exists());
    }

    /// Un conteneur introuvable est un « introuvable » : code 5.
    #[test]
    fn un_conteneur_introuvable_rend_cinq() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let mut console = FakeConsole::non_interactive();

        let erreur = executer(
            &mut contexte(&mut console, atelier.path()),
            &options(
                &atelier.path().join("nulle-part.vaultx"),
                &atelier.path().join("restaure"),
            ),
            &mut std::io::empty(),
        )
        .expect_err("refus attendu");
        assert_eq!(erreur.code(), 5);
    }

    /// Une source illisible pour une autre raison qu'une absence remonte telle
    /// quelle, et non déguisée en « introuvable ».
    #[cfg(unix)]
    #[test]
    fn une_source_illisible_remonte_l_erreur() {
        use std::os::unix::fs::PermissionsExt;

        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let source = atelier.path().join("s.vaultx");
        std::fs::write(&source, b"peu importe").expect("écrivable");
        let mut permissions = std::fs::metadata(&source).expect("lisible").permissions();
        permissions.set_mode(0o000);
        std::fs::set_permissions(&source, permissions).expect("modifiable");

        let mut console = FakeConsole::non_interactive();
        let resultat = executer(
            &mut contexte(&mut console, atelier.path()),
            &options(&source, &atelier.path().join("restaure")),
            &mut std::io::empty(),
        );

        let mut permissions = std::fs::metadata(&source).expect("lisible").permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&source, permissions).expect("modifiable");

        assert!(matches!(resultat, Err(CliError::Io(_))), "{resultat:?}");
    }

    /// XFR-010 : `--verify-content` demande la passphrase, et échoue sans
    /// terminal plutôt que de lire l'entrée standard.
    #[test]
    fn la_verification_de_contenu_demande_la_passphrase() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let (_, conteneur) = coffre_et_conteneur(atelier.path());
        let restaure = atelier.path().join("restaure");

        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        executer(
            &mut contexte(&mut console, atelier.path()),
            &Options {
                verify_content: true,
                ..options(Path::new(ENTREE_STANDARD), &restaure)
            },
            &mut &conteneur[..],
        )
        .expect("importable et vérifiable");
        assert_eq!(console.invites.len(), 1);
        assert!(console.tout_affiche().contains("1 fichier(s) authentifiés"));

        // Sans terminal, le vault est bien reconstitué mais la vérification
        // échoue : l'entrée standard ne sert jamais de canal de saisie.
        let second = atelier.path().join("second");
        let mut muette = FakeConsole::non_interactive();
        assert!(matches!(
            executer(
                &mut contexte(&mut muette, atelier.path()),
                &Options {
                    verify_content: true,
                    ..options(Path::new(ENTREE_STANDARD), &second)
                },
                &mut &conteneur[..],
            ),
            Err(CliError::NotInteractive)
        ));
        assert!(second.join("header").is_file());
    }

    #[test]
    fn le_rendu_machine_resume_l_import() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let (coffre, conteneur) = coffre_et_conteneur(atelier.path());

        let mut console = FakeConsole::non_interactive();
        let mut ctx = contexte(&mut console, atelier.path());
        ctx.json = true;
        executer(
            &mut ctx,
            &Options {
                replace: true,
                ..options(Path::new(ENTREE_STANDARD), &coffre)
            },
            &mut &conteneur[..],
        )
        .expect("remplaçable");

        let affiche = console.tout_affiche();
        assert!(affiche.contains("\"blob_count\":1"), "{affiche}");
        assert!(affiche.contains("\"replaced\":\""), "{affiche}");
        assert!(affiche.contains("\"verified\":null"), "{affiche}");

        // Et sans remplacement, `replaced` vaut null.
        let mut console = FakeConsole::non_interactive();
        let mut ctx = contexte(&mut console, atelier.path());
        ctx.json = true;
        executer(
            &mut ctx,
            &options(Path::new(ENTREE_STANDARD), &atelier.path().join("ailleurs")),
            &mut &conteneur[..],
        )
        .expect("importable");
        assert!(console.tout_affiche().contains("\"replaced\":null"));

        // Et avec `--verify-content`, `verified` porte le compte des fichiers
        // authentifiés — la seule valeur du rendu machine qu'un script ne peut
        // obtenir autrement.
        let mut console = FakeConsole::new(&[PASSPHRASE], &[]);
        let mut ctx = contexte(&mut console, atelier.path());
        ctx.json = true;
        executer(
            &mut ctx,
            &Options {
                verify_content: true,
                ..options(Path::new(ENTREE_STANDARD), &atelier.path().join("verifie"))
            },
            &mut &conteneur[..],
        )
        .expect("importable et vérifiable");
        assert!(console.tout_affiche().contains("\"verified\":1"));
    }

    /// D-205, XFR-023 : le sondage n'écrit rien, et rend un code, un seul.
    #[test]
    fn le_sondage_rend_un_code_et_rien_d_autre() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let (coffre, _) = coffre_et_conteneur(atelier.path());

        let sonder_vers = |destination: &Path, version, replace| {
            let mut console = FakeConsole::non_interactive();
            let resultat = executer(
                &mut contexte(&mut console, atelier.path()),
                &Options {
                    probe: true,
                    container_version: version,
                    replace,
                    ..options(Path::new(ENTREE_STANDARD), destination)
                },
                &mut std::io::empty(),
            );
            let affiche = console.tout_affiche();
            assert!(
                affiche.trim().is_empty(),
                "le sondage n'écrit rien : {affiche}"
            );
            resultat.map_err(|erreur| erreur.code())
        };

        // Destination libre, version lisible : 0.
        assert!(sonder_vers(&atelier.path().join("libre"), Some(1), false).is_ok());
        // Destination occupée par un vault : 8, et 0 si le remplacement est
        // demandé.
        assert_eq!(sonder_vers(&coffre, None, false), Err(8));
        assert!(sonder_vers(&coffre, None, true).is_ok());
        // Version de conteneur non gérée : 7, **avant** même de regarder la
        // destination.
        assert_eq!(sonder_vers(&coffre, Some(99), true), Err(7));
        // Chemin qui existe sans être un vault : 2.
        let fichier = atelier.path().join("fichier-ordinaire");
        std::fs::write(&fichier, b"contenu etranger").expect("écrivable");
        assert_eq!(sonder_vers(&fichier, None, true), Err(2));
    }

    /// La traduction de XFR-014 ne détourne que `AlreadyExists` : tout le reste
    /// remonte tel quel.
    #[test]
    fn seule_la_collision_de_destination_devient_un_usage() {
        assert!(matches!(
            destination_inutilisable(Error::AlreadyExists),
            CliError::Usage(_)
        ));
        assert!(matches!(
            destination_inutilisable(Error::Corrupted),
            CliError::Core(Error::Corrupted)
        ));
    }
}
