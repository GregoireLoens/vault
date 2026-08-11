//! Suite bloquante — le transfert entre postes (T046, T047, T060).
//!
//! Le scénario 6 du quickstart, éprouvé contre le **faux client ssh** de
//! `tests/faux-ssh/`, placé en tête du `PATH` du processus `vault` que ces
//! tests lancent (D-207). Aucune couture n'existe dans le code de production :
//! ce sont ses vraies lignes qui s'exécutent.
//!
//! Trois familles de propriétés y sont établies :
//!
//! - **rien ne part avant le sondage** — une destination occupée ou une version
//!   non gérée font échouer sans qu'un octet du vault n'ait traversé (FR-028) ;
//! - **aucun secret ne traverse le canal**, dans un sens comme dans l'autre, ni
//!   la passphrase ni la clé maîtresse en clair (FR-023, SC-003) ;
//! - **le tube nu donne la même garantie que la commande dédiée** — le sceau vit
//!   dans le conteneur, pas dans la commande (XFR-050, SC-013).
//!
//! Ces tests ne s'exécutent que sur des systèmes POSIX : le faux client est un
//! script `sh`. C'est la plateforme d'intégration continue, où la couverture est
//! mesurée.

#![cfg(unix)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;

const PASSPHRASE: &str = "une passphrase bien assez longue";

/// Répertoire du faux client ssh, à mettre en tête du `PATH`.
fn faux_ssh() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("faux-ssh")
}

/// Le binaire `vault` de la compilation en cours.
fn binaire() -> PathBuf {
    assert_cmd::cargo::cargo_bin("vault")
}

/// Un atelier : le faux ssh dans le `PATH`, un journal, et de quoi consigner ce
/// qui traverse le tube.
struct Atelier {
    repertoire: tempfile::TempDir,
    journal: PathBuf,
    recu: PathBuf,
}

impl Atelier {
    fn neuf() -> Self {
        let repertoire = tempfile::tempdir().expect("répertoire temporaire");
        // Les traces du faux client vivent à part : le répertoire de l'atelier
        // sert de destination aux transferts, et un fichier de trace qui s'y
        // trouverait passerait pour une destination occupée.
        let traces = repertoire.path().join("_faux-ssh");
        std::fs::create_dir(&traces).expect("créable");
        let journal = traces.join("journal");
        let recu = traces.join("recu");
        std::fs::write(&journal, b"").expect("écrivable");
        std::fs::write(&recu, b"").expect("écrivable");
        Self {
            repertoire,
            journal,
            recu,
        }
    }

    fn chemin(&self) -> &Path {
        self.repertoire.path()
    }

    fn journal(&self) -> String {
        String::from_utf8_lossy(&std::fs::read(&self.journal).expect("lisible")).into_owned()
    }

    fn octets_recus(&self) -> Vec<u8> {
        std::fs::read(&self.recu).expect("lisible")
    }

    /// Une commande `vault` dont le `PATH` commence par le faux client.
    fn vault(&self) -> Command {
        let mut commande = Command::new(binaire());
        let chemin_actuel = std::env::var_os("PATH").unwrap_or_default();
        let mut chemins = vec![faux_ssh()];
        chemins.extend(std::env::split_paths(&chemin_actuel));
        commande
            .env(
                "PATH",
                std::env::join_paths(chemins).expect("PATH assemblable"),
            )
            .env("FAUX_SSH_JOURNAL", &self.journal)
            .env("FAUX_SSH_RECU", &self.recu);
        commande
    }

    /// Un vault local **volumineux**, refermé.
    ///
    /// Nécessaire pour éprouver un canal rompu **à mi-course** : sous ce
    /// volume, le conteneur entier tient dans le tampon du tube, l'émetteur
    /// n'attend jamais, et la rupture ne se voit pas. Le tampon d'un tube fait
    /// 64 Kio sur Linux ; il faut donc écrire nettement plus pour que la
    /// coupure atteigne vraiment l'écrivain.
    fn coffre_volumineux(&self, nom: &str) -> PathBuf {
        self.coffre_de(nom, &vec![0x5a; 400_000])
    }

    /// Un vault local peuplé, refermé.
    fn coffre(&self, nom: &str) -> PathBuf {
        self.coffre_de(nom, SECRET)
    }

    /// Un vault local contenant `contenu`, refermé.
    fn coffre_de(&self, nom: &str, contenu: &[u8]) -> PathBuf {
        let coffre = self.chemin().join(nom);
        let mut vault = vault_core::Vault::create(
            &coffre,
            vault_core::SecretString::from(PASSPHRASE.to_owned()),
            vault_core::KdfParams::new(64, 1, 1).expect("valides"),
        )
        .expect("créable");

        let source = self.chemin().join(format!("{nom}-source.bin"));
        std::fs::write(&source, contenu).expect("écrivable");
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
}

/// Marqueur choisi pour être introuvable par hasard.
const SECRET: &[u8] = b"XYZZY-CONTENU-CONFIDENTIEL-QUI-NE-DOIT-PAS-TRAVERSER";

fn en_texte(chemin: &Path) -> &str {
    chemin.to_str().expect("UTF-8")
}

/// Vrai si `foin` contient `aiguille`.
fn contient(foin: &[u8], aiguille: &[u8]) -> bool {
    !aiguille.is_empty() && foin.windows(aiguille.len()).any(|f| f == aiguille)
}

// ---------------------------------------------------------------------------
// Le cas nominal
// ---------------------------------------------------------------------------

/// Un envoi complet : le sondage passe, le conteneur traverse le tube, la
/// destination le reçoit et le vérifie, et son code de retour 0 remonte.
#[test]
fn un_envoi_nominal_depose_un_vault_ouvrable_a_la_destination() {
    let atelier = Atelier::neuf();
    let coffre = atelier.coffre("coffre");
    let destination = atelier.chemin().join("recu-vault");

    atelier
        .vault()
        .args([
            "send",
            en_texte(&coffre),
            &format!("poste-b:{}", en_texte(&destination)),
            "--remote-command",
            en_texte(&binaire()),
        ])
        .assert()
        .code(0);

    // Le vault est arrivé, et il s'ouvre avec la passphrase du vault source.
    let session = vault_core::Vault::open(&destination)
        .expect("ouvrable")
        .unlock(vault_core::SecretString::from(PASSPHRASE.to_owned()))
        .expect("déverrouillable");
    assert_eq!(session.list(None).len(), 1);

    // Deux sessions ssh : le sondage, puis la transmission (D-205).
    let journal = atelier.journal();
    assert_eq!(journal.lines().count(), 2, "{journal}");
    assert!(journal.lines().next().expect("sondage").contains("--probe"));
    assert!(
        !journal
            .lines()
            .nth(1)
            .expect("transmission")
            .contains("--probe")
    );
}

/// XFR-032 : le rapatriement obtient le même résultat, dans l'autre sens.
#[test]
fn un_rapatriement_nominal_ramene_le_vault() {
    let atelier = Atelier::neuf();
    let coffre = atelier.coffre("distant");
    let destination = atelier.chemin().join("rapatrie");

    atelier
        .vault()
        .args([
            "fetch",
            &format!("poste-b:{}", en_texte(&coffre)),
            en_texte(&destination),
            "--remote-command",
            en_texte(&binaire()),
        ])
        .assert()
        .code(0);

    let session = vault_core::Vault::open(&destination)
        .expect("ouvrable")
        .unlock(vault_core::SecretString::from(PASSPHRASE.to_owned()))
        .expect("déverrouillable");
    assert_eq!(session.list(None).len(), 1);

    // Le vault source est intact : un transfert copie, il ne déplace pas.
    assert!(coffre.join("header").is_file());
}

// ---------------------------------------------------------------------------
// FR-028 : rien ne part avant le sondage
// ---------------------------------------------------------------------------

/// **Zéro octet du vault n'est écrit** lorsque le sondage refuse. C'est la
/// raison d'être du sondage, et la propriété la plus importante de ce fichier.
#[test]
fn un_sondage_refusant_ne_laisse_partir_aucun_octet() {
    // Destination occupée : le sondage relaie vers un vrai vault, qui rend 8.
    let atelier = Atelier::neuf();
    let coffre = atelier.coffre("coffre");
    let occupee = atelier.coffre("occupee");

    atelier
        .vault()
        .args([
            "send",
            en_texte(&coffre),
            &format!("poste-b:{}", en_texte(&occupee)),
            "--remote-command",
            en_texte(&binaire()),
        ])
        .assert()
        .code(8);

    assert!(
        atelier.octets_recus().is_empty(),
        "aucun octet ne doit avoir traversé le tube"
    );
    assert_eq!(
        atelier.journal().lines().count(),
        1,
        "seule la session de sondage a été ouverte"
    );

    // Version de conteneur non gérée : le faux client rend 7 au sondage.
    let atelier = Atelier::neuf();
    let coffre = atelier.coffre("coffre");
    atelier
        .vault()
        .env("FAUX_SSH_MODE_SONDAGE", "code:7")
        .args([
            "send",
            en_texte(&coffre),
            &format!("poste-b:{}", en_texte(&atelier.chemin().join("ailleurs"))),
            "--remote-command",
            en_texte(&binaire()),
        ])
        .assert()
        .code(7);
    assert!(atelier.octets_recus().is_empty());
}

/// Le sondage refuse aussi lorsque le chemin distant existe **sans** être un
/// vault : code 2, et rien n'a bougé.
#[test]
fn un_chemin_distant_qui_n_est_pas_un_vault_est_refuse_au_sondage() {
    let atelier = Atelier::neuf();
    let coffre = atelier.coffre("coffre");
    let fichier = atelier.chemin().join("fichier-ordinaire");
    std::fs::write(&fichier, b"contenu etranger").expect("écrivable");

    atelier
        .vault()
        .args([
            "send",
            en_texte(&coffre),
            &format!("poste-b:{}", en_texte(&fichier)),
            "--remote-command",
            en_texte(&binaire()),
        ])
        .assert()
        .code(2);

    assert!(atelier.octets_recus().is_empty());
    assert_eq!(
        std::fs::read(&fichier).expect("lisible"),
        b"contenu etranger"
    );
}

/// Avec `--replace` et `--yes`, la même destination occupée devient acceptable,
/// et l'ancien vault est déplacé plutôt que supprimé.
#[test]
fn un_remplacement_confirme_traverse_le_sondage() {
    let atelier = Atelier::neuf();
    let coffre = atelier.coffre("coffre");
    let occupee = atelier.coffre("occupee");

    atelier
        .vault()
        .args([
            "send",
            en_texte(&coffre),
            &format!("poste-b:{}", en_texte(&occupee)),
            "--replace",
            "--yes",
            "--remote-command",
            en_texte(&binaire()),
        ])
        .assert()
        .code(0);

    // L'ancien vault est là, sous son nom de remplacement (FR-013b).
    let ecarte: Vec<String> = std::fs::read_dir(atelier.chemin())
        .expect("listable")
        .filter_map(std::result::Result::ok)
        .map(|entree| entree.file_name().to_string_lossy().into_owned())
        .filter(|nom| nom.contains(".vault-remplace-"))
        .collect();
    assert_eq!(ecarte.len(), 1, "{ecarte:?}");
    assert!(occupee.join("header").is_file());
}

// ---------------------------------------------------------------------------
// XFR-024, FR-023, SC-003 : aucun secret ne traverse le canal
// ---------------------------------------------------------------------------

/// **Quel que soit le cas** : ni la passphrase, ni le contenu déposé,
/// n'apparaissent dans ce que le faux client a reçu.
#[test]
fn aucun_secret_ne_traverse_le_canal() {
    let atelier = Atelier::neuf();
    let coffre = atelier.coffre("coffre");
    let destination = atelier.chemin().join("recu-vault");

    atelier
        .vault()
        .args([
            "send",
            en_texte(&coffre),
            &format!("poste-b:{}", en_texte(&destination)),
            "--remote-command",
            en_texte(&binaire()),
        ])
        .assert()
        .code(0);

    let recu = atelier.octets_recus();
    assert!(!recu.is_empty(), "quelque chose doit avoir traversé");
    assert!(
        !contient(&recu, SECRET),
        "le contenu déposé apparaît en clair dans le tube"
    );
    assert!(
        !contient(&recu, PASSPHRASE.as_bytes()),
        "la passphrase apparaît dans le tube"
    );

    // Ce qui a traversé est bien le conteneur, et rien d'autre : la magie y
    // figure, et le flux se réimporte tel quel.
    assert!(contient(&recu, &vault_core::CONTAINER_MAGIC));
    let ailleurs = atelier.chemin().join("depuis-le-tube");
    vault_core::Vault::import(&mut &recu[..], &ailleurs, vault_core::ImportPolicy::Refuse)
        .expect("ce qui a traversé est un conteneur complet");
}

// ---------------------------------------------------------------------------
// XFR-022, XFR-026 : ce que vault passe au client, et ce qu'il ne passe pas
// ---------------------------------------------------------------------------

/// vault n'ajoute **aucune** option touchant à la vérification d'hôte, et
/// transmet celles de l'utilisateur telles quelles.
#[test]
fn la_ligne_remise_au_client_n_affaiblit_rien() {
    let atelier = Atelier::neuf();
    let coffre = atelier.coffre("coffre");

    atelier
        .vault()
        .args([
            "send",
            en_texte(&coffre),
            &format!("poste-b:{}", en_texte(&atelier.chemin().join("recu"))),
            "--ssh-option",
            "-p2222",
            "--ssh-option",
            "-oControlMaster=auto",
            "--remote-command",
            en_texte(&binaire()),
        ])
        .assert()
        .code(0);

    let journal = atelier.journal();
    for interdite in [
        "StrictHostKeyChecking",
        "UserKnownHostsFile",
        "BatchMode",
        "-o StrictHostKeyChecking",
    ] {
        assert!(!journal.contains(interdite), "{interdite} : {journal}");
    }
    // Les options de l'utilisateur, elles, sont bien là — telles quelles.
    assert!(journal.contains("-p2222"), "{journal}");
    assert!(journal.contains("-oControlMaster=auto"), "{journal}");
    // Et la destination est celle qu'il a écrite.
    assert!(journal.contains("poste-b"), "{journal}");
}

/// XFR-026 : un chemin distant hostile est **cité**, et n'est jamais
/// interprété — ni par le shell distant, ni par le faux client qui l'imite.
#[test]
fn un_chemin_distant_hostile_n_est_jamais_interprete() {
    let atelier = Atelier::neuf();
    let coffre = atelier.coffre("coffre");
    let temoin = atelier.chemin().join("temoin-qui-doit-survivre");
    std::fs::write(&temoin, b"intact").expect("écrivable");

    // Le chemin porte de quoi effacer le témoin si la citation était fautive.
    let hostile = format!(
        "{}; rm -f {}",
        en_texte(&atelier.chemin().join("recu")),
        en_texte(&temoin)
    );

    atelier
        .vault()
        .env("FAUX_SSH_MODE_SONDAGE", "code:2")
        .args([
            "send",
            en_texte(&coffre),
            &format!("poste-b:{hostile}"),
            "--remote-command",
            en_texte(&binaire()),
        ])
        .assert()
        .code(2);

    assert!(
        temoin.is_file(),
        "le chemin hostile a été interprété par le shell"
    );
    // La ligne remise au client porte bien le chemin **cité**.
    assert!(atelier.journal().contains('\''), "{}", atelier.journal());
}

/// D-206 : un chemin distant qui n'est pas de l'UTF-8 valide est refusé
/// **avant tout lancement**.
#[test]
fn un_chemin_distant_non_utf8_est_refuse_avant_tout_lancement() {
    use std::os::unix::ffi::OsStrExt;

    let atelier = Atelier::neuf();
    let coffre = atelier.coffre("coffre");

    atelier
        .vault()
        .arg("send")
        .arg(en_texte(&coffre))
        .arg(std::ffi::OsStr::from_bytes(b"poste-b:/coffre-\xff\xfe"))
        .assert()
        .code(2);

    assert!(
        atelier.journal().is_empty(),
        "aucune session ssh ne devait être ouverte"
    );
}

// ---------------------------------------------------------------------------
// XFR-025, XFR-027 : les échecs du canal et ceux de la destination
// ---------------------------------------------------------------------------

/// La table des échecs du scénario 6, en un test : chaque situation rend le
/// code que le contrat lui réserve, et le vault source reste intact.
#[test]
fn chaque_echec_rend_le_code_du_contrat() {
    for (mode, attendu, quoi) in [
        ("absent", 9, "commande distante introuvable"),
        ("hote-inconnu", 9, "hôte inconnu"),
        ("empreinte", 9, "empreinte changée"),
        ("rompu", 9, "canal rompu à mi-course"),
        ("signal", 9, "session tuée par un signal"),
        ("code:1", 1, "conteneur refusé par la destination"),
        ("code:6", 6, "espace insuffisant à la destination"),
    ] {
        let atelier = Atelier::neuf();
        // Volumineux : c'est la seule façon qu'une rupture soit vraiment « à
        // mi-course » plutôt qu'absorbée par le tampon du tube.
        let coffre = atelier.coffre_volumineux("coffre");
        let avant = std::fs::read(coffre.join("header")).expect("lisible");

        atelier
            .vault()
            .env("FAUX_SSH_MODE", mode)
            .args([
                "send",
                en_texte(&coffre),
                &format!("poste-b:{}", en_texte(&atelier.chemin().join("recu"))),
                "--remote-command",
                en_texte(&binaire()),
            ])
            .assert()
            .code(attendu);

        // FR-031 : le vault source n'est ni modifié ni supprimé.
        assert_eq!(
            std::fs::read(coffre.join("header")).expect("lisible"),
            avant,
            "{quoi}"
        );
    }
}

/// XFR-027 : le client ssh absent du `PATH` rend 9, et le message nomme ce qui
/// manque.
#[test]
fn un_client_ssh_absent_du_path_rend_neuf() {
    let atelier = Atelier::neuf();
    let coffre = atelier.coffre("coffre");

    Command::new(binaire())
        .env("PATH", atelier.chemin())
        .args([
            "send",
            en_texte(&coffre),
            &format!("poste-b:{}", en_texte(&atelier.chemin().join("recu"))),
        ])
        .assert()
        .code(9)
        .stderr(predicates::str::contains("transport"));
}

// ---------------------------------------------------------------------------
// XFR-050, XFR-051, SC-013 : le tube nu
// ---------------------------------------------------------------------------

/// **La suite établit l'identité, plutôt que la documentation ne l'affirme.**
///
/// Un transfert monté à la main en tube — `export --to -` puis `import -` —
/// produit exactement le même vault, et **les mêmes vérifications**, qu'un
/// transfert lancé par `send` : le sceau vit dans le conteneur, pas dans la
/// commande.
#[test]
fn le_tube_nu_donne_la_meme_garantie_que_la_commande_dediee() {
    let atelier = Atelier::neuf();
    let coffre = atelier.coffre("coffre");

    // Par la commande dédiée.
    let par_send = atelier.chemin().join("par-send");
    atelier
        .vault()
        .args([
            "send",
            en_texte(&coffre),
            &format!("poste-b:{}", en_texte(&par_send)),
            "--remote-command",
            en_texte(&binaire()),
        ])
        .assert()
        .code(0);

    // À la main, en tube : le conteneur passe par un fichier, ce qui est le
    // même flux d'octets qu'un tube — et ce que la suite peut comparer.
    let conteneur = atelier.chemin().join("a-la-main.vaultx");
    Command::new(binaire())
        .args([
            "export",
            "--to",
            en_texte(&conteneur),
            "--vault",
            en_texte(&coffre),
        ])
        .assert()
        .code(0);
    let par_tube = atelier.chemin().join("par-tube");
    Command::new(binaire())
        .args(["import", en_texte(&conteneur), "--to", en_texte(&par_tube)])
        .assert()
        .code(0);

    // Les deux vaults sont identiques, octet pour octet.
    assert_eq!(repertoire(&par_send), repertoire(&par_tube));

    // Et le tube nu refuse **exactement** ce que `send` refuse : un conteneur
    // altéré ne donne pas de vault, quel que soit le chemin emprunté.
    let mut altere = std::fs::read(&conteneur).expect("lisible");
    let milieu = altere.len() / 2;
    altere[milieu] ^= 0x01;
    let corrompu = atelier.chemin().join("corrompu.vaultx");
    std::fs::write(&corrompu, &altere).expect("écrivable");

    let refuse = atelier.chemin().join("refuse");
    Command::new(binaire())
        .args(["import", en_texte(&corrompu), "--to", en_texte(&refuse)])
        .assert()
        .code(1);
    assert!(!refuse.exists());
}

/// Contenu d'un répertoire de vault, `.lock` excepté.
fn repertoire(coffre: &Path) -> Vec<(String, Vec<u8>)> {
    let mut contenu: Vec<(String, Vec<u8>)> = walkdir::WalkDir::new(coffre)
        .sort_by_file_name()
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entree| entree.file_type().is_file())
        .map(|entree| {
            (
                entree
                    .path()
                    .strip_prefix(coffre)
                    .expect("sous le vault")
                    .to_string_lossy()
                    .into_owned(),
                std::fs::read(entree.path()).expect("lisible"),
            )
        })
        .filter(|(nom, _)| nom != ".lock")
        .collect();
    contenu.sort();
    contenu
}

// ---------------------------------------------------------------------------
// FR-035 : ce qu'un transfert échoué laisse à la destination
// ---------------------------------------------------------------------------

/// Un transfert interrompu à mi-course ne laisse **aucun vault ouvrable** à la
/// destination, et le reliquat éventuel se supprime sans conséquence.
#[test]
fn un_transfert_rompu_ne_laisse_aucun_vault_ouvrable() {
    let atelier = Atelier::neuf();
    let coffre = atelier.coffre_volumineux("coffre");
    let destination = atelier.chemin().join("recu");

    atelier
        .vault()
        .env("FAUX_SSH_MODE", "rompu")
        .args([
            "send",
            en_texte(&coffre),
            &format!("poste-b:{}", en_texte(&destination)),
            "--remote-command",
            en_texte(&binaire()),
        ])
        .assert()
        .code(9);

    assert!(
        vault_core::Vault::open(&destination).is_err(),
        "aucun vault ouvrable ne doit subsister"
    );
}

// ---------------------------------------------------------------------------
// Le compte rendu, et le sondage dans le sens du rapatriement
// ---------------------------------------------------------------------------

/// FR-028 dans l'autre sens : le sondage porte sur la **source** distante, et
/// son refus arrive avant qu'un octet ne soit reçu.
#[test]
fn un_rapatriement_sonde_la_source_avant_de_recevoir() {
    let atelier = Atelier::neuf();
    let destination = atelier.chemin().join("rapatrie");

    // Le vault distant est introuvable : le sondage rend 5, et rien n'arrive.
    atelier
        .vault()
        .env("FAUX_SSH_MODE_SONDAGE", "code:5")
        .args([
            "fetch",
            &format!("poste-b:{}", en_texte(&atelier.chemin().join("nulle-part"))),
            en_texte(&destination),
            "--remote-command",
            en_texte(&binaire()),
        ])
        .assert()
        .code(5);

    assert!(!destination.exists(), "rien ne doit être arrivé");
    assert_eq!(
        atelier.journal().lines().count(),
        1,
        "seule la session de sondage a été ouverte"
    );
}

/// Le rendu machine des deux transferts, et l'annonce du vault remplacé.
///
/// FR-013b vaut dans les deux sens : là comme ailleurs, vault dit **où** il a
/// mis le vault qu'il a écarté.
#[test]
fn le_rendu_machine_resume_les_deux_transferts() {
    let atelier = Atelier::neuf();
    let coffre = atelier.coffre("coffre");

    // Envoi, en JSON.
    let sortie = atelier
        .vault()
        .args([
            "send",
            en_texte(&coffre),
            &format!("poste-b:{}", en_texte(&atelier.chemin().join("recu-vault"))),
            "--json",
            "--remote-command",
            en_texte(&binaire()),
        ])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let sortie = String::from_utf8(sortie).expect("UTF-8");
    assert!(sortie.contains("\"blob_count\":1"), "{sortie}");
    assert!(sortie.contains("\"payload_bytes\":"), "{sortie}");

    // Rapatriement par-dessus un vault existant, en JSON : l'ancien est déplacé
    // et son emplacement annoncé sur l'erreur standard.
    let occupee = atelier.coffre("occupee");
    let assertion = atelier
        .vault()
        .args([
            "fetch",
            &format!("poste-b:{}", en_texte(&coffre)),
            en_texte(&occupee),
            "--replace",
            "--json",
            "--remote-command",
            en_texte(&binaire()),
        ])
        .assert()
        .code(0);
    let sortie = String::from_utf8(assertion.get_output().stdout.clone()).expect("UTF-8");
    let dialogue = String::from_utf8(assertion.get_output().stderr.clone()).expect("UTF-8");

    assert!(sortie.contains("\"blob_count\":1"), "{sortie}");
    assert!(
        dialogue.contains(".vault-remplace-"),
        "l'emplacement du vault écarté doit être annoncé : {dialogue}"
    );
    // XFR-006 : le rendu machine sort seul sur la sortie standard.
    assert!(!sortie.contains(".vault-remplace-"), "{sortie}");
}

/// Le rendu textuel dit ce qui est arrivé, et où.
#[test]
fn le_rendu_textuel_nomme_la_destination() {
    let atelier = Atelier::neuf();
    let coffre = atelier.coffre("coffre");
    let destination = atelier.chemin().join("recu-vault");

    atelier
        .vault()
        .args([
            "send",
            en_texte(&coffre),
            &format!("poste-b:{}", en_texte(&destination)),
            "--remote-command",
            en_texte(&binaire()),
        ])
        .assert()
        .code(0)
        .stderr(predicates::str::contains("Vault reçu : poste-b:"));

    let rapatrie = atelier.chemin().join("rapatrie");
    atelier
        .vault()
        .args([
            "fetch",
            &format!("poste-b:{}", en_texte(&coffre)),
            en_texte(&rapatrie),
            "--remote-command",
            en_texte(&binaire()),
        ])
        .assert()
        .code(0)
        .stderr(predicates::str::contains("Vault rapatrié"));
}

/// Les mêmes refus de forme que `send`, dans le sens du rapatriement, et
/// **sans** `--remote-command` : c'est le seul chemin qui emploie la commande
/// distante par défaut.
#[test]
fn le_rapatriement_refuse_une_source_mal_formee_et_emploie_le_defaut() {
    let atelier = Atelier::neuf();

    // Source qui n'a pas la forme d'une cible distante : refus, sans réseau.
    atelier
        .vault()
        .args([
            "fetch",
            "pas-une-cible",
            en_texte(&atelier.chemin().join("rapatrie")),
        ])
        .assert()
        .code(2);
    assert!(
        atelier.journal().is_empty(),
        "aucune session ne devait s'ouvrir"
    );

    // Sans `--remote-command`, c'est `vault` qui est invoqué là-bas. Le faux
    // client relaie, et `vault` n'étant pas dans son `PATH`, la commande
    // distante est introuvable : code 9 (XFR-027).
    atelier
        .vault()
        .args([
            "fetch",
            &format!("poste-b:{}", en_texte(&atelier.chemin().join("distant"))),
            en_texte(&atelier.chemin().join("rapatrie")),
        ])
        .assert()
        .code(9);

    assert!(
        atelier.journal().contains("'vault' export"),
        "la commande distante par défaut doit être `vault` : {}",
        atelier.journal()
    );
}
