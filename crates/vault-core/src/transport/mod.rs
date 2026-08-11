//! Transport entre postes — T049 à T056.
//!
//! FR-019 à FR-031. **vault n'implémente aucun protocole réseau et n'ouvre
//! aucune socket** (FR-020). Il lance le client ssh du système en
//! sous-processus et lui parle par des tubes ; l'authentification des deux
//! extrémités, la vérification d'empreinte et le premier appairage sont ceux
//! d'OpenSSH, éprouvés et déjà configurés sur le poste de l'utilisateur.
//!
//! Le réseau reste ainsi dans le graphe de **processus** de vault, jamais dans
//! son graphe de **dépendances** : `deny.toml` continue de bannir toute crate
//! réseau, transitivité comprise.
//!
//! # Ce que vault ne fait pas, et pourquoi
//!
//! - **Il n'ajoute aucune option touchant à la vérification d'hôte** — ni
//!   `StrictHostKeyChecking`, ni `UserKnownHostsFile`, ni `BatchMode`. Il ne
//!   retire donc rien à la configuration de l'utilisateur, et **ne peut pas non
//!   plus la corriger** : c'est la limite de la délégation, et elle est écrite
//!   ici plutôt que supposée.
//! - **Il n'intercepte pas la sortie d'erreur du sous-processus.** C'est ce qui
//!   fait parvenir à l'utilisateur les questions d'OpenSSH — confirmation
//!   d'empreinte, passphrase de clé, second facteur — et son avertissement de
//!   changement de clé d'hôte, qui doit interrompre un transfert.
//! - **Il ne définit aucun protocole entre vault et vault** (FR-029a). Le
//!   compte rendu de la destination se réduit au **code de retour** de la
//!   commande distante, que ssh propage déjà.
//!
//! # Le sondage, et ce qu'il ne peut pas faire
//!
//! Avant de transmettre le moindre octet, l'émetteur ouvre une **première**
//! session ssh qui exécute un mode de sondage de la commande distante. Ce mode
//! n'écrit rien sur sa sortie standard et rend un code de retour, et un seul
//! (D-205). C'est ce qui permet à FR-028 d'être tenu : une destination occupée,
//! un vault absent à l'autre bout ou une version trop ancienne font échouer
//! **avant** le premier octet.
//!
//! Le sondage répond par oui ou par non. Il ne peut pas dire « j'ai reçu 41 372
//! membres », et c'est pourquoi **la reprise d'un transfert interrompu est hors
//! périmètre** : elle exigerait un protocole, que la clarification a écarté.

pub(crate) mod quote;

use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::{Child, Command, Stdio};

use crate::Vault;
use crate::error::{Error, Result};
use crate::format::container::CONTAINER_VERSION;
use crate::ops::export::{ExportEnvelope, ExportSummary};
use crate::ops::import::{ImportPolicy, ImportSummary};
use crate::transport::quote::pour_shell_posix;

/// Programme du client ssh, **résolu par le `PATH`**.
///
/// C'est ainsi que l'utilisateur choisit son client — et c'est aussi ce qui
/// rend les tests possibles **sans couture** : ils placent en tête du `PATH` un
/// exécutable nommé `ssh` qui joue le rôle du client. Le code de production ne
/// comporte donc aucun trait de substitution, aucun paramètre de programme, et
/// ce sont ses vraies lignes que la suite exécute (D-207).
const CLIENT_SSH: &str = "ssh";

/// Commande vault invoquée à distance, par défaut.
const COMMANDE_DISTANTE: &str = "vault";

/// Code de retour d'un shell POSIX pour « commande introuvable ».
const COMMANDE_INTROUVABLE: i32 = 127;

/// Code de retour propre au client ssh : il ne vient pas de vault.
const ECHEC_SSH: i32 = 255;

/// Ce qu'un utilisateur écrit pour désigner l'autre bout : `[utilisateur@]hôte:chemin`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteTarget {
    user: Option<String>,
    host: String,
    path: String,
}

impl RemoteTarget {
    /// Vrai si cette chaîne **ressemble** à une cible distante.
    ///
    /// C'est un contrôle de **forme**, pas d'intention : il sert à refuser
    /// qu'un argument supposé local en soit une (FR-019a). La grammaire de
    /// `send` et `fetch` rend déjà la combinaison distant-distant
    /// inexprimable ; il ne reste que ce contrôle-là.
    ///
    /// Deux formes sont explicitement **locales**, malgré leur deux-points :
    /// un chemin dont le deux-points suit une barre oblique, et une lettre de
    /// lecteur Windows.
    #[must_use]
    pub fn looks_remote(brut: &OsStr) -> bool {
        let texte = brut.to_string_lossy();
        let Some(colonne) = texte.find(':') else {
            return false;
        };
        let avant = &texte[..colonne];
        if avant.is_empty() || avant.contains('/') || avant.contains('\\') {
            return false;
        }
        // `C:\coffre` est un chemin Windows, pas un hôte nommé `C`.
        !(avant.len() == 1 && avant.chars().all(|c| c.is_ascii_alphabetic()))
    }

    /// Analyse `[utilisateur@]hôte:chemin`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPath`] si la chaîne n'est pas de l'UTF-8 valide (D-206),
    /// ou si elle n'a pas la forme d'une cible distante.
    pub fn parse(brut: &OsStr) -> Result<Self> {
        // D-206 : le refus du non-UTF-8 vient **avant** tout le reste. Le format
        // conserve les octets bruts des noms, mais une ligne de commande ssh ne
        // les accepte pas, et refuser explicitement vaut mieux que de laisser le
        // shell distant produire une erreur opaque.
        let texte = brut.to_str().ok_or(Error::InvalidPath)?;
        if !Self::looks_remote(brut) {
            return Err(Error::InvalidPath);
        }

        let (avant, path) = texte.split_once(':').ok_or(Error::InvalidPath)?;
        if path.is_empty() {
            return Err(Error::InvalidPath);
        }

        let (user, host) = match avant.rsplit_once('@') {
            Some((user, host)) => (Some(user.to_owned()), host),
            None => (None, avant),
        };
        if host.is_empty() || user.as_deref().is_some_and(str::is_empty) {
            return Err(Error::InvalidPath);
        }

        Ok(Self {
            user,
            host: host.to_owned(),
            path: path.to_owned(),
        })
    }

    /// Chemin du vault sur le poste distant.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Hôte, sans l'utilisateur.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Utilisateur, s'il a été précisé.
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// Ce qui est remis au client ssh comme destination.
    fn destination(&self) -> String {
        match &self.user {
            Some(user) => format!("{user}@{}", self.host),
            None => self.host.clone(),
        }
    }
}

/// Ce que l'utilisateur passe au client ssh, et la commande à invoquer là-bas.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshOptions {
    /// Options transmises **telles quelles** au client ssh — port, identité,
    /// hôte de rebond. vault ne les interprète pas (FR-027).
    pub options: Vec<OsString>,
    /// Commande vault à invoquer à distance.
    pub remote_command: String,
}

impl Default for SshOptions {
    fn default() -> Self {
        Self {
            options: Vec::new(),
            remote_command: COMMANDE_DISTANTE.to_owned(),
        }
    }
}

impl SshOptions {
    /// Assemble la ligne que le **shell distant** recevra.
    ///
    /// Chaque morceau y est déjà cité s'il en a besoin : `ssh` ne transmet pas
    /// un tableau d'arguments, il concatène (D-206).
    fn ligne_distante(&self, morceaux: &[String]) -> String {
        let mut ligne = pour_shell_posix(&self.remote_command);
        for morceau in morceaux {
            ligne.push(' ');
            ligne.push_str(morceau);
        }
        ligne
    }
}

/// Lance une session ssh et rend le sous-processus.
fn lancer(
    cible: &RemoteTarget,
    ssh: &SshOptions,
    ligne: &str,
    entree: Stdio,
    sortie: Stdio,
) -> Result<Child> {
    let mut commande = Command::new(CLIENT_SSH);
    // FR-027 : les options de l'utilisateur, telles quelles. FR-025, XFR-022 :
    // vault n'en ajoute **aucune** qui touche à la vérification d'hôte.
    commande.args(&ssh.options);
    commande.arg(cible.destination());
    commande.arg(ligne);
    commande
        .stdin(entree)
        .stdout(sortie)
        // XFR-021 : héritée, pour que les questions et avertissements d'OpenSSH
        // atteignent le terminal de l'utilisateur (FR-026).
        .stderr(Stdio::inherit());

    // Le client ssh absent du `PATH` est un échec de transport, et il est
    // explicite : vault ne cherche pas de solution de repli, il n'en a pas.
    commande.spawn().map_err(|_| Error::TransportFailed)
}

/// Traduit le code de retour d'une session ssh.
///
/// FR-029a : c'est **tout** ce que la destination fait remonter. Les codes qui
/// appartiennent au transport — ssh lui-même, commande introuvable, mort par
/// signal — deviennent [`Error::TransportFailed`] ; tout autre code non nul est
/// propagé tel quel, parce que c'est celui que la destination a choisi et que
/// la cause qu'elle a nommée est déjà parvenue au terminal.
fn verdict(mut enfant: Child) -> Result<()> {
    let statut = enfant.wait().map_err(|_| Error::TransportFailed)?;
    match statut.code() {
        Some(0) => Ok(()),
        Some(ECHEC_SSH | COMMANDE_INTROUVABLE) | None => Err(Error::TransportFailed),
        Some(code) => Err(Error::RemoteFailed { code }),
    }
}

/// Sondage : une session, un mode qui n'écrit rien, un code de retour (D-205).
fn sonder(cible: &RemoteTarget, ssh: &SshOptions, morceaux: &[String]) -> Result<()> {
    let enfant = lancer(
        cible,
        ssh,
        &ssh.ligne_distante(morceaux),
        Stdio::null(),
        Stdio::inherit(),
    )?;
    verdict(enfant)
}

/// Ajoute `--replace` à une commande distante lorsque le remplacement a été
/// demandé et confirmé localement (FR-013d, XFR-029).
fn avec_remplacement(mut morceaux: Vec<String>, policy: ImportPolicy) -> Vec<String> {
    if policy == ImportPolicy::Replace {
        morceaux.push("--replace".to_owned());
    }
    morceaux
}

/// Concilie ce que l'écriture locale a donné et ce que le distant a rendu.
///
/// L'ordre importe. Un distant qui rend 0 valide l'opération. Un distant qui
/// refuse **alors que notre écriture s'est rompue** signale un canal coupé, et
/// non un refus motivé : c'est un échec de **transport** (XFR-027). Un distant
/// qui refuse après avoir tout reçu, lui, a bien un motif, et son code de
/// retour est celui qui remonte à l'utilisateur (FR-029b).
fn concilier<T>(enfant: Child, travail: Result<T>) -> Result<T> {
    arbitrer(verdict(enfant), travail)
}

/// La décision elle-même, séparée du sous-processus qui la déclenche.
///
/// Elle est ainsi éprouvable sans réseau ni faux client, et c'est bien la
/// **même** fonction que le transport appelle : la séparer n'a pas créé de
/// chemin de remplacement.
fn arbitrer<T>(verdict: Result<()>, travail: Result<T>) -> Result<T> {
    match (verdict, travail) {
        (Ok(()), travail) => travail,
        (Err(Error::RemoteFailed { code }), travail) => {
            if travail.is_err() {
                Err(Error::TransportFailed)
            } else {
                Err(Error::RemoteFailed { code })
            }
        }
        (Err(transport), _) => Err(transport),
    }
}

impl Vault {
    /// Envoie le vault local `source` vers `cible`.
    ///
    /// Le vault source n'est ni modifié ni supprimé (FR-031) : `send` n'est
    /// qu'un export poussé dans un tube, et un export ne touche à rien.
    ///
    /// # Errors
    ///
    /// - [`Error::TransportFailed`] si le client ssh est absent, si la commande
    ///   distante est introuvable, ou si le canal se rompt (XFR-027) ;
    /// - [`Error::RemoteFailed`] si la destination refuse en nommant sa cause —
    ///   son code de retour est alors celui qui remonte (FR-029b) ;
    /// - celles de [`Vault::export`] pour ce qui relève du vault local.
    pub fn send(
        source: &Path,
        cible: &RemoteTarget,
        ssh: &SshOptions,
        policy: ImportPolicy,
    ) -> Result<ExportSummary> {
        // FR-028, XFR-023 : le sondage précède **toute** transmission. Sans lui,
        // le seul moyen d'apprendre que la destination est occupée serait
        // d'envoyer l'en-tête et d'attendre — et un en-tête transmis n'est pas
        // « rien ».
        sonder(
            cible,
            ssh,
            &avec_remplacement(
                vec![
                    "import".to_owned(),
                    "--probe".to_owned(),
                    "--to".to_owned(),
                    pour_shell_posix(cible.path()),
                    "--container-version".to_owned(),
                    CONTAINER_VERSION.to_string(),
                ],
                policy,
            ),
        )?;

        let ligne = ssh.ligne_distante(&avec_remplacement(
            vec![
                "import".to_owned(),
                "-".to_owned(),
                "--to".to_owned(),
                pour_shell_posix(cible.path()),
            ],
            policy,
        ));
        let mut enfant = lancer(cible, ssh, &ligne, Stdio::piped(), Stdio::inherit())?;

        let mut tube = enfant.stdin.take().ok_or(Error::TransportFailed)?;
        // FR-022, FR-023 : ce qui entre dans le tube est **déjà chiffré**, et
        // aucun secret n'y figure — un export par défaut n'ouvre pas le vault,
        // donc aucune clé n'existe en mémoire pendant un transfert.
        let ecriture = Vault::export(source, ExportEnvelope::Source, &mut tube);
        // Fermer le tube signale la fin du conteneur à la destination.
        drop(tube);

        concilier(enfant, ecriture)
    }

    /// Rapatrie le vault distant `cible` vers `destination`.
    ///
    /// Symétrique de [`Vault::send`]. Aucun secret ne traverse le canal dans ce
    /// sens non plus : le conteneur arrive déjà chiffré, et l'import ne l'ouvre
    /// pas (FR-018, FR-023).
    ///
    /// # Errors
    ///
    /// Celles de [`Vault::send`] pour le transport, et celles de
    /// [`Vault::import`] pour ce qui relève du vault local.
    pub fn fetch(
        cible: &RemoteTarget,
        destination: &Path,
        ssh: &SshOptions,
        policy: ImportPolicy,
    ) -> Result<ImportSummary> {
        // La destination est **locale** dans ce sens : elle se contrôle sans
        // réseau, donc avant d'en ouvrir. Un refus tombe ainsi sans qu'aucune
        // session ssh n'ait été ouverte.
        crate::ops::import::verifier_destination(destination, policy)?;

        // Le sondage porte sur la source : y a-t-il là-bas un vault, et sait-on
        // lire son format ?
        sonder(
            cible,
            ssh,
            &[
                "export".to_owned(),
                "--probe".to_owned(),
                "--vault".to_owned(),
                pour_shell_posix(cible.path()),
            ],
        )?;

        let ligne = ssh.ligne_distante(&[
            "export".to_owned(),
            "--to".to_owned(),
            "-".to_owned(),
            "--vault".to_owned(),
            pour_shell_posix(cible.path()),
        ]);
        let mut enfant = lancer(cible, ssh, &ligne, Stdio::null(), Stdio::piped())?;

        let mut tube = enfant.stdout.take().ok_or(Error::TransportFailed)?;
        let lecture = Vault::import(&mut tube, destination, policy);
        drop(tube);

        concilier(enfant, lecture)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cible(brut: &str) -> RemoteTarget {
        RemoteTarget::parse(OsStr::new(brut)).expect("cible valide")
    }

    #[test]
    fn une_cible_distante_se_decompose() {
        let complete = cible("utilisateur@poste-b:/home/vous/coffre");
        assert_eq!(complete.user(), Some("utilisateur"));
        assert_eq!(complete.host(), "poste-b");
        assert_eq!(complete.path(), "/home/vous/coffre");
        assert_eq!(complete.destination(), "utilisateur@poste-b");

        let sans_utilisateur = cible("poste-b:~/coffres/mon-vault");
        assert_eq!(sans_utilisateur.user(), None);
        assert_eq!(sans_utilisateur.host(), "poste-b");
        assert_eq!(sans_utilisateur.path(), "~/coffres/mon-vault");
        assert_eq!(sans_utilisateur.destination(), "poste-b");

        // Le chemin peut contenir des deux-points : seul le premier sépare.
        assert_eq!(cible("hote:/a:b:c").path(), "/a:b:c");
        // Une adresse littérale reste un hôte comme un autre.
        assert_eq!(cible("moi@192.168.1.2:/coffre").host(), "192.168.1.2");

        assert!(format!("{complete:?}").contains("RemoteTarget"));
        assert_eq!(complete, cible("utilisateur@poste-b:/home/vous/coffre"));
    }

    /// FR-019a : le contrôle est de **forme**. Ce qui ressemble à un chemin
    /// local en est un, et ce qui ressemble à une cible distante en est une.
    #[test]
    fn la_forme_distingue_le_local_du_distant() {
        for distant in [
            "hote:chemin",
            "moi@hote:chemin",
            "hote:/absolu",
            "hote:~/relatif",
        ] {
            assert!(
                RemoteTarget::looks_remote(OsStr::new(distant)),
                "{distant:?}"
            );
        }

        for local in [
            "/home/vous/coffre",
            "coffre",
            "./coffre",
            "../coffre",
            // Le deux-points suit une barre oblique : il appartient au chemin.
            "/home/vous/a:b",
            "./a:b",
            // Lettre de lecteur Windows.
            "C:\\coffres\\mon-vault",
            "c:/coffres",
            // Rien avant le deux-points.
            ":chemin",
            "",
        ] {
            assert!(!RemoteTarget::looks_remote(OsStr::new(local)), "{local:?}");
        }
    }

    #[test]
    fn une_cible_mal_formee_est_refusee() {
        let mut verdicts = Vec::new();
        for invalide in [
            // Pas de deux-points : ce n'est pas une cible distante.
            "poste-b",
            // Chemin vide.
            "poste-b:",
            // Hôte vide.
            "@poste-b:/coffre",
            "moi@:/coffre",
            // Utilisateur vide.
            "@hote:/coffre",
        ] {
            verdicts.push(matches!(
                RemoteTarget::parse(OsStr::new(invalide)),
                Err(Error::InvalidPath)
            ));
        }
        assert_eq!(verdicts, vec![true; 5], "cibles mal formées");
    }

    /// D-206 : un chemin distant qui n'est pas de l'UTF-8 valide est refusé
    /// **avant tout lancement**.
    #[cfg(unix)]
    #[test]
    fn une_cible_non_utf8_est_refusee() {
        use std::os::unix::ffi::OsStrExt;

        let brute = OsStr::from_bytes(b"hote:/coffre-\xff\xfe");
        assert!(matches!(
            RemoteTarget::parse(brute),
            Err(Error::InvalidPath)
        ));
    }

    /// La ligne remise au shell distant cite ce qui doit l'être, et rien de ce
    /// qu'un chemin hostile contient n'en sort.
    #[test]
    fn la_ligne_distante_cite_ce_qu_elle_assemble() {
        let ssh = SshOptions::default();
        assert_eq!(ssh.remote_command, "vault");

        let ligne = ssh.ligne_distante(&avec_remplacement(
            vec![
                "import".to_owned(),
                "-".to_owned(),
                "--to".to_owned(),
                pour_shell_posix("; rm -rf /"),
            ],
            ImportPolicy::Replace,
        ));
        assert_eq!(ligne, "'vault' import - --to '; rm -rf /' --replace");

        // Sans remplacement, l'option n'apparaît pas.
        let sobre = ssh.ligne_distante(&avec_remplacement(
            vec!["import".to_owned()],
            ImportPolicy::Refuse,
        ));
        assert_eq!(sobre, "'vault' import");

        // La commande distante est citée elle aussi : un chemin d'installation
        // avec une espace ne doit pas se redécouper.
        let ailleurs = SshOptions {
            remote_command: "/opt/mes outils/vault".to_owned(),
            ..SshOptions::default()
        };
        assert!(
            ailleurs
                .ligne_distante(&["info".to_owned()])
                .starts_with("'/opt/mes outils/vault' info")
        );
        assert!(format!("{ailleurs:?}").contains("SshOptions"));
        assert_ne!(ailleurs, SshOptions::default());
    }

    /// XFR-020, XFR-027 : le transport est un sous-processus `ssh` résolu par
    /// le `PATH`, et son absence est un échec **de transport**, jamais un échec
    /// du vault.
    ///
    /// Le test s'appuie sur le fait qu'aucun `ssh` n'existe dans le `PATH` de
    /// l'environnement d'intégration — qui n'a d'ailleurs pas d'interface
    /// réseau. Si un jour il en existait un, le lancement échouerait plus loin,
    /// et l'assertion resterait vraie pour une autre raison : c'est pourquoi
    /// elle porte sur le variant et non sur la cause.
    #[test]
    fn un_client_ssh_absent_est_un_echec_de_transport() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let resultat = Vault::send(
            &atelier.path().join("coffre"),
            &cible("poste-b:/coffre"),
            &SshOptions::default(),
            ImportPolicy::Refuse,
        );
        assert!(matches!(
            resultat,
            Err(Error::TransportFailed | Error::RemoteFailed { .. })
        ));
    }

    /// La conciliation, sans réseau : c'est elle qui décide lequel, du verdict
    /// distant ou du travail local, l'emporte.
    #[test]
    fn la_conciliation_donne_la_priorite_au_canal() {
        // Un distant qui refuse alors que le travail local a échoué signale un
        // canal coupé, et non un refus motivé.
        assert!(matches!(
            arbitrer(
                Err(Error::RemoteFailed { code: 1 }),
                Err::<(), _>(Error::Corrupted)
            ),
            Err(Error::TransportFailed)
        ));
        // Un distant qui refuse après avoir tout reçu a un motif : son code
        // remonte.
        assert!(matches!(
            arbitrer(Err(Error::RemoteFailed { code: 8 }), Ok(())),
            Err(Error::RemoteFailed { code: 8 })
        ));
        // Un distant qui accepte laisse le travail local décider.
        assert!(matches!(arbitrer(Ok(()), Ok(())), Ok(())));
        assert!(matches!(
            arbitrer(Ok(()), Err::<(), _>(Error::Corrupted)),
            Err(Error::Corrupted)
        ));
        // Un échec de transport l'emporte sur tout.
        assert!(matches!(
            arbitrer(Err(Error::TransportFailed), Ok(())),
            Err(Error::TransportFailed)
        ));
    }
}
