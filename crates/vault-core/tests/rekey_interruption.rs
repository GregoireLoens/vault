//! Interruption pendant le changement de passphrase (T061, FR-035, C-022).
//!
//! Après une coupure en cours d'opération, le vault doit s'ouvrir avec
//! l'ancienne **ou** avec la nouvelle passphrase, jamais avec aucune. C'est la
//! seule exigence de la user story 4 qu'on ne peut pas prouver en appelant une
//! fonction : elle porte sur ce qui reste quand le processus meurt.
//!
//! Le test lance donc un processus auxiliaire qui change la passphrase **en
//! boucle**, alternant entre deux, et le **tue**. Le tuer plutôt que lui
//! demander de s'arrêter est le point : un signal de mort immédiate ne laisse
//! exécuter aucun code de nettoyage, ce qui est exactement la coupure
//! d'alimentation que FR-035 envisage. L'opération est ensuite jugée sur son
//! seul résultat observable — le vault s'ouvre-t-il encore ?
//!
//! Ce test ne peut pas échouer par malchance : si l'enfant est tué avant
//! d'avoir rien fait, l'ancienne passphrase ouvre, et c'est un succès. Il
//! n'échoue que si un état intermédiaire réel existe, où **aucune** des deux
//! n'ouvre.
//!
//! # Pourquoi ce test vit seul dans son fichier
//!
//! Il ne peut pas cohabiter avec d'autres tests dans le même binaire, et la
//! raison tient à une propriété de `flock` qui mérite d'être connue :
//! **un verrou `flock` appartient à la description de fichier ouverte, et
//! `fork` la partage.** Un processus qui se duplique pendant qu'un de ses fils
//! d'exécution détient le verrou d'un vault en lègue une copie à l'enfant, et
//! ce verrou reste pris tant que l'enfant n'a pas fait son `exec` — les
//! descripteurs sont bien marqués « à fermer sur exec », mais entre le `fork`
//! et l'`exec` la fenêtre est réelle, et la charge de la machine l'élargit.
//!
//! Ce fichier lance huit processus. Voisins d'autres tests qui créent des
//! vaults au même moment, ils leur volaient par intermittence leur verrou, et
//! la suite échouait en `AlreadyInUse` sur des vaults sans aucun rapport. Isolé
//! dans son binaire, il ne duplique le processus qu'à des instants où aucun
//! autre vault n'est ouvert.
//!
//! La propriété n'est pas un défaut du vault : le binaire `vault` ne se
//! duplique jamais. Elle concerne une application tierce qui embarquerait
//! `vault-core` **et** ferait `fork`, et le module `fs::lock` de la
//! bibliothèque la consigne à ce titre.

use std::path::{Path, PathBuf};
use std::time::Duration;

use vault_core::{KdfParams, SecretString, Vault};

/// Rôle du processus auxiliaire, transmis par l'environnement.
const ROLE: &str = "VAULT_TEST_REKEY_ROLE";
/// Emplacement du vault, transmis par l'environnement.
const COFFRE: &str = "VAULT_TEST_REKEY_COFFRE";

const ANCIENNE: &str = "passphrase de test bien assez longue";
const NOUVELLE: &str = "une toute autre passphrase, tout aussi longue";

fn params() -> KdfParams {
    KdfParams::new(64, 1, 1).expect("paramètres valides")
}

fn secret(texte: &str) -> SecretString {
    SecretString::from(texte.to_owned())
}

fn ouvre_avec(coffre: &Path, passphrase: &str) -> bool {
    Vault::open(coffre)
        .expect("ouvrable")
        .unlock(secret(passphrase))
        .is_ok()
}

/// Point d'entrée du processus auxiliaire : change la passphrase en boucle,
/// alternant entre les deux, jusqu'à ce qu'on le tue.
#[test]
fn processus_auxiliaire() {
    if std::env::var(ROLE).is_err() {
        return;
    }
    let coffre = PathBuf::from(std::env::var(COFFRE).expect("emplacement transmis"));

    loop {
        let (courante, suivante) = if ouvre_avec(&coffre, ANCIENNE) {
            (ANCIENNE, NOUVELLE)
        } else {
            (NOUVELLE, ANCIENNE)
        };

        let mut session = Vault::open(&coffre)
            .expect("ouvrable")
            .unlock(secret(courante))
            .expect("déverrouillable");
        session
            .change_passphrase(secret(suivante), None)
            .expect("changeable");
        session.lock();
    }
}

/// FR-035, C-022 : **tué** en pleine opération, le vault reste ouvrable avec
/// l'ancienne ou la nouvelle passphrase — jamais avec aucune.
///
/// Le délai varie d'une répétition à l'autre pour que la coupure tombe à des
/// moments différents de la séquence dérivation / écriture / remplacement.
#[test]
fn une_interruption_laisse_toujours_le_vault_ouvrable() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = atelier.path().join("coffre");
    Vault::create(&coffre, secret(ANCIENNE), params())
        .expect("créable")
        .lock();

    let mut verdicts = Vec::new();
    for repetition in 0..8u64 {
        let mut enfant =
            std::process::Command::new(std::env::current_exe().expect("binaire de test"))
                .args(["processus_auxiliaire", "--exact", "--nocapture"])
                .env(ROLE, "boucler")
                .env(COFFRE, &coffre)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("processus lançable");

        // Des délais irréguliers plutôt qu'un pas régulier : un pas régulier
        // risquerait de tomber toujours au même endroit de la boucle.
        std::thread::sleep(Duration::from_millis(40 + repetition * 17));
        enfant.kill().expect("tuable");
        enfant.wait().expect("terminable");

        // Le verrou est rendu par la mort du processus, et l'une des deux
        // passphrases ouvre.
        verdicts.push(ouvre_avec(&coffre, ANCIENNE) || ouvre_avec(&coffre, NOUVELLE));
    }

    assert_eq!(verdicts, vec![true; 8]);
}
