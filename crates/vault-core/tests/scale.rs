//! Volume et débit (T067, SC-009).
//!
//! SC-009 : « un utilisateur retrouve un fichier précis dans un vault contenant
//! 10 000 entrées en moins de 30 secondes ». Trente secondes est une borne
//! généreuse, et c'est voulu — elle décrit ce qu'un utilisateur tolère, pas ce
//! que la machine sait faire. Un test qui la frôlerait signalerait un problème
//! bien avant de devenir rouge.
//!
//! Ce qui est mesuré est le **geste complet**, tel qu'un utilisateur le vit :
//! ouvrir le vault, le déverrouiller — donc dériver la clé, lire et déchiffrer
//! l'index entier — puis retrouver l'entrée et son contenu. Chronométrer la
//! seule recherche dans un index déjà en mémoire mesurerait une recherche
//! dichotomique, ce qui n'apprendrait rien : le coût réel est celui de l'index,
//! et il croît avec le nombre d'entrées.
//!
//! # Ce que ce test ne mesure pas
//!
//! La **construction** du vault n'entre pas dans le chronomètre. Déposer
//! 10 000 fichiers est une opération que l'utilisateur étale sur des mois ; la
//! comprimer en quelques secondes de test dirait quelque chose du disque de
//! l'exécuteur, pas de l'expérience visée par SC-009.
//!
//! Le prix à payer est connu et assumé : bâtir le vault occupe l'essentiel de
//! la minute que dure cette suite, dix mille écritures de blob étant dix mille
//! synchronisations sur le disque. C'est le coût d'un test fidèle à l'énoncé —
//! ramener le corpus à mille entrées le rendrait six fois plus rapide et ne
//! prouverait plus SC-009. La borne des trente minutes de l'intégration
//! continue laisse la marge nécessaire, y compris sur les exécuteurs dont le
//! système de fichiers est plus lent.
//!
//! Les paramètres de dérivation sont minimaux, ici encore. Des paramètres
//! réalistes ajouteraient une demi-seconde constante, la même pour un vault
//! d'une entrée que pour un vault de dix mille : ils déplaceraient la mesure
//! sans rien révéler de ce que ce test cherche, à savoir comment le coût varie
//! avec le **nombre d'entrées**.

use std::time::{Duration, Instant};

use vault_core::{AddMode, KdfParams, OnConflict, SecretString, Vault, VaultPath};

/// Nombre d'entrées exigé par SC-009.
const ENTREES: usize = 10_000;

/// Borne de SC-009.
const BORNE: Duration = Duration::from_secs(30);

const PASSPHRASE: &str = "passphrase de test bien assez longue";

fn params() -> KdfParams {
    KdfParams::new(64, 1, 1).expect("paramètres valides")
}

fn secret() -> SecretString {
    SecretString::from(PASSPHRASE.to_owned())
}

/// Nom du `numero`-ième fichier du corpus.
///
/// Les noms sont répartis dans cent dossiers : un vault de dix mille entrées
/// dans un seul dossier ne ressemble à rien de réel, et l'arborescence est
/// justement ce qui allonge les chemins de l'index.
fn nom(numero: usize) -> String {
    format!("dossier-{:03}/fichier-{numero:05}.txt", numero % 100)
}

fn chemin(nom: &str) -> VaultPath {
    VaultPath::from_components(nom.split('/').map(|c| c.as_bytes().to_vec()))
        .expect("chemin valide")
}

/// SC-009 : retrouver une entrée parmi 10 000, vault fermé au départ.
#[test]
fn retrouver_une_entree_parmi_dix_mille() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let source = atelier.path().join("source");
    for centaine in 0..100 {
        std::fs::create_dir_all(source.join(format!("dossier-{centaine:03}"))).expect("créable");
    }
    for numero in 0..ENTREES {
        // Un octet par fichier : ce test mesure le nombre d'entrées, pas le
        // débit de chiffrement, que `roundtrip.rs` couvre déjà.
        std::fs::write(
            source.join(nom(numero)),
            [u8::try_from(numero % 251).expect("reste inférieur à 251")],
        )
        .expect("écrivable");
    }

    let coffre = atelier.path().join("coffre");
    let mut vault = Vault::create(&coffre, secret(), params()).expect("créable");
    vault
        .add_dir(
            &source,
            &VaultPath::root(),
            AddMode::Copy,
            OnConflict::Fail,
            &mut |_| {},
        )
        .expect("ajoutable");
    // Les dix mille fichiers, plus les cent dossiers qui les portent.
    assert_eq!(vault.list(None).len(), ENTREES + 100);
    vault.lock();

    // Le chronomètre ne démarre qu'ici : le vault est fermé, comme il l'est
    // quand l'utilisateur cherche quelque chose.
    let vise = chemin(&nom(7_777));
    let sortie = atelier.path().join("sortie");
    std::fs::create_dir(&sortie).expect("créable");

    let depart = Instant::now();
    let session = Vault::open(&coffre)
        .expect("ouvrable")
        .unlock(secret())
        .expect("déverrouillable");
    let entree = session.stat(&vise).expect("présente");
    session
        .extract(&vise, &sortie, OnConflict::Fail)
        .expect("extractible");
    let ecoule = depart.elapsed();

    assert_eq!(entree.size, Some(1));
    assert_eq!(
        std::fs::read(sortie.join("fichier-07777.txt")).expect("lisible"),
        [u8::try_from(7_777_usize % 251).expect("reste inférieur à 251")]
    );
    assert!(
        ecoule < BORNE,
        "SC-009 : {ecoule:?} pour retrouver une entrée parmi {ENTREES}"
    );
}

/// Le listage d'un sous-dossier ne parcourt pas les dix mille entrées pour
/// l'utilisateur : il en rend cent, et vite.
#[test]
fn lister_un_sous_dossier_reste_immediat() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let source = atelier.path().join("source");
    std::fs::create_dir_all(source.join("dossier-042")).expect("créable");
    for numero in (42..ENTREES).step_by(100) {
        std::fs::write(source.join(nom(numero)), b"x").expect("écrivable");
    }

    let coffre = atelier.path().join("coffre");
    let mut vault = Vault::create(&coffre, secret(), params()).expect("créable");
    vault
        .add_dir(
            &source,
            &VaultPath::root(),
            AddMode::Copy,
            OnConflict::Fail,
            &mut |_| {},
        )
        .expect("ajoutable");

    let depart = Instant::now();
    let listees = vault.list(Some(&chemin("dossier-042")));
    let ecoule = depart.elapsed();

    // Les cent fichiers, plus l'entrée du dossier lui-même.
    assert_eq!(listees.len(), 101);
    assert!(ecoule < BORNE, "{ecoule:?}");
}
