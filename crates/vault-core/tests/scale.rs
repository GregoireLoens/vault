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

use std::io::{Read as _, Write as _};
use std::time::{Duration, Instant};

use vault_core::{AddMode, ExportEnvelope, KdfParams, OnConflict, SecretString, Vault, VaultPath};

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

/// SC-002 : un export ne coûte pas plus de 20 % de plus qu'une copie.
///
/// # Ce que cette mesure établit
///
/// SC-002 n'est pas une exigence de rapidité, c'est une exigence de **nature**.
/// Un export qui déchiffrerait le contenu pour le rechiffrer paierait une
/// dérivation de clé par blob et deux passes AEAD sur chaque octet : le coût
/// s'en verrait, et de très loin. Rester dans les 20 % d'une copie d'octets
/// établit qu'il ne se passe rien de tel — que les blobs sont recopiés tels
/// qu'ils sont sur le disque, ce que FR-002 exige et que
/// `no_plaintext.rs` vérifie par ailleurs sur le contenu produit.
///
/// # Pourquoi la référence est une copie *octet par octet*
///
/// `std::fs::copy` n'est pas la bonne référence, et le choix mérite d'être
/// écrit. Sur btrfs, XFS ou APFS, elle délègue au noyau, qui peut se contenter
/// de partager les extents sans déplacer un seul octet : la copie devient
/// quasi instantanée et le rapport n'a plus de sens — il mesurerait l'absence
/// de travail, pas le travail. La référence retenue lit et réécrit réellement
/// chaque octet, ce qui est exactement ce que fait l'export. C'est la seule
/// comparaison qui compare deux fois la même chose.
///
/// # Pourquoi le minimum de plusieurs passages
///
/// Un exécuteur partagé subit des voisins. La moyenne les inclut, le minimum
/// les écarte : de deux passages sur les mêmes octets, le plus rapide est
/// celui qui a le moins attendu autre chose. Un tour de chauffe précède les
/// mesures pour que le cache de pages serve les deux camps également.
#[test]
fn un_export_ne_coute_pas_plus_qu_une_copie() {
    /// Assez d'octets pour que le chiffrement se verrait, assez peu pour que
    /// la suite reste courte.
    const FICHIERS: usize = 200;
    const TAILLE: usize = 64 * 1024;
    /// Le tampon de la copie de référence — la taille de morceau du format,
    /// et non une valeur choisie pour arranger le rapport.
    const MORCEAU: usize = 64 * 1024;
    /// Trois mesures, dont on garde la meilleure de chaque camp.
    const PASSAGES: usize = 3;
    /// La marge de SC-002.
    const MARGE: f64 = 1.20;

    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let source = atelier.path().join("source");
    std::fs::create_dir(&source).expect("créable");
    for numero in 0..FICHIERS {
        let motif = u8::try_from(numero % 251).expect("reste inférieur à 251");
        std::fs::write(
            source.join(format!("f-{numero:04}.bin")),
            vec![motif; TAILLE],
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
    vault.lock();

    // Une copie du répertoire, octet par octet — voir le commentaire de tête.
    let copier = |vers: &std::path::Path| -> std::io::Result<()> {
        for entree in walk(&coffre) {
            let relatif = entree.strip_prefix(&coffre).expect("sous le coffre");
            if let Some(parent) = vers.join(relatif).parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut lu = std::fs::File::open(&entree)?;
            let mut ecrit = std::fs::File::create(vers.join(relatif))?;
            // Écrit à la main, et non par `std::io::copy` : celle-ci se
            // spécialise en `copy_file_range`, qui délègue au noyau et peut ne
            // déplacer aucun octet. Voir le commentaire de tête.
            let mut tampon = vec![0_u8; MORCEAU];
            loop {
                let lus = lu.read(&mut tampon)?;
                if lus == 0 {
                    break;
                }
                ecrit.write_all(&tampon[..lus])?;
            }
            ecrit.flush()?;
        }
        Ok(())
    };

    let exporter = |vers: &std::path::Path| -> vault_core::Result<()> {
        let mut sortie = std::io::BufWriter::new(std::fs::File::create(vers)?);
        Vault::export(&coffre, ExportEnvelope::Source, &mut sortie)?;
        sortie.flush()?;
        Ok(())
    };

    // Tour de chauffe : le cache de pages doit servir les deux camps.
    let chauffe = atelier.path().join("chauffe");
    copier(&chauffe).expect("copiable");
    exporter(&atelier.path().join("chauffe.vaultx")).expect("exportable");

    let mut copie = Duration::MAX;
    let mut export = Duration::MAX;
    for passage in 0..PASSAGES {
        let vers = atelier.path().join(format!("copie-{passage}"));
        let depart = Instant::now();
        copier(&vers).expect("copiable");
        copie = copie.min(depart.elapsed());
        std::fs::remove_dir_all(&vers).expect("supprimable");

        let vers = atelier.path().join(format!("export-{passage}.vaultx"));
        let depart = Instant::now();
        exporter(&vers).expect("exportable");
        export = export.min(depart.elapsed());
        std::fs::remove_file(&vers).expect("supprimable");
    }

    let rapport = export.as_secs_f64() / copie.as_secs_f64();
    assert!(
        rapport <= MARGE,
        "SC-002 : export {export:?} contre copie {copie:?}, soit {rapport:.2}× — \
au-delà de {MARGE:.2}×, quelque chose déchiffre"
    );
}

/// Tous les fichiers du répertoire d'un vault, dossier `blobs` compris.
fn walk(racine: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut trouves = Vec::new();
    let mut a_visiter = vec![racine.to_path_buf()];
    while let Some(dossier) = a_visiter.pop() {
        for entree in std::fs::read_dir(&dossier).expect("lisible") {
            let chemin = entree.expect("lisible").path();
            if chemin.is_dir() {
                a_visiter.push(chemin);
            } else {
                trouves.push(chemin);
            }
        }
    }
    trouves
}
