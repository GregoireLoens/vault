//! Corpus permanent d'entrées hostiles (T022, FR-011).
//!
//! Toute entrée ayant un jour révélé un défaut vit **ici**, et y est rejouée
//! par la suite ordinaire — sur les trois plateformes, par quiconque lance
//! `cargo test`, y compris ceux qui ne lanceront jamais d'exploration.
//!
//! Sans ce fichier, une découverte faite par une campagne guidée serait perdue
//! au premier changement d'outil : le défaut serait corrigé, l'entrée qui
//! l'avait révélé oubliée, et rien n'empêcherait la régression. C'est le seul
//! lien contractuel entre l'exploration hors ligne et la porte bloquante
//! (VER-004f).
//!
//! # Comment ce corpus s'enrichit
//!
//! Une entrée y est versée **avant même que le défaut soit corrigé**. L'ordre
//! importe : versée après, elle risque de ne jamais l'être, et l'on ne s'en
//! aperçoit que le jour où la régression revient.
//!
//! # État actuel
//!
//! Aucune campagne n'a encore révélé de défaut. Le corpus est donc amorcé avec
//! les entrées qui, **dans l'histoire de ce projet**, ont réellement compté :
//! elles sont issues des cas limites que le développement a rencontrés, et
//! toutes doivent produire un refus explicite. Un corpus vide serait un fichier
//! qui ne prouve rien ; celui-ci vérifie déjà quelque chose.

use std::path::Path;

use vault_core::{AddMode, KdfParams, OnConflict, SecretString, Vault, VaultPath};

const PASSPHRASE: &str = "passphrase de test bien assez longue";

fn params() -> KdfParams {
    KdfParams::new(64, 1, 1).expect("paramètres valides")
}

fn secret() -> SecretString {
    SecretString::from(PASSPHRASE.to_owned())
}

fn coffre_peuple(atelier: &Path) -> std::path::PathBuf {
    let coffre = atelier.join("coffre");
    let source = atelier.join("note.txt");
    std::fs::write(&source, b"contenu").expect("écrivable");

    let mut vault = Vault::create(&coffre, secret(), params()).expect("créable");
    vault
        .add_file(
            &source,
            &VaultPath::from_components([b"note.txt".to_vec()]).expect("valide"),
            AddMode::Copy,
            OnConflict::Fail,
        )
        .expect("ajoutable");
    vault.lock();
    coffre
}

/// En-têtes ayant compté. Chacun doit produire un refus explicite, jamais une
/// panique ni une lecture approximative.
const EN_TETES: [(&str, &[u8]); 4] = [
    ("vide", b""),
    ("texte quelconque", b"ceci n'est pas un en-tete"),
    // Un octet initial de CBOR annonçant une carte, suivi de rien : le décodeur
    // doit s'arrêter sur la longueur, pas sur ce qu'elle annonce.
    ("carte CBOR tronquée d'emblée", &[0xa9]),
    // Une chaîne CBOR annonçant une longueur démesurée. Une implémentation qui
    // réserverait d'après l'annonce serait éliminée par le noyau avant d'avoir
    // pu refuser.
    (
        "longueur annoncée démesurée",
        &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    ),
];

/// Un en-tête hostile ne fait jamais autre chose que refuser.
#[test]
fn les_en_tetes_du_corpus_sont_refuses() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_peuple(atelier.path());
    let en_tete = coffre.join("header");

    let mut fautifs = Vec::new();
    for (intitule, octets) in EN_TETES {
        std::fs::write(&en_tete, octets).expect("écrivable");
        if Vault::open(&coffre).is_ok() {
            fautifs.push(intitule);
        }
    }

    assert_eq!(fautifs, Vec::<&str>::new());
}

/// Les noms de fichiers de `objects/` sont fournis par le système de fichiers,
/// donc par quiconque écrit dans le répertoire du vault.
///
/// Le cas multi-octets a compté : découper une chaîne hexadécimale sur des
/// frontières d'octets, et non de caractères, fait paniquer un découpage naïf.
/// Il est ici pour ne jamais revenir.
#[test]
fn les_noms_de_blob_du_corpus_ne_font_pas_paniquer() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_peuple(atelier.path());
    let objets = coffre.join("objects");

    for nom in [
        String::new(),
        "court".to_owned(),
        "z".repeat(64),
        "0".repeat(63),
        // Multi-octets : `é` occupe deux octets pour un seul caractère.
        format!("é{}", "0".repeat(61)),
        "0".repeat(65),
    ] {
        if !nom.is_empty() {
            std::fs::write(objets.join(&nom), b"dechet").expect("écrivable");
        }
    }

    // Le déverrouillage balaie les orphelins : il traverse tous ces noms.
    let session = Vault::open(&coffre)
        .expect("ouvrable")
        .unlock(secret())
        .expect("déverrouillable");
    assert_eq!(session.list(None).len(), 1, "le contenu est intact");
}

/// Index tronqués à des positions qui ont compté : juste en deçà du minimum,
/// et exactement au nonce.
#[test]
fn les_index_tronques_du_corpus_sont_refuses() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_peuple(atelier.path());
    let index = coffre.join("index");
    let original = std::fs::read(&index).expect("lisible");

    let mut fautifs = Vec::new();
    for position in [0, 1, 23, 24, 39] {
        std::fs::write(&index, &original[..position.min(original.len())]).expect("écrivable");
        if Vault::open(&coffre)
            .expect("ouvrable")
            .unlock(secret())
            .is_ok()
        {
            fautifs.push(position);
        }
    }

    std::fs::write(&index, &original).expect("écrivable");
    assert_eq!(fautifs, Vec::<usize>::new());
}

/// Chemins ayant compté : ceux que VR-I4 doit refuser, et le nom multi-octets
/// qui doit être accepté tel quel.
#[test]
fn les_chemins_du_corpus_suivent_les_regles() {
    let refuses: Vec<bool> = [
        vec![b"".to_vec()],
        vec![b".".to_vec()],
        vec![b"..".to_vec()],
        vec![b"a/b".to_vec()],
        vec![b"a\\b".to_vec()],
        vec![vec![b'a', 0, b'b']],
    ]
    .into_iter()
    .map(|composants| VaultPath::from_components(composants).is_err())
    .collect();
    assert_eq!(refuses, vec![true; 6]);

    // Accepté : des octets qui ne forment pas de l'UTF-8 valide restent un nom
    // légitime dans le vault (VR-I1).
    let hostile = VaultPath::from_components([vec![0xff, 0xfe, b'x']]).expect("accepté");
    assert_eq!(hostile.file_name(), Some(&[0xff, 0xfe, b'x'][..]));
}
