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

// ---------------------------------------------------------------------------
// Le conteneur d'export — T013, cinquième surface de décodage
// ---------------------------------------------------------------------------
//
// Le conteneur rejoint le corpus au même titre que l'en-tête, l'index, les
// chemins et les blobs. Les entrées ci-dessous sont celles que le développement
// de la feature 003 a réellement rencontrées, et chacune **doit** produire un
// refus explicite, sans panique, sans boucle et sans allocation démesurée.
//
// L'entrée la plus instructive est la dernière : un cadre annonçant 2⁶³ octets.
// Elle est la raison d'être des bornes de `docs/conteneur.md` §4 — sans elles,
// la lire ferait réserver huit exaoctets à celui qui la lit, et ce test ne
// finirait jamais.

/// Conteneurs hostiles, chacun décrit par ce qu'il éprouve.
///
/// Bâtis à la main, depuis les seules constantes publiques : c'est ce qu'un
/// adversaire ferait, et le corpus doit donc en faire autant.
fn conteneurs_du_corpus() -> Vec<(&'static str, Vec<u8>)> {
    use ciborium::Value;

    fn encoder(valeur: &Value) -> Vec<u8> {
        let mut octets = Vec::new();
        ciborium::into_writer(valeur, &mut octets).expect("encodable");
        octets
    }

    fn en_tete(magic: &[u8], version: u64, membres: u64) -> Vec<u8> {
        encoder(&Value::Map(vec![
            (Value::Text("magic".into()), Value::Bytes(magic.to_vec())),
            (
                Value::Text("container_version".into()),
                Value::Integer(version.into()),
            ),
            (
                Value::Text("vault_format_version".into()),
                Value::Integer(1.into()),
            ),
            (
                Value::Text("member_count".into()),
                Value::Integer(membres.into()),
            ),
            (
                Value::Text("payload_bytes".into()),
                Value::Integer(0.into()),
            ),
        ]))
    }

    fn cadre(kind: &str, id: Option<Vec<u8>>, length: u64) -> Vec<u8> {
        encoder(&Value::Map(vec![
            (Value::Text("kind".into()), Value::Text(kind.into())),
            (
                Value::Text("id".into()),
                id.map_or(Value::Null, Value::Bytes),
            ),
            (Value::Text("length".into()), Value::Integer(length.into())),
        ]))
    }

    let magie = vault_core::CONTAINER_MAGIC.to_vec();
    let mut corpus = vec![
        ("flux vide", Vec::new()),
        ("texte quelconque", b"ceci n'est pas un conteneur".to_vec()),
        ("magie d'un vault sur disque", en_tete(b"VAULTFMT", 1, 2)),
        ("version de conteneur future", en_tete(&magie, 2, 2)),
        ("aucun membre annonce", en_tete(&magie, 1, 0)),
        ("en-tete seul, sans sceau", en_tete(&magie, 1, 2)),
    ];

    // Un cadre dont la longueur annoncée déborde toute mémoire concevable.
    let mut demesure = en_tete(&magie, 1, 2);
    demesure.extend_from_slice(&cadre("header", None, 1 << 63));
    corpus.push((
        "longueur annoncee a deux puissance soixante-trois",
        demesure,
    ));

    // Un cadre dont la longueur annoncée est la valeur maximale d'un entier.
    let mut maximale = en_tete(&magie, 1, 2);
    maximale.extend_from_slice(&cadre("index", None, u64::MAX));
    corpus.push(("longueur annoncee a u64::MAX", maximale));

    // Un membre `blob` là où le `header` est attendu.
    let mut desordre = en_tete(&magie, 1, 2);
    desordre.extend_from_slice(&cadre("blob", Some(vec![0u8; 32]), 0));
    corpus.push(("blob en premiere position", desordre));

    // Un type de membre que le format ne connaît pas.
    let mut inconnu = en_tete(&magie, 1, 2);
    inconnu.extend_from_slice(&cadre("manifeste", None, 0));
    corpus.push(("type de membre inconnu", inconnu));

    // Un identifiant de blob de longueur fausse.
    let mut court = en_tete(&magie, 1, 3);
    court.extend_from_slice(&cadre("header", None, 0));
    court.extend_from_slice(&cadre("index", None, 0));
    court.extend_from_slice(&cadre("blob", Some(vec![0u8; 4]), 0));
    corpus.push(("identifiant de blob trop court", court));

    corpus
}

/// Chaque conteneur du corpus est refusé, et **rien n'apparaît à destination**.
#[test]
fn les_conteneurs_du_corpus_sont_refuses() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");

    for (index, (quoi, octets)) in conteneurs_du_corpus().into_iter().enumerate() {
        let cible = atelier.path().join(format!("cible-{index}"));
        let resultat = Vault::import(&mut &octets[..], &cible, vault_core::ImportPolicy::Refuse);
        assert!(resultat.is_err(), "accepté : {quoi}");
        assert!(!cible.exists(), "un vault est apparu pour : {quoi}");
    }
}
