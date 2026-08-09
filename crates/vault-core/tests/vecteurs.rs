//! Vecteurs de test publiés (T015, FR-006).
//!
//! `docs/format.md` publie, en section 7 bis, les valeurs intermédiaires de la
//! chaîne de dérivation du vault de référence, pour qu'un tiers puisse situer
//! l'étape exacte où son implémentation diverge **sans exécuter vault**.
//!
//! Des valeurs publiées que rien ne vérifie vieillissent en silence : le code
//! évolue, le document reste, et le tiers qui s'y fie se retrouve à déboguer
//! une divergence qui n'est pas la sienne. Cette suite fait donc échouer la
//! chaîne d'intégration dès qu'un écart apparaît entre le document et le
//! logiciel.
//!
//! # Ce qui est vérifié ici, et ce qui l'est ailleurs
//!
//! Cette suite couvre tout ce qu'un tiers peut **observer** : les champs
//! publics de l'en-tête, les octets exacts du contexte public, et ce que
//! l'index révèle une fois ouvert. Les valeurs **secrètes** — clé d'enveloppe,
//! clé maîtresse, clé de blob — ne traversent aucune interface publique, et
//! c'est délibéré ; elles sont vérifiées par les tests unitaires de
//! `format::header` et de `crypto::keys`, qui voient l'intérieur du crate.

use std::path::Path;

use vault_core::{SecretString, Vault, VaultPath};

/// Emplacement du vault de référence, relatif à la racine du crate.
const REFERENCE: &str = "tests/fixtures/v1";

/// Publiée dans `docs/format.md` : ce vault ne protège rien.
const PASSPHRASE: &str = "vault fixture v1 passphrase de reference";

/// Convertit une chaîne hexadécimale du document en octets.
fn hex(texte: &str) -> Vec<u8> {
    (0..texte.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&texte[index..index + 2], 16).expect("hexadécimal"))
        .collect()
}

/// Copie la référence dans un répertoire jetable.
///
/// Ouvrir un vault n'est pas une opération en lecture seule : le verrou y crée
/// son fichier support et le déverrouillage balaie les orphelins. Voir
/// `compat.rs`.
fn copie_jetable(atelier: &Path) -> std::path::PathBuf {
    let cible = atelier.join("coffre");
    std::fs::create_dir_all(cible.join("objects")).expect("créable");
    for entree in walkdir::WalkDir::new(REFERENCE)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entree| entree.file_type().is_file())
    {
        let relatif = entree
            .path()
            .strip_prefix(REFERENCE)
            .expect("sous la racine");
        std::fs::copy(entree.path(), cible.join(relatif)).expect("copiable");
    }
    cible
}

/// L'en-tête du vault de référence, décodé depuis ses octets bruts.
///
/// Le décodage passe par CBOR directement, et non par le logiciel : ce sont les
/// **octets publiés** qui sont comparés, tels qu'un tiers les lirait.
fn en_tete_brut() -> ciborium::Value {
    let octets = std::fs::read(Path::new(REFERENCE).join("header")).expect("lisible");
    ciborium::from_reader(&octets[..]).expect("CBOR décodable")
}

fn champ<'a>(entete: &'a ciborium::Value, nom: &str) -> &'a ciborium::Value {
    entete
        .as_map()
        .expect("carte CBOR")
        .iter()
        .find(|(cle, _)| cle.as_text() == Some(nom))
        .map_or_else(
            || panic!("champ {nom} absent de l'en-tête"),
            |(_, valeur)| valeur,
        )
}

/// Section 7 bis : les champs publics de l'en-tête sont ceux qui sont publiés.
#[test]
fn les_champs_publics_publies_sont_ceux_de_l_en_tete() {
    let entete = en_tete_brut();

    assert_eq!(
        champ(&entete, "magic").as_bytes().expect("octets"),
        b"VAULTFMT"
    );
    assert_eq!(
        champ(&entete, "format_version").as_integer(),
        Some(1.into())
    );
    assert_eq!(
        champ(&entete, "kdf_salt").as_bytes().expect("octets"),
        &hex("bdfaa6979ddb4e6f23ce5c8615aaedcd")
    );
    assert_eq!(
        champ(&entete, "kdf_memory_kib").as_integer(),
        Some(64.into())
    );
    assert_eq!(
        champ(&entete, "kdf_iterations").as_integer(),
        Some(1.into())
    );
    assert_eq!(
        champ(&entete, "kdf_parallelism").as_integer(),
        Some(1.into())
    );
    assert_eq!(
        champ(&entete, "kdf_algorithm").as_text().expect("texte"),
        "argon2id"
    );
    assert_eq!(
        champ(&entete, "aead_algorithm").as_text().expect("texte"),
        "xchacha20poly1305"
    );
}

/// Section 7 bis : les 65 octets du contexte public, reconstruits selon la
/// recette du document, sont bien ceux qui sont publiés.
///
/// C'est le vecteur le plus utile de tous : le contexte public est une
/// concaténation à champs de largeur fixe, et c'est exactement le genre de
/// construction qu'une description approximative rend irreproductible.
#[test]
fn le_contexte_public_publie_est_reproductible() {
    let publie = hex(concat!(
        "5641554c54464d54",
        "00000001",
        "6172676f6e326964",
        "bdfaa6979ddb4e6f23ce5c8615aaedcd",
        "00000040",
        "00000001",
        "00000001",
        "786368616368613230706f6c7931333035",
    ));
    assert_eq!(publie.len(), 65, "le document annonce 65 octets");

    // Reconstruction depuis les champs de l'en-tête, en suivant §4.2.
    let entete = en_tete_brut();
    let mut reconstruit = Vec::new();
    reconstruit.extend_from_slice(b"VAULTFMT");
    reconstruit.extend_from_slice(&1u32.to_be_bytes());
    reconstruit.extend_from_slice(b"argon2id");
    reconstruit.extend_from_slice(champ(&entete, "kdf_salt").as_bytes().expect("octets"));
    reconstruit.extend_from_slice(&64u32.to_be_bytes());
    reconstruit.extend_from_slice(&1u32.to_be_bytes());
    reconstruit.extend_from_slice(&1u32.to_be_bytes());
    reconstruit.extend_from_slice(b"xchacha20poly1305");

    assert_eq!(reconstruit, publie);

    // Et les données associées, soit le préfixe suivi du contexte : 84 octets.
    let mut aad = b"vault master key v1".to_vec();
    aad.extend_from_slice(&publie);
    assert_eq!(aad.len(), 84, "le document annonce 84 octets");
}

/// Section 7 bis : l'entrée témoin porte bien les valeurs publiées.
#[test]
fn l_entree_temoin_publiee_est_celle_de_l_index() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = copie_jetable(atelier.path());

    let session = Vault::open(&coffre)
        .expect("ouvrable")
        .unlock(SecretString::from(PASSPHRASE.to_owned()))
        .expect("la passphrase publiée ouvre");

    let chemin = VaultPath::from_components([b"lisez-moi.txt".to_vec()]).expect("valide");
    let entree = session.stat(&chemin).expect("présente");
    assert_eq!(entree.size, Some(67), "taille publiée");

    let (blob_id, rempli) = session
        .blob_of(&chemin)
        .expect("présente")
        .expect("un blob");
    assert_eq!(
        blob_id.to_hex(),
        "64a8f329ed76ed598354b07483b2dca8a2bd700eb09e08df17b3fac6d7b81d80"
    );
    assert_eq!(rempli, 4096, "blob_padded_size publiée");

    // Le nonce STREAM est en tête du blob, et fait 19 octets (§6).
    let blob = std::fs::read(coffre.join("objects").join(blob_id.to_hex())).expect("lisible");
    assert_eq!(
        blob[..19],
        hex("5174be637c527dbea15f84a55487b1b3afc790")[..],
        "nonce STREAM publié"
    );

    // Nonce complet du morceau 0 : le contenu tient en un morceau, donc le
    // drapeau de dernier morceau vaut 0x01.
    let mut nonce_du_morceau = blob[..19].to_vec();
    nonce_du_morceau.extend_from_slice(&0u32.to_be_bytes());
    nonce_du_morceau.push(0x01);
    assert_eq!(
        nonce_du_morceau,
        hex("5174be637c527dbea15f84a55487b1b3afc7900000000001")
    );
    assert_eq!(
        nonce_du_morceau.len(),
        24,
        "un nonce XChaCha fait 24 octets"
    );
}

/// Les données associées d'un blob, publiées en section 7 bis : le préfixe
/// suivi de l'identifiant, soit 45 octets.
#[test]
fn les_donnees_associees_du_blob_publiees_sont_reproductibles() {
    let mut aad = b"vault blob v1".to_vec();
    aad.extend_from_slice(&hex(
        "64a8f329ed76ed598354b07483b2dca8a2bd700eb09e08df17b3fac6d7b81d80",
    ));
    assert_eq!(aad.len(), 45, "le document annonce 45 octets");
    assert_eq!(
        aad,
        hex(concat!(
            "7661756c7420626c6f6220763164",
            "a8f329ed76ed598354b07483b2dca8a2bd700eb09e08df17b3fac6d7b81d80",
        ))
    );
}
