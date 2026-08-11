//! Suite bloquante — le conteneur d'export (T016, T017, quickstart 2 à 4).
//!
//! Trois propriétés y sont établies, à la frontière publique de la
//! bibliothèque plutôt que dans ses entrailles :
//!
//! - **un export par défaut ne demande rien et n'ouvre rien** (FR-005a,
//!   XFR-001) ;
//! - **deux exports d'un vault inchangé donnent les mêmes octets** (FR-005c,
//!   XFR-007), et la variante sous passphrase distincte, elle, n'en donne pas —
//!   la limite du déterminisme est éprouvée au même titre que le déterminisme ;
//! - **le conteneur refuse ce qu'il ne comprend pas**, sans panique, sans
//!   boucle, sans allocation démesurée, et sans laisser de vault à destination.
//!
//! Le troisième point fait du conteneur la **cinquième surface de décodage** du
//! projet, aux côtés de l'en-tête, de l'index, des chemins et des blobs. Les
//! conteneurs hostiles y sont fabriqués à la main, depuis les seules constantes
//! publiques : c'est ce qu'un adversaire ferait, et c'est donc ce que la suite
//! doit faire.

use std::path::{Path, PathBuf};

use ciborium::Value;
use vault_core::{
    AddMode, CONTAINER_END, CONTAINER_MAGIC, CONTAINER_VERSION, Error, ExportEnvelope,
    ImportPolicy, KdfParams, OnConflict, SecretString, Vault, VaultPath,
};

const PASSPHRASE: &str = "passphrase de test bien assez longue";

fn params() -> KdfParams {
    KdfParams::new(64, 1, 1).expect("paramètres valides")
}

fn passphrase() -> SecretString {
    SecretString::from(PASSPHRASE.to_owned())
}

/// Un vault de deux entrées, refermé.
fn coffre_peuple(atelier: &Path) -> PathBuf {
    let coffre = atelier.join("coffre");
    let mut vault = Vault::create(&coffre, passphrase(), params()).expect("créable");
    for (nom, contenu) in [("note.txt", &b"une note"[..]), ("gros.bin", &[0x2a; 9000])] {
        let source = atelier.join(nom);
        std::fs::write(&source, contenu).expect("écrivable");
        vault
            .add_file(
                &source,
                &VaultPath::from_components([nom.as_bytes().to_vec()]).expect("valide"),
                AddMode::Copy,
                OnConflict::Fail,
            )
            .expect("ajoutable");
    }
    vault.lock();
    coffre
}

fn exporter(coffre: &Path) -> Vec<u8> {
    let mut conteneur = Vec::new();
    Vault::export(coffre, ExportEnvelope::Source, &mut conteneur).expect("exportable");
    conteneur
}

// ---------------------------------------------------------------------------
// Scénario 2 — un export ne demande rien et ne déchiffre rien
// ---------------------------------------------------------------------------

/// FR-005a, XFR-001 : l'export d'un vault **verrouillé** aboutit sans qu'aucune
/// `SecretString` n'ait été construite par le test.
///
/// La preuve est dans la signature autant que dans l'exécution :
/// [`ExportEnvelope::Source`] ne porte aucun champ, et il n'existe donc aucun
/// moyen de lui passer une passphrase.
#[test]
fn export_sans_passphrase_aboutit_sur_un_vault_verrouille() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_peuple(atelier.path());

    let mut conteneur = Vec::new();
    let resume =
        Vault::export(&coffre, ExportEnvelope::Source, &mut conteneur).expect("exportable");

    assert_eq!(resume.blob_count, 2);
    assert!(!conteneur.is_empty());

    // Le membre `header` est le fichier `header` du vault, à l'octet près : il
    // a été recopié sans être ouvert, donc la clé maîtresse n'a jamais été
    // désenveloppée.
    let en_tete = std::fs::read(coffre.join("header")).expect("lisible");
    assert!(
        conteneur
            .windows(en_tete.len())
            .any(|fenetre| fenetre == en_tete),
        "l'en-tête du vault doit figurer tel quel dans le conteneur"
    );
}

/// L'export ne demande rien **et** ne touche rien : le répertoire du vault est
/// identique avant et après.
#[test]
fn export_sans_passphrase_ne_modifie_pas_le_vault() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_peuple(atelier.path());

    let avant = empreinte_du_vault(&coffre);
    let _ = exporter(&coffre);
    assert_eq!(empreinte_du_vault(&coffre), avant);
}

/// Contenu du répertoire d'un vault, `.lock` excepté — il décrit l'état
/// d'exécution d'un poste, pas le contenu d'un vault (FR-008a).
fn empreinte_du_vault(coffre: &Path) -> Vec<(String, Vec<u8>)> {
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
// Scénario 3 — deux exports du même vault donnent les mêmes octets
// ---------------------------------------------------------------------------

/// FR-005c, XFR-007, SC-014 : le déterminisme, y compris après que l'ordre de
/// parcours du répertoire a été délibérément mélangé.
#[test]
fn determinisme_de_deux_exports_successifs() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_peuple(atelier.path());

    let premier = exporter(&coffre);
    assert_eq!(premier, exporter(&coffre));

    // Les blobs sont recréés dans l'ordre inverse : sur la plupart des systèmes
    // de fichiers, cela suffit à changer l'ordre de `read_dir`. Le tri par
    // identifiant doit rendre ce changement indifférent.
    let objets = coffre.join("objects");
    let mut noms: Vec<_> = std::fs::read_dir(&objets)
        .expect("listable")
        .filter_map(std::result::Result::ok)
        .map(|entree| entree.file_name())
        .collect();
    noms.sort_unstable();
    noms.reverse();
    for nom in &noms {
        let contenu = std::fs::read(objets.join(nom)).expect("lisible");
        std::fs::remove_file(objets.join(nom)).expect("supprimable");
        std::fs::write(objets.join(nom), contenu).expect("écrivable");
    }

    assert_eq!(
        premier,
        exporter(&coffre),
        "le tri des blobs par identifiant rend l'ordre de parcours indifférent"
    );
}

/// **La limite du déterminisme**, éprouvée au même titre que lui : la variante
/// sous passphrase distincte réenveloppe, donc tire un sel et un nonce neufs.
/// Deux exports y diffèrent **légitimement**.
#[test]
fn determinisme_ne_vaut_pas_sous_passphrase_distincte() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_peuple(atelier.path());
    let distincte = || ExportEnvelope::NewPassphrase {
        current: passphrase(),
        new: SecretString::from("une toute autre passphrase, longue".to_owned()),
    };

    let mut premier = Vec::new();
    Vault::export(&coffre, distincte(), &mut premier).expect("exportable");
    let mut second = Vec::new();
    Vault::export(&coffre, distincte(), &mut second).expect("exportable");

    assert_ne!(premier, second);
    assert_eq!(
        premier.len(),
        second.len(),
        "seule l'enveloppe diffère : le contenu n'est pas rechiffré"
    );
}

/// Le déterminisme sert à quelque chose : deux exports d'un vault inchangé se
/// comparent **sans être ouverts**, et l'un comme l'autre se réimporte.
#[test]
fn determinisme_survit_a_un_aller_retour() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_peuple(atelier.path());
    let conteneur = exporter(&coffre);

    let restaure = atelier.path().join("restaure");
    Vault::import(&mut &conteneur[..], &restaure, ImportPolicy::Refuse).expect("importable");

    // Le vault restitué produit à son tour le **même** conteneur : le
    // déterminisme ne dépend pas de l'emplacement.
    assert_eq!(exporter(&restaure), conteneur);
}

// ---------------------------------------------------------------------------
// Scénario 4 — le conteneur refuse ce qu'il ne comprend pas
// ---------------------------------------------------------------------------

/// Un membre à fabriquer : type, identifiant, longueur annoncée, charge.
struct Membre {
    kind: &'static str,
    id: Option<Vec<u8>>,
    /// Longueur **annoncée**, qui peut mentir sur la charge réelle.
    length: u64,
    charge: Vec<u8>,
}

impl Membre {
    fn nu(kind: &'static str, charge: &[u8]) -> Self {
        Self {
            kind,
            id: None,
            length: charge.len() as u64,
            charge: charge.to_vec(),
        }
    }

    fn blob(id: u8, charge: &[u8]) -> Self {
        let mut identifiant = vec![0u8; 32];
        identifiant[0] = id;
        Self {
            kind: "blob",
            id: Some(identifiant),
            length: charge.len() as u64,
            charge: charge.to_vec(),
        }
    }
}

fn encoder(valeur: &Value) -> Vec<u8> {
    let mut octets = Vec::new();
    ciborium::into_writer(valeur, &mut octets).expect("encodable");
    octets
}

/// Fabrique un conteneur de toutes pièces, sans passer par l'écrivain de la
/// bibliothèque : c'est ce qu'un adversaire ferait.
fn forger(magic: &[u8], container_version: u64, membres: Vec<Membre>) -> Vec<u8> {
    // Le volume annoncé est celui des charges **réelles**, et non des longueurs
    // annoncées : un cadre peut ainsi mentir sur sa longueur sans que l'en-tête
    // se dénonce, ce qui est exactement le cas hostile à éprouver.
    let payload: u64 = membres.iter().map(|m| m.charge.len() as u64).sum();
    let mut flux = encoder(&Value::Map(vec![
        (Value::Text("magic".into()), Value::Bytes(magic.to_vec())),
        (
            Value::Text("container_version".into()),
            Value::Integer(container_version.into()),
        ),
        (
            Value::Text("vault_format_version".into()),
            Value::Integer(1.into()),
        ),
        (
            Value::Text("member_count".into()),
            Value::Integer((membres.len() as u64).into()),
        ),
        (
            Value::Text("payload_bytes".into()),
            Value::Integer(payload.into()),
        ),
    ]));

    let compte = membres.len() as u64;
    for membre in membres {
        flux.extend_from_slice(&encoder(&Value::Map(vec![
            (Value::Text("kind".into()), Value::Text(membre.kind.into())),
            (
                Value::Text("id".into()),
                membre.id.map_or(Value::Null, Value::Bytes),
            ),
            (
                Value::Text("length".into()),
                Value::Integer(membre.length.into()),
            ),
        ])));
        flux.extend_from_slice(&membre.charge);
    }

    sceller(flux, compte)
}

/// Appose un sceau cohérent à la fin du flux.
fn sceller(flux: Vec<u8>, member_count: u64) -> Vec<u8> {
    let digest = blake3::hash(&flux);
    let mut scelle = flux;
    scelle.extend_from_slice(&encoder(&Value::Map(vec![
        (
            Value::Text("end".into()),
            Value::Bytes(CONTAINER_END.to_vec()),
        ),
        (
            Value::Text("member_count".into()),
            Value::Integer(member_count.into()),
        ),
        (
            Value::Text("digest".into()),
            Value::Bytes(digest.as_bytes().to_vec()),
        ),
    ])));
    scelle
}

/// Importe un conteneur hostile et rend l'erreur, en vérifiant qu'aucun vault
/// n'est apparu.
fn refus(atelier: &Path, nom: &str, conteneur: &[u8]) -> Error {
    let cible = atelier.join(nom);
    let erreur = Vault::import(&mut &conteneur[..], &cible, ImportPolicy::Refuse)
        .expect_err("un refus était attendu");
    assert!(!cible.exists(), "aucun vault ne doit apparaître pour {nom}");
    erreur
}

/// La première moitié de la table du scénario 4 : les conteneurs **forgés de
/// toutes pièces**, que le logiciel n'a jamais produits.
///
/// Chacun produit un refus explicite, sans panique, sans boucle et sans
/// allocation démesurée.
#[test]
fn refus_des_conteneurs_forges() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");

    let deux_membres = || {
        vec![
            Membre::nu("header", b"en-tete"),
            Membre::nu("index", b"index"),
        ]
    };

    // Magie inconnue — ce n'est pas un conteneur.
    assert!(matches!(
        refus(
            atelier.path(),
            "magie",
            &forger(b"PASVAULT", CONTAINER_VERSION.into(), deux_membres())
        ),
        Error::Corrupted
    ));

    // Version de conteneur non gérée — refus explicite, version nommée.
    assert!(matches!(
        refus(
            atelier.path(),
            "version",
            &forger(&CONTAINER_MAGIC, 2, deux_membres())
        ),
        Error::UnsupportedFormatVersion { found: 2, supported } if supported == CONTAINER_VERSION
    ));

    // Longueur annoncée à 2⁶³ — hors bornes, **avant toute allocation**. Si
    // elle était réservée, ce test ne finirait pas.
    let mut demesure = deux_membres();
    demesure[0].length = 1 << 63;
    assert!(matches!(
        refus(
            atelier.path(),
            "demesure",
            &forger(&CONTAINER_MAGIC, CONTAINER_VERSION.into(), demesure)
        ),
        Error::Corrupted
    ));

    // Membre `blob` avant `index` — ordre violé.
    assert!(matches!(
        refus(
            atelier.path(),
            "ordre",
            &forger(
                &CONTAINER_MAGIC,
                CONTAINER_VERSION.into(),
                vec![
                    Membre::nu("header", b"en-tete"),
                    Membre::blob(1, b"trop tot"),
                    Membre::nu("index", b"index"),
                ]
            )
        ),
        Error::Corrupted
    ));

    // Deux blobs de même identifiant — doublon.
    assert!(matches!(
        refus(
            atelier.path(),
            "doublon",
            &forger(
                &CONTAINER_MAGIC,
                CONTAINER_VERSION.into(),
                vec![
                    Membre::nu("header", b"en-tete"),
                    Membre::nu("index", b"index"),
                    Membre::blob(7, b"premier"),
                    Membre::blob(7, b"second"),
                ]
            )
        ),
        Error::Corrupted
    ));

    // Type de membre inconnu.
    assert!(matches!(
        refus(
            atelier.path(),
            "type",
            &forger(
                &CONTAINER_MAGIC,
                CONTAINER_VERSION.into(),
                vec![Membre::nu("manifeste", b"?"), Membre::nu("index", b"index"),]
            )
        ),
        Error::Corrupted
    ));

    // Un flux qui n'est pas du CBOR du tout.
    assert!(matches!(
        refus(atelier.path(), "etranger", b"ceci n'est pas un conteneur"),
        Error::Corrupted
    ));
    assert!(matches!(
        refus(atelier.path(), "vide", b""),
        Error::Corrupted
    ));
}

/// La seconde moitié de la table du scénario 4 : les **altérations d'un
/// conteneur légitime**, que seul le sceau peut voir.
#[test]
fn refus_des_alterations_d_un_conteneur_legitime() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_peuple(atelier.path());
    let legitime = exporter(&coffre);

    // Point de repère : le conteneur légitime, lui, passe.
    Vault::import(
        &mut &legitime[..],
        &atelier.path().join("temoin"),
        ImportPolicy::Refuse,
    )
    .expect("le conteneur légitime doit s'importer");

    // Flux tronqué à mi-charge — le sceau est absent.
    assert!(matches!(
        refus(atelier.path(), "tronque", &legitime[..legitime.len() / 2]),
        Error::Corrupted
    ));

    // Un octet retourné au milieu d'un blob — l'empreinte du sceau diverge.
    let mut retourne = legitime.clone();
    let milieu = retourne.len() / 2;
    retourne[milieu] ^= 0x01;
    assert!(matches!(
        refus(atelier.path(), "retourne", &retourne),
        Error::Corrupted
    ));

    // Octets ajoutés après le sceau — le flux ne s'arrête pas là.
    let mut suivi = legitime.clone();
    suivi.push(0x00);
    assert!(matches!(
        refus(atelier.path(), "suivi", &suivi),
        Error::Corrupted
    ));
}

/// Un conteneur forgé qui transporte un vault d'une version de format inconnue
/// est refusé **avant** d'écrire quoi que ce soit — le membre `header` n'est
/// même pas lu.
#[test]
fn refus_d_une_version_de_vault_inconnue() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");

    let mut flux = encoder(&Value::Map(vec![
        (
            Value::Text("magic".into()),
            Value::Bytes(CONTAINER_MAGIC.to_vec()),
        ),
        (
            Value::Text("container_version".into()),
            Value::Integer(CONTAINER_VERSION.into()),
        ),
        (
            Value::Text("vault_format_version".into()),
            Value::Integer(99.into()),
        ),
        (Value::Text("member_count".into()), Value::Integer(2.into())),
        (
            Value::Text("payload_bytes".into()),
            Value::Integer(0.into()),
        ),
    ]));
    flux = sceller(flux, 2);

    assert!(matches!(
        refus(atelier.path(), "vault-futur", &flux),
        Error::UnsupportedFormatVersion {
            found: 99,
            supported: 1
        }
    ));
}

/// Un conteneur annonçant moins de deux membres ne peut pas porter un vault :
/// le `header` et l'`index` sont obligatoires.
#[test]
fn refus_d_un_conteneur_sans_ses_membres_obligatoires() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");

    for membres in [vec![], vec![Membre::nu("header", b"seul")]] {
        let conteneur = forger(&CONTAINER_MAGIC, CONTAINER_VERSION.into(), membres);
        assert!(matches!(
            refus(atelier.path(), "incomplet", &conteneur),
            Error::Corrupted
        ));
    }
}
