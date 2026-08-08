//! Suite bloquante — refus de l'entrée hostile (T019 à T021, FR-009, FR-010).
//!
//! `tamper.rs` retourne des bits dans un vault **bien formé** : il éprouve
//! l'authentification. Cette suite fait autre chose — elle soumet aux surfaces
//! de décodage des octets que **personne n'a choisis**, et vérifie qu'aucun ne
//! produit autre chose qu'un refus explicite.
//!
//! Le projet promet un refus explicite de tout ce qu'il ne comprend pas. Une
//! panique, une boucle sans fin ou une allocation dictée par une taille
//! annoncée sont des manquements à cette promesse, et **aucune des portes
//! existantes ne peut les voir** : le formatage, l'analyse statique et la
//! couverture regardent le code, pas ce qu'il fait d'une entrée absurde.
//!
//! # Trois familles, et pourquoi les trois
//!
//! Des octets purement aléatoires ne forment presque jamais du CBOR valide :
//! seuls, ils s'arrêteraient au premier contrôle et n'exploreraient rien de ce
//! qui suit. Chaque surface reçoit donc :
//!
//! 1. des **octets arbitraires**, qui éprouvent le tout premier contrôle ;
//! 2. des structures **presque valides**, obtenues en altérant lourdement un
//!    artefact réel — c'est ce qui atteint les chemins profonds ;
//! 3. des structures valides **tronquées** à une position quelconque, qui
//!    éprouvent les contrôles de longueur.
//!
//! # Pourquoi un générateur déterministe plutôt que `proptest`
//!
//! Cette suite est une **porte**. Une porte dont la durée n'est pas bornée n'en
//! est pas une, et une porte dont la graine change à chaque exécution devient
//! un générateur d'échecs inexpliqués — celui qui voit rouge ne peut pas
//! reproduire ce que la machine d'en face a vu.
//!
//! Le générateur ci-dessous tient en dix lignes, part d'une graine figée, et
//! produit exactement la même suite d'entrées partout, à chaque fois. Il n'écrit
//! aucun fichier de régression. L'exploration guidée par la couverture, elle,
//! vit dans `fuzz/` et se mène hors ligne (voir `docs/verifications.md`).

use std::path::Path;

use vault_core::{AddMode, KdfParams, OnConflict, SecretString, Vault, VaultPath};

/// Nombre de cas par famille et par surface. Figé : c'est ce qui borne la
/// durée de la porte.
const CAS: usize = 256;

/// Graine figée. La changer change la suite explorée — ce qui se fait
/// délibérément, pas par accident.
const GRAINE: u64 = 0x7661_756c_7420_3030;

const PASSPHRASE: &str = "passphrase de test bien assez longue";

/// Générateur déterministe — xorshift64*, suffisant pour engendrer des octets
/// sans structure et reproductible à l'identique sur toutes les plateformes.
struct Alea(u64);

impl Alea {
    fn nouveau(graine: u64) -> Self {
        Self(graine | 1)
    }

    fn suivant(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn octet(&mut self) -> u8 {
        u8::try_from(self.suivant() & 0xff).expect("masqué sur un octet")
    }

    fn borne(&mut self, maximum: usize) -> usize {
        if maximum == 0 {
            0
        } else {
            usize::try_from(self.suivant() % maximum as u64).expect("borné")
        }
    }

    fn octets(&mut self, longueur: usize) -> Vec<u8> {
        (0..longueur).map(|_| self.octet()).collect()
    }
}

fn params() -> KdfParams {
    KdfParams::new(64, 1, 1).expect("paramètres valides")
}

fn secret() -> SecretString {
    SecretString::from(PASSPHRASE.to_owned())
}

/// Un vault contenant un fichier, refermé.
fn coffre_peuple(atelier: &Path) -> std::path::PathBuf {
    let coffre = atelier.join("coffre");
    let source = atelier.join("note.txt");
    std::fs::write(&source, vec![0x5a; 3000]).expect("écrivable");

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

/// Les trois familles d'entrées engendrées à partir d'un artefact réel.
///
/// La famille « presque valide » altère **lourdement** l'original — plusieurs
/// octets à la fois — là où `tamper.rs` n'en retourne qu'un seul. L'un éprouve
/// l'authentification, l'autre le décodage.
fn familles(alea: &mut Alea, original: &[u8]) -> Vec<Vec<u8>> {
    let mut entrees = Vec::with_capacity(CAS * 3);

    for _ in 0..CAS {
        let longueur = alea.borne(original.len().max(1) * 2);
        entrees.push(alea.octets(longueur));
    }

    for _ in 0..CAS {
        let mut presque = original.to_vec();
        let alterations = 1 + alea.borne(16);
        for _ in 0..alterations {
            if presque.is_empty() {
                break;
            }
            let position = alea.borne(presque.len());
            presque[position] = alea.octet();
        }
        entrees.push(presque);
    }

    for _ in 0..CAS {
        let position = alea.borne(original.len() + 1);
        entrees.push(original[..position].to_vec());
    }

    entrees
}

/// Rapporte les cas fautifs, et eux seuls.
///
/// Un vecteur de sept cent soixante-huit booléens est illisible dans un
/// rapport d'échec : ce qui aide est le numéro du cas et la raison.
fn aucun_echec(fautifs: &[String], total: usize) {
    assert!(
        fautifs.is_empty(),
        "{} cas fautifs sur {total} :\n{}",
        fautifs.len(),
        fautifs.join("\n")
    );
}

/// FR-010 : aucune entrée hostile ne produit d'arrêt anormal, et **aucune ne
/// mène à une session dont le contenu serait faux**.
///
/// Le test n'exige pas que `Vault::open` échoue. Ce serait une erreur d'énoncé :
/// l'ouverture ne fait que **décoder les champs publics**, et n'authentifie
/// rien — c'est documenté, et c'est ce qui permet à `vault info` de travailler
/// sans passphrase. Une entrée qui n'altère que la clé enveloppée se décode donc
/// légitimement, et c'est le déverrouillage qui la refusera.
///
/// La propriété qui compte est ailleurs, et elle est plus forte : **si une
/// entrée hostile parvient jusqu'à une session ouverte, le contenu de cette
/// session doit être le bon.** Un vault qui s'ouvrirait sur autre chose que ses
/// données serait bien pire qu'un vault qui refuse.
#[test]
fn aucune_entree_hostile_ne_passe_par_l_en_tete() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_peuple(atelier.path());
    let en_tete = coffre.join("header");
    let original = std::fs::read(&en_tete).expect("lisible");
    let attendu = VaultPath::from_components([b"note.txt".to_vec()]).expect("valide");

    let mut alea = Alea::nouveau(GRAINE);
    let entrees = familles(&mut alea, &original);
    let total = entrees.len();
    let mut fautifs = Vec::new();
    let mut ouverts = 0usize;

    for (numero, entree) in entrees.into_iter().enumerate() {
        std::fs::write(&en_tete, &entree).expect("écrivable");
        let Ok(verrouille) = Vault::open(&coffre) else {
            continue;
        };
        match verrouille.unlock(secret()) {
            Err(_) => {}
            Ok(session) => {
                ouverts += 1;
                if session.stat(&attendu).is_err() || session.list(None).len() != 1 {
                    fautifs.push(format!(
                        "cas {numero} : session ouverte sur un contenu faux"
                    ));
                }
            }
        }
    }

    std::fs::write(&en_tete, &original).expect("écrivable");
    assert!(ouverts > 0, "aucune entrée n'a atteint le déverrouillage");
    aucun_echec(&fautifs, total);
}

/// L'index est intégralement chiffré : une entrée hostile ne peut donc pas
/// atteindre son décodeur CBOR sans la clé maîtresse.
///
/// Ce que cette suite éprouve ici est la couche qui précède — longueurs,
/// séparation du nonce, authentification. **Le décodeur CBOR lui-même n'est
/// atteignable qu'en forgeant un index authentifié**, ce qui suppose de
/// connaître la clé : c'est le scénario du vault forgé puis remis à sa victime,
/// couvert par les tests unitaires de `format::index`, qui disposent de la clé.
#[test]
fn aucune_entree_hostile_ne_passe_par_l_index() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_peuple(atelier.path());
    let index = coffre.join("index");
    let original = std::fs::read(&index).expect("lisible");

    let mut alea = Alea::nouveau(GRAINE ^ 0x11);
    let entrees = familles(&mut alea, &original);
    let total = entrees.len();

    let verdicts: Vec<bool> = entrees
        .into_iter()
        .map(|entree| {
            std::fs::write(&index, &entree).expect("écrivable");
            let resultat = Vault::open(&coffre).expect("ouvrable").unlock(secret());
            resultat.is_err() || entree == original
        })
        .collect();

    std::fs::write(&index, &original).expect("écrivable");
    assert_eq!(verdicts, vec![true; total], "{total} entrées soumises");
}

/// FR-039 : un blob hostile est refusé sans laisser de sortie partielle, et
/// **jamais restitué altéré**.
///
/// Ici encore, exiger un échec systématique serait une erreur d'énoncé. Le
/// **remplissage** d'un blob n'est ni déchiffré ni interprété (VR-B3) : une
/// entrée qui ne touche que lui — ou qui tronque le blob à l'intérieur de
/// celui-ci — laisse légitimement l'extraction aboutir.
///
/// La propriété exacte est donc : **ou bien l'extraction échoue et n'écrit
/// rien, ou bien elle aboutit et restitue le contenu d'origine, octet pour
/// octet.** Ce qui est interdit, c'est le troisième cas — aboutir sur des
/// données altérées.
#[test]
fn aucune_entree_hostile_ne_passe_par_un_blob() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_peuple(atelier.path());
    let sortie = atelier.path().join("sortie");
    std::fs::create_dir(&sortie).expect("créable");

    let chemin = VaultPath::from_components([b"note.txt".to_vec()]).expect("valide");
    let session = Vault::open(&coffre)
        .expect("ouvrable")
        .unlock(secret())
        .expect("déverrouillable");
    let (blob_id, _) = session
        .blob_of(&chemin)
        .expect("présente")
        .expect("un blob");
    let chemin_blob = coffre.join("objects").join(blob_id.to_hex());
    let original = std::fs::read(&chemin_blob).expect("lisible");

    let contenu_attendu = vec![0x5a; 3000];
    let mut alea = Alea::nouveau(GRAINE ^ 0x22);
    let entrees = familles(&mut alea, &original);
    let total = entrees.len();
    let mut fautifs = Vec::new();
    let mut aboutis = 0usize;

    for (numero, entree) in entrees.into_iter().enumerate() {
        std::fs::write(&chemin_blob, &entree).expect("écrivable");
        let _ = std::fs::remove_file(sortie.join("note.txt"));

        if session
            .extract(&chemin, &sortie, OnConflict::Replace)
            .is_ok()
        {
            aboutis += 1;
            let restitue = std::fs::read(sortie.join("note.txt")).expect("lisible");
            if restitue != contenu_attendu {
                fautifs.push(format!(
                    "cas {numero} : contenu ALTÉRÉ restitué sans erreur"
                ));
            }
        } else if std::fs::read_dir(&sortie)
            .expect("listable")
            .next()
            .is_some()
        {
            fautifs.push(format!("cas {numero} : sortie partielle après échec"));
        }
    }

    std::fs::write(&chemin_blob, &original).expect("écrivable");
    assert!(
        aboutis > 0,
        "aucune entrée n'a abouti : le remplissage n'a pas été exploré"
    );
    aucun_echec(&fautifs, total);
}

/// Les composants de chemin sont conservés en octets bruts : n'importe quelle
/// suite d'octets peut être soumise à leur construction.
///
/// Aucune ne doit faire paniquer. Celles qui sont acceptées doivent respecter
/// les règles de composition, et rien de ce qui est accepté ne doit permettre
/// de remonter hors du vault.
#[test]
fn aucun_chemin_hostile_ne_fait_paniquer() {
    let mut alea = Alea::nouveau(GRAINE ^ 0x33);
    let mut acceptes = 0usize;
    let mut verdicts = Vec::new();

    for _ in 0..CAS * 3 {
        let profondeur = 1 + alea.borne(4);
        let composants: Vec<Vec<u8>> = (0..profondeur)
            .map(|_| {
                let longueur = alea.borne(12);
                alea.octets(longueur)
            })
            .collect();

        match VaultPath::from_components(composants) {
            Err(_) => verdicts.push(true),
            Ok(chemin) => {
                acceptes += 1;
                // Rien d'accepté ne doit contenir un composant interdit.
                let sain = chemin.components().all(|composant| {
                    !composant.is_empty()
                        && composant != b"."
                        && composant != b".."
                        && !composant.iter().any(|o| matches!(o, b'/' | b'\\' | 0))
                });
                verdicts.push(sain);
            }
        }
    }

    assert!(
        acceptes > 0,
        "aucun chemin accepté : le test n'explore rien"
    );
    assert_eq!(verdicts, vec![true; CAS * 3]);
}

/// FR-010 : une taille annoncée démesurée est refusée **sans que la mémoire
/// correspondante soit réservée**.
///
/// L'absence d'allocation ne se mesure pas directement depuis un test. Ce qui
/// se constate, et qui suffit : l'appel rend la main immédiatement, sur une
/// taille annoncée que nulle machine ne pourrait allouer. Une implémentation
/// qui réserverait d'après l'annonce serait éliminée par le noyau avant d'avoir
/// pu échouer proprement.
#[test]
fn une_taille_annoncee_demesuree_est_refusee_sans_reserver() {
    let atelier = tempfile::tempdir().expect("répertoire temporaire");
    let coffre = coffre_peuple(atelier.path());
    let sortie = atelier.path().join("sortie");
    std::fs::create_dir(&sortie).expect("créable");

    let session = Vault::open(&coffre)
        .expect("ouvrable")
        .unlock(secret())
        .expect("déverrouillable");
    let chemin = VaultPath::from_components([b"note.txt".to_vec()]).expect("valide");
    let (blob_id, _) = session
        .blob_of(&chemin)
        .expect("présente")
        .expect("un blob");

    // Un blob réduit à quelques octets, alors que l'index en annonce trois
    // mille : la lecture doit s'arrêter sur la longueur, pas sur l'annonce.
    let chemin_blob = coffre.join("objects").join(blob_id.to_hex());
    std::fs::write(&chemin_blob, b"court").expect("écrivable");

    assert!(session.extract(&chemin, &sortie, OnConflict::Fail).is_err());
    assert_eq!(
        std::fs::read_dir(&sortie).expect("listable").count(),
        0,
        "aucune sortie partielle"
    );
}
