//! Export d'un vault vers un conteneur — T020 à T024.
//!
//! FR-001 à FR-010. L'opération est courte parce que le format a été conçu pour
//! qu'elle le soit : **un export ne chiffre rien**, il recopie des octets déjà
//! chiffrés en les cadrant (D-201).
//!
//! **FR-005a, D-202 : l'enveloppe du vault source est reprise telle quelle.**
//! Le membre `header` du conteneur est le fichier `header` du vault, copié sans
//! être ouvert. La clé maîtresse n'est donc **jamais désenveloppée** au cours
//! d'un export par défaut, donc jamais présente en mémoire, donc jamais
//! exposée : un export manipule des octets opaques du début à la fin, et
//! n'exige aucune passphrase.
//!
//! Recopier ce fichier ne divulgue rien. Il est **en clair par conception**,
//! visible de quiconque accède au répertoire du vault, et la clé maîtresse
//! qu'il porte y est enveloppée sous Argon2id. Un conteneur n'est, à cet égard,
//! ni plus ni moins exposé que le vault dont il provient.
//!
//! **FR-005c : l'export est déterministe en mode par défaut.** Deux exports
//! d'un vault inchangé produisent des octets identiques. Rien de variable n'est
//! écrit — ni horodatage, ni nom de machine, ni version du logiciel — et les
//! blobs sont **triés par identifiant croissant**, sans quoi l'ordre de parcours
//! du répertoire, qui dépend du système de fichiers, suffirait à faire diverger
//! deux exports du même vault.
//!
//! **FR-008 : un export est une copie fidèle, pas un ménage.** Il emporte les
//! blobs qu'aucune entrée de l'index ne désigne, parce qu'il ne lit pas l'index
//! et ne peut donc pas les distinguer. Seul le support du verrou est laissé :
//! il décrit l'état d'exécution d'un poste, pas le contenu d'un vault (FR-008a).

use std::io::Write;
use std::path::Path;

use secrecy::{ExposeSecret, SecretString};

use crate::error::{Error, Result};
use crate::format::blob::BlobId;
use crate::format::container::{ContainerWriter, MemberKind};
use crate::format::header::Header;
use crate::fs::lock::VaultLock;
use crate::ops::{HEADER_FILE, INDEX_FILE, OBJECTS_DIR, blob_path};
use crate::{MIN_PASSPHRASE_LEN, Vault};

/// Enveloppe dont le conteneur sera protégé.
pub enum ExportEnvelope {
    /// Celle du vault source, **recopiée telle quelle**.
    ///
    /// C'est le défaut, et il n'exige aucune passphrase (FR-005a).
    Source,
    /// Une enveloppe neuve, sous une passphrase distincte (FR-005b).
    ///
    /// Exige d'ouvrir le vault source pour réenvelopper sa clé maîtresse —
    /// exactement l'opération de `vault passwd`. Le contenu n'est pas
    /// davantage touché, et le déterminisme de FR-005c ne s'applique pas :
    /// un sel et un nonce neufs sont tirés à chaque fois.
    NewPassphrase {
        /// Passphrase du vault source, nécessaire pour ouvrir son enveloppe.
        current: SecretString,
        /// Passphrase dont le conteneur sera protégé.
        new: SecretString,
    },
}

/// Ce qu'un export a produit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExportSummary {
    /// Nombre de blobs emportés, déchets inertes compris.
    pub blob_count: u64,
    /// Volume total des membres, en octets.
    pub payload_bytes: u64,
}

impl Vault {
    /// Écrit le vault de `path` dans `sink`, sous forme de conteneur d'export.
    ///
    /// Le verrou exclusif est pris pour la durée de l'opération et rendu au
    /// retour (FR-007). Le vault source n'est **jamais** modifié, y compris sur
    /// les chemins d'erreur (FR-009) : rien ici n'ouvre un fichier du vault en
    /// écriture.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyInUse`] si le vault est déjà ouvert par une autre
    ///   instance (FR-007) ;
    /// - [`Error::NotFound`] s'il n'y a pas de vault à cet emplacement ;
    /// - [`Error::Corrupted`] si l'en-tête est illisible, ou
    ///   [`Error::UnsupportedFormatVersion`] si son format dépasse ce que cette
    ///   version sait lire ;
    /// - [`Error::WeakPassphrase`] si la passphrase distincte demandée est trop
    ///   courte, **avant** toute écriture ;
    /// - [`Error::Authentication`] si la passphrase du vault source est erronée,
    ///   dans la seule variante qui l'exige ;
    /// - [`Error::Io`] si la lecture du vault ou l'écriture du conteneur
    ///   échouent.
    // L'enveloppe est prise **par valeur** parce qu'elle porte des passphrases :
    // c'est ce qui garantit qu'elles sont libérées — donc effacées par
    // `secrecy` — au retour de l'appel. Voir la note de `Vault::create`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn export(
        path: &Path,
        envelope: ExportEnvelope,
        sink: &mut dyn Write,
    ) -> Result<ExportSummary> {
        // FR-007 : le verrou est pris avant toute lecture, et tenu jusqu'au
        // retour. Un vault qui change en cours d'export produirait un conteneur
        // incohérent, que rien ne signalerait avant l'import.
        let _lock = VaultLock::acquire(path)?;

        let en_tete_source = match std::fs::read(path.join(HEADER_FILE)) {
            Ok(octets) => octets,
            Err(erreur) if erreur.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::NotFound);
            }
            Err(erreur) => return Err(erreur.into()),
        };
        // Décodé pour refuser tôt un vault qu'on ne saurait pas relire, et pour
        // connaître la version de format à annoncer dans l'en-tête du conteneur.
        let header = Header::decode(&en_tete_source)?;

        let membre_header = match envelope {
            ExportEnvelope::Source => en_tete_source,
            ExportEnvelope::NewPassphrase { current, new } => {
                fabriquer_en_tete(&header, &current, &new)?
            }
        };

        let index = std::fs::read(path.join(INDEX_FILE))?;
        let blobs = recenser_blobs(path)?;

        let member_count = 2 + blobs.len() as u64;
        let payload_bytes = blobs
            .iter()
            .try_fold(
                (membre_header.len() + index.len()) as u64,
                |total, (_, taille)| total.checked_add(*taille),
            )
            .ok_or(Error::Corrupted)?;

        let mut writer =
            ContainerWriter::begin(sink, header.format_version(), member_count, payload_bytes)?;
        writer.member(
            MemberKind::Header,
            None,
            membre_header.len() as u64,
            &mut &membre_header[..],
        )?;
        writer.member(MemberKind::Index, None, index.len() as u64, &mut &index[..])?;
        for (blob_id, taille) in &blobs {
            let mut fichier = std::fs::File::open(blob_path(path, blob_id))?;
            writer.member(MemberKind::Blob, Some(*blob_id), *taille, &mut fichier)?;
        }
        writer.finish()?;

        Ok(ExportSummary {
            blob_count: blobs.len() as u64,
            payload_bytes,
        })
    }
}

/// Réenveloppe la clé maîtresse sous une passphrase distincte, et rend
/// l'en-tête **fabriqué** qui en résulte (FR-005b).
///
/// La clé maîtresse et tout le contenu restent inchangés : seule l'enveloppe
/// change, comme à `vault passwd` (D-004, C-021).
fn fabriquer_en_tete(
    header: &Header,
    current: &SecretString,
    new: &SecretString,
) -> Result<Vec<u8>> {
    // La longueur se compte en caractères, comme à la création : une règle
    // exprimée en octets serait plus permissive pour les uns que pour les
    // autres.
    if new.expose_secret().chars().count() < MIN_PASSPHRASE_LEN {
        return Err(Error::WeakPassphrase {
            minimum: MIN_PASSPHRASE_LEN,
        });
    }

    let master_key = header.unlock(current)?;
    let mut fabrique = header.clone();
    // Les paramètres de coût du vault source sont conservés : choisir une
    // passphrase distincte pour un conteneur ne doit pas rabaisser
    // silencieusement un coût que l'utilisateur avait relevé.
    fabrique.rewrap(&master_key, new, header.kdf_params())?;
    fabrique.encode()
}

/// Recense les blobs du vault, **triés par identifiant croissant**, avec leur
/// taille sur disque.
///
/// Un fichier de `objects/` dont le nom n'est pas un identifiant de blob est
/// laissé de côté : ce n'est pas un blob, donc pas quelque chose que le format
/// sait transporter. C'est la même règle que le balayage des orphelins, qui ne
/// supprime pas non plus ce qu'il ne reconnaît pas.
fn recenser_blobs(vault_dir: &Path) -> Result<Vec<(BlobId, u64)>> {
    let mut blobs = Vec::new();
    for entree in std::fs::read_dir(vault_dir.join(OBJECTS_DIR))? {
        let entree = entree?;
        let Ok(blob_id) = BlobId::from_hex(&entree.file_name().to_string_lossy()) else {
            continue;
        };
        blobs.push((blob_id, entree.metadata()?.len()));
    }
    // Le tri est ce qui rend l'export déterministe (FR-005c) : un parcours de
    // répertoire ne garantit aucun ordre.
    blobs.sort_unstable_by_key(|(blob_id, _)| *blob_id);
    Ok(blobs)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::crypto::kdf::KdfParams;
    use crate::format::container::{CONTAINER_MAGIC, ContainerReader};
    use crate::fs::lock::LOCK_FILE;
    use crate::{AddMode, OnConflict, VaultPath};

    const PASSPHRASE: &str = "une passphrase bien assez longue";

    fn params() -> KdfParams {
        KdfParams::new(64, 1, 1).expect("paramètres valides")
    }

    fn passphrase() -> SecretString {
        SecretString::from(PASSPHRASE.to_owned())
    }

    /// Un vault peuplé de deux entrées, refermé.
    fn coffre_peuple(atelier: &Path) -> PathBuf {
        let coffre = atelier.join("coffre");
        let mut vault = Vault::create(&coffre, passphrase(), params()).expect("créable");
        for (nom, contenu) in [("note.txt", &b"une note"[..]), ("autre.bin", &[0x2a; 9000])] {
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

    fn exporter(coffre: &Path, envelope: ExportEnvelope) -> Result<(Vec<u8>, ExportSummary)> {
        let mut conteneur = Vec::new();
        let resume = Vault::export(coffre, envelope, &mut conteneur)?;
        Ok((conteneur, resume))
    }

    #[test]
    fn un_export_produit_un_conteneur_lisible() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());

        let (conteneur, resume) = exporter(&coffre, ExportEnvelope::Source).expect("exportable");

        assert_eq!(&conteneur[..0], b"");
        assert!(
            conteneur
                .windows(CONTAINER_MAGIC.len())
                .any(|f| f == CONTAINER_MAGIC),
            "la magie du conteneur doit figurer dans le flux"
        );
        assert_eq!(resume.blob_count, 2);

        let reader = ContainerReader::open(&conteneur[..]).expect("ouvrable");
        assert_eq!(reader.header().member_count, 4);
        assert_eq!(reader.header().payload_bytes, resume.payload_bytes);
        assert_eq!(
            reader.header().vault_format_version,
            crate::FORMAT_VERSION,
            "l'en-tête annonce la version du vault transporté"
        );
    }

    /// FR-005a, XFR-001 : **aucune passphrase n'est demandée**. Le test appelle
    /// l'export sur un vault verrouillé sans jamais construire de
    /// `SecretString` — la signature de `ExportEnvelope::Source` ne permet pas
    /// d'en fournir une.
    #[test]
    fn un_export_par_defaut_n_exige_aucune_passphrase() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());

        let (conteneur, _) = exporter(&coffre, ExportEnvelope::Source).expect("exportable");

        // Le membre `header` est le fichier `header` du vault, à l'octet près :
        // il a été recopié sans être ouvert.
        let source = std::fs::read(coffre.join(HEADER_FILE)).expect("lisible");
        let mut reader = ContainerReader::open(&conteneur[..]).expect("ouvrable");
        let frame = reader.next_frame().expect("cadre").expect("présent");
        let mut membre = Vec::new();
        reader.copy_payload(&frame, &mut membre).expect("charge");
        assert_eq!(frame.kind, MemberKind::Header);
        assert_eq!(membre, source);
    }

    /// FR-005c, XFR-007 : deux exports d'un vault inchangé donnent les **mêmes
    /// octets**, y compris après que l'ordre de parcours du répertoire a changé.
    #[test]
    fn deux_exports_d_un_vault_inchange_donnent_les_memes_octets() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());

        let (premier, _) = exporter(&coffre, ExportEnvelope::Source).expect("exportable");
        let (second, _) = exporter(&coffre, ExportEnvelope::Source).expect("exportable");
        assert_eq!(premier, second);

        // L'ordre de parcours du répertoire est mélangé en recréant les blobs
        // dans l'ordre inverse : le conteneur ne doit pas bouger d'un octet.
        let objets = coffre.join(OBJECTS_DIR);
        let mut noms: Vec<_> = std::fs::read_dir(&objets)
            .expect("listable")
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name())
            .collect();
        noms.sort_unstable();
        noms.reverse();
        for nom in &noms {
            let contenu = std::fs::read(objets.join(nom)).expect("lisible");
            std::fs::remove_file(objets.join(nom)).expect("supprimable");
            std::fs::write(objets.join(nom), contenu).expect("écrivable");
        }

        let (apres, _) = exporter(&coffre, ExportEnvelope::Source).expect("exportable");
        assert_eq!(premier, apres, "le tri des blobs rend l'ordre indifférent");
    }

    /// FR-005b : la variante réenveloppe, donc tire un sel neuf — et le
    /// déterminisme ne s'y applique pas. C'est la **limite** du déterminisme,
    /// éprouvée au même titre que le déterminisme lui-même.
    #[test]
    fn une_passphrase_distincte_produit_des_octets_differents() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());
        let nouvelle = || SecretString::from("une toute autre passphrase, longue".to_owned());

        let (premier, _) = exporter(
            &coffre,
            ExportEnvelope::NewPassphrase {
                current: passphrase(),
                new: nouvelle(),
            },
        )
        .expect("exportable");
        let (second, _) = exporter(
            &coffre,
            ExportEnvelope::NewPassphrase {
                current: passphrase(),
                new: nouvelle(),
            },
        )
        .expect("exportable");

        assert_ne!(premier, second, "un sel neuf est tiré à chaque fois");
        assert_eq!(premier.len(), second.len(), "seule l'enveloppe diffère");

        // Le conteneur s'ouvre avec la nouvelle passphrase, et plus avec
        // l'ancienne.
        let mut reader = ContainerReader::open(&premier[..]).expect("ouvrable");
        let frame = reader.next_frame().expect("cadre").expect("présent");
        let mut membre = Vec::new();
        reader.copy_payload(&frame, &mut membre).expect("charge");
        let fabrique = Header::decode(&membre).expect("décodable");
        assert!(fabrique.unlock(&nouvelle()).is_ok());
        assert!(matches!(
            fabrique.unlock(&passphrase()),
            Err(Error::Authentication)
        ));
    }

    #[test]
    fn une_passphrase_source_erronee_est_refusee() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());

        assert!(matches!(
            exporter(
                &coffre,
                ExportEnvelope::NewPassphrase {
                    current: SecretString::from("une passphrase parfaitement fausse".to_owned()),
                    new: SecretString::from("une toute autre passphrase, longue".to_owned()),
                }
            ),
            Err(Error::Authentication)
        ));
    }

    /// La passphrase distincte suit la même règle de longueur qu'à la création,
    /// et le refus tombe **avant** toute écriture.
    #[test]
    fn une_passphrase_distincte_trop_courte_est_refusee_avant_ecriture() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());

        let mut conteneur = Vec::new();
        assert!(matches!(
            Vault::export(
                &coffre,
                ExportEnvelope::NewPassphrase {
                    current: passphrase(),
                    new: SecretString::from("onze carac".to_owned()),
                },
                &mut conteneur
            ),
            Err(Error::WeakPassphrase { minimum: 12 })
        ));
        assert!(conteneur.is_empty(), "aucun octet ne doit avoir été écrit");
    }

    /// FR-007, XFR-004 : un vault déjà ouvert par une autre instance fait
    /// échouer l'export, sans qu'un octet ne sorte.
    #[test]
    fn un_vault_deja_ouvert_fait_echouer_l_export() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        let session = Vault::create(&coffre, passphrase(), params()).expect("créable");

        let mut conteneur = Vec::new();
        assert!(matches!(
            Vault::export(&coffre, ExportEnvelope::Source, &mut conteneur),
            Err(Error::AlreadyInUse)
        ));
        assert!(conteneur.is_empty());

        // Le verrou rendu, l'export passe — et le rend à son tour.
        session.lock();
        assert!(exporter(&coffre, ExportEnvelope::Source).is_ok());
        let _reprise = VaultLock::acquire(&coffre).expect("le verrou a été rendu");
    }

    /// FR-008, FR-008a : la copie est fidèle — les blobs orphelins partent — et
    /// le support du verrou reste à quai.
    #[test]
    fn l_export_emporte_les_orphelins_et_laisse_le_verrou() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());

        let orphelin = BlobId::generate();
        std::fs::write(blob_path(&coffre, &orphelin), b"dechet inerte").expect("écrivable");
        // Un fichier étranger, qui n'est pas un blob : il n'est pas transporté.
        std::fs::write(coffre.join(OBJECTS_DIR).join("pas-un-blob"), b"etranger")
            .expect("écrivable");
        assert!(
            coffre.join(LOCK_FILE).exists(),
            "le verrou a laissé sa trace"
        );

        let (conteneur, resume) = exporter(&coffre, ExportEnvelope::Source).expect("exportable");
        assert_eq!(resume.blob_count, 3, "l'orphelin est du voyage");

        let mut reader = ContainerReader::open(&conteneur[..]).expect("ouvrable");
        let mut identifiants = Vec::new();
        while let Some(frame) = reader.next_frame().expect("cadre") {
            reader
                .copy_payload(&frame, &mut Vec::new())
                .expect("charge");
            if let Some(id) = frame.id {
                identifiants.push(id);
            }
        }
        reader.finish().expect("scellé");
        assert!(identifiants.contains(&orphelin));
        assert_eq!(identifiants.len(), 3);
    }

    /// FR-009 : le vault source n'est pas modifié, y compris quand l'export
    /// échoue en cours d'écriture.
    #[test]
    fn l_export_ne_modifie_pas_le_vault_source() {
        struct Rompu;
        impl Write for Rompu {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("tube fermé"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(Write::flush(&mut Rompu).is_ok());

        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());
        let avant = empreinte_du_repertoire(&coffre);

        assert!(Vault::export(&coffre, ExportEnvelope::Source, &mut Rompu).is_err());
        assert_eq!(empreinte_du_repertoire(&coffre), avant);

        assert!(exporter(&coffre, ExportEnvelope::Source).is_ok());
        assert_eq!(empreinte_du_repertoire(&coffre), avant);
    }

    /// Empreinte du répertoire d'un vault, `.lock` excepté : c'est ce qui doit
    /// rester identique de part et d'autre d'un export.
    fn empreinte_du_repertoire(coffre: &Path) -> Vec<(String, Vec<u8>)> {
        let mut contenu = Vec::new();
        for entree in walkdir::WalkDir::new(coffre).sort_by_file_name() {
            let entree = entree.expect("parcourable");
            if !entree.file_type().is_file() {
                continue;
            }
            let relatif = entree
                .path()
                .strip_prefix(coffre)
                .expect("sous le vault")
                .to_string_lossy()
                .into_owned();
            if relatif == LOCK_FILE {
                continue;
            }
            contenu.push((relatif, std::fs::read(entree.path()).expect("lisible")));
        }
        contenu
    }

    /// Un écrivain qui accepte l'en-tête du conteneur puis se rompt fait
    /// échouer l'écriture d'un **membre**, et non son ouverture.
    ///
    /// Le cas mérite son propre test : c'est le seul qui traverse la
    /// propagation d'erreur de la boucle des membres, là où le précédent
    /// s'arrête au premier octet.
    #[test]
    fn un_ecrivain_qui_se_rompt_en_cours_de_route_est_signale() {
        /// Accepte `restant` octets, puis refuse tout.
        struct Fragile {
            restant: usize,
        }
        impl Write for Fragile {
            fn write(&mut self, tampon: &[u8]) -> std::io::Result<usize> {
                if self.restant == 0 {
                    return Err(std::io::Error::other("tube fermé"));
                }
                let pris = tampon.len().min(self.restant);
                self.restant -= pris;
                Ok(pris)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(Write::flush(&mut Fragile { restant: 0 }).is_ok());

        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());
        let avant = empreinte_du_repertoire(&coffre);

        // Trois points de rupture, un par étape de l'écriture : l'en-tête du
        // conteneur, le membre `header`, puis un membre suivant. Ils ne rendent
        // pas tous la même erreur — une rupture pendant un **cadre** remonte de
        // l'encodeur CBOR, donc en `Corrupted` ; une rupture pendant une
        // **charge** remonte de la copie, donc en `Io`. Ce qui compte est
        // qu'aucune ne panique et qu'aucune ne touche au vault source.
        let mut verdicts = Vec::new();
        for restant in [40, 200, 400] {
            let mut fragile = Fragile { restant };
            verdicts.push(matches!(
                Vault::export(&coffre, ExportEnvelope::Source, &mut fragile),
                Err(Error::Corrupted | Error::Io(_))
            ));
            // FR-009 : même là, le vault source est intact.
            assert_eq!(empreinte_du_repertoire(&coffre), avant);
        }
        assert_eq!(
            verdicts,
            vec![true; 3],
            "rupture à l'en-tête, au membre header, puis à un membre suivant"
        );
    }

    /// Une défaillance de lecture de l'en-tête qui n'est **pas** une absence
    /// remonte telle quelle, et non déguisée en « introuvable » : dire qu'il
    /// n'y a pas de vault là où il y en a un mais illisible enverrait
    /// l'utilisateur chercher au mauvais endroit.
    #[cfg(unix)]
    #[test]
    fn un_en_tete_illisible_par_permission_remonte_l_erreur() {
        use std::os::unix::fs::PermissionsExt;

        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());
        let en_tete = coffre.join(HEADER_FILE);

        let mut permissions = std::fs::metadata(&en_tete).expect("lisible").permissions();
        permissions.set_mode(0o000);
        std::fs::set_permissions(&en_tete, permissions).expect("modifiable");

        let mut conteneur = Vec::new();
        let resultat = Vault::export(&coffre, ExportEnvelope::Source, &mut conteneur);

        let mut permissions = std::fs::metadata(&en_tete).expect("lisible").permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&en_tete, permissions).expect("modifiable");

        assert!(matches!(resultat, Err(Error::Io(_))), "{resultat:?}");
        assert!(conteneur.is_empty());
    }

    #[test]
    fn un_emplacement_sans_vault_est_introuvable() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let mut conteneur = Vec::new();
        assert!(matches!(
            Vault::export(atelier.path(), ExportEnvelope::Source, &mut conteneur),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn un_en_tete_illisible_est_refuse() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());
        std::fs::write(coffre.join(HEADER_FILE), b"ceci n'est pas un en-tete").expect("écrivable");

        let mut conteneur = Vec::new();
        assert!(matches!(
            Vault::export(&coffre, ExportEnvelope::Source, &mut conteneur),
            Err(Error::Corrupted)
        ));
        assert!(conteneur.is_empty());
    }

    /// Un `objects/` absent fait échouer le recensement plutôt que de produire
    /// un conteneur silencieusement amputé.
    #[test]
    fn un_repertoire_d_objets_absent_est_signale() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = coffre_peuple(atelier.path());
        std::fs::remove_dir_all(coffre.join(OBJECTS_DIR)).expect("supprimable");

        let mut conteneur = Vec::new();
        assert!(matches!(
            Vault::export(&coffre, ExportEnvelope::Source, &mut conteneur),
            Err(Error::Io(_))
        ));
    }

    /// Un vault vide est licite : deux membres, aucun blob.
    #[test]
    fn un_vault_vide_s_exporte() {
        let atelier = tempfile::tempdir().expect("répertoire temporaire");
        let coffre = atelier.path().join("coffre");
        Vault::create(&coffre, passphrase(), params())
            .expect("créable")
            .lock();

        let (conteneur, resume) = exporter(&coffre, ExportEnvelope::Source).expect("exportable");
        assert_eq!(resume.blob_count, 0);
        let reader = ContainerReader::open(&conteneur[..]).expect("ouvrable");
        assert_eq!(reader.header().member_count, 2);
    }

    #[test]
    fn le_resume_a_un_debug() {
        let resume = ExportSummary {
            blob_count: 3,
            payload_bytes: 42,
        };
        assert!(format!("{resume:?}").contains("ExportSummary"));
        assert_eq!(resume, resume);
    }
}
