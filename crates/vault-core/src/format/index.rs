//! Index chiffré du vault — T024.
//!
//! L'index porte tout ce qui caractérise le contenu : arborescence, noms
//! réels, tailles réelles, dates, identifiants de blobs. Il est encodé en CBOR
//! puis **chiffré intégralement** avec la clé maîtresse. C'est lui qui fait que
//! `objects/` ne contient que des fichiers opaques aux noms aléatoires
//! (FR-036).
//!
//! **VR-I5** : l'index est réécrit *intégralement* à chaque modification, puis
//! remplacé atomiquement. Aucune écriture en place, aucune mise à jour
//! partielle. C'est aussi ce qui en fait le **point d'engagement** du vault
//! (D-008) : un blob écrit mais non référencé ici n'existe pas du point de vue
//! du vault, c'est un déchet inerte et non une corruption.
//!
//! # Écart assumé avec `data-model.md`
//!
//! Le modèle de données plaçait `index_nonce` dans l'en-tête. Il est ici en
//! tête du fichier `index`. Le nonce doit changer à chaque réécriture de
//! l'index ; le laisser dans l'en-tête obligerait à remplacer deux fichiers
//! pour une seule modification, et une interruption entre les deux laisserait
//! un en-tête pointant un nonce qui n'est plus celui de l'index — donc un
//! vault ouvrable mais dont l'index serait indéchiffrable. Placer le nonce
//! dans le fichier qu'il protège ramène l'opération à **un seul** remplacement
//! atomique. C'est aussi ce qui rend vraie l'affirmation de C-021 selon
//! laquelle un changement de passphrase « ne réécrit que l'en-tête » : avec le
//! nonce dans l'en-tête, celui-ci aurait été réécrit à chaque ajout de fichier.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::crypto::aead::{self, NONCE_LEN, TAG_LEN};
use crate::crypto::keys::{INDEX_DOMAIN, MasterKey};
use crate::error::{Error, Result};
use crate::format::blob::BlobId;
use crate::format::path::VaultPath;

/// Nature d'une entrée.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    /// Fichier ordinaire, stocké dans un blob.
    File,
    /// Dossier, qui n'occupe aucun blob.
    Directory,
}

/// Une entrée telle qu'elle est stockée dans l'index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct IndexEntry {
    /// Chemin relatif dans le vault.
    pub path: VaultPath,
    /// Fichier ou dossier.
    pub kind: EntryKind,
    /// Taille **réelle**, avant remplissage. Absente pour un dossier (VR-I2).
    pub size: Option<u64>,
    /// Date de modification d'origine, en secondes Unix.
    pub modified: i64,
    /// Identifiant du blob. Absent pour un dossier.
    pub blob_id: Option<BlobId>,
    /// Taille du blob après remplissage. Absente pour un dossier.
    pub blob_padded_size: Option<u64>,
}

/// Représentation sérialisée de l'index.
#[derive(Serialize, Deserialize)]
struct IndexRepr {
    index_version: u64,
    entries: Vec<IndexEntry>,
}

/// Index d'un vault déverrouillé.
///
/// Les entrées sont maintenues triées par chemin : l'ordre de l'index ne doit
/// pas dépendre de l'ordre dans lequel les fichiers ont été ajoutés, sans quoi
/// il trahirait la chronologie des ajouts (dans l'esprit de VR-B5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Index {
    index_version: u64,
    entries: Vec<IndexEntry>,
}

impl Index {
    /// Index d'un vault neuf : aucune entrée.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Numéro de révision, incrémenté à chaque modification.
    pub(crate) fn index_version(&self) -> u64 {
        self.index_version
    }

    /// L'entrée située à ce chemin.
    pub(crate) fn get(&self, path: &VaultPath) -> Option<&IndexEntry> {
        self.position(path).ok().map(|index| &self.entries[index])
    }

    /// Les entrées situées sous ce chemin, lui compris s'il existe.
    pub(crate) fn list(&self, under: &VaultPath) -> Vec<&IndexEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.path.starts_with(under))
            .collect()
    }

    /// Ajoute une entrée, ou remplace celle qui occupe déjà ce chemin.
    ///
    /// Renvoie l'entrée remplacée, dont l'appelant devra délier le blob
    /// (VR-B6). Sert [`crate::OnConflict::Replace`].
    pub(crate) fn replace(&mut self, entry: IndexEntry) -> Option<IndexEntry> {
        self.index_version += 1;
        match self.position(&entry.path) {
            Ok(position) => Some(std::mem::replace(&mut self.entries[position], entry)),
            Err(position) => {
                self.entries.insert(position, entry);
                None
            }
        }
    }

    // Dérogation datée : la suppression relève de la phase 5 (T058 et
    // suivantes) et le balayage des blobs orphelins de T054. Les deux sont
    // écrits et testés ici parce qu'ils font partie du format ; leurs appelants
    // arrivent avec ces tâches.
    #[allow(dead_code)]
    /// Retire une entrée et, si `recursive`, toute sa descendance.
    ///
    /// Renvoie les entrées retirées : l'appelant délie leurs blobs **après**
    /// avoir réécrit l'index (C-020, VR-B6).
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] si aucune entrée n'occupe ce chemin ;
    /// - [`Error::DirectoryNotEmpty`] si l'entrée a une descendance et que
    ///   `recursive` est faux.
    pub(crate) fn remove(&mut self, path: &VaultPath, recursive: bool) -> Result<Vec<IndexEntry>> {
        if self.position(path).is_err() {
            return Err(Error::NotFound);
        }
        let descendants = self
            .entries
            .iter()
            .filter(|entry| entry.path.starts_with(path) && &entry.path != path)
            .count();
        if descendants > 0 && !recursive {
            return Err(Error::DirectoryNotEmpty);
        }

        let mut removed = Vec::new();
        self.entries.retain(|entry| {
            if entry.path.starts_with(path) {
                removed.push(entry.clone());
                false
            } else {
                true
            }
        });
        self.index_version += 1;
        Ok(removed)
    }

    /// Tous les identifiants de blobs référencés.
    ///
    /// VR-I6 : un blob présent dans `objects/` mais absent de cet ensemble est
    /// un déchet, supprimable au déverrouillage suivant.
    #[allow(dead_code)]
    pub(crate) fn referenced_blobs(&self) -> BTreeSet<BlobId> {
        self.entries
            .iter()
            .filter_map(|entry| entry.blob_id)
            .collect()
    }

    /// Efface l'index sur place.
    ///
    /// VR-S1, VR-S2 : l'index déchiffré porte les noms réels et
    /// l'arborescence. Le laisser au ramassage ordinaire de la mémoire
    /// laisserait ces octets en clair dans le tas jusqu'à leur réutilisation.
    pub(crate) fn zeroize(&mut self) {
        for entry in &mut self.entries {
            entry.path.zeroize();
        }
        self.entries.clear();
        self.index_version = 0;
    }

    /// Chiffre l'index pour écriture sur disque.
    ///
    /// Produit `nonce ‖ chiffré ‖ tag`. Le nonce est tiré neuf à chaque appel :
    /// deux réécritures successives du même contenu donnent deux fichiers
    /// différents, et ne révèlent donc pas qu'il n'a pas changé.
    ///
    /// # Errors
    ///
    /// [`Error::Corrupted`] si l'encodage CBOR échoue.
    pub(crate) fn encrypt(&self, master_key: &MasterKey) -> Result<Vec<u8>> {
        let repr = IndexRepr {
            index_version: self.index_version,
            entries: self.entries.clone(),
        };
        let mut plaintext = Vec::new();
        ciborium::into_writer(&repr, &mut plaintext).map_err(|_| Error::Corrupted)?;

        let nonce = aead::random_nonce();
        let sealed = aead::seal(master_key.expose(), &nonce, INDEX_DOMAIN, &plaintext)?;

        let mut file = Vec::with_capacity(NONCE_LEN + sealed.len());
        file.extend_from_slice(&nonce);
        file.extend_from_slice(&sealed);
        Ok(file)
    }

    /// Déchiffre un index lu sur disque.
    ///
    /// # Errors
    ///
    /// - [`Error::Authentication`] si l'index ne s'authentifie pas — clé
    ///   erronée ou fichier altéré ;
    /// - [`Error::Corrupted`] si le fichier est trop court pour contenir un
    ///   nonce et un tag, si le CBOR est illisible, ou si l'index authentifié
    ///   viole ses propres invariants.
    pub(crate) fn decrypt(master_key: &MasterKey, bytes: &[u8]) -> Result<Self> {
        if bytes.len() < NONCE_LEN + TAG_LEN {
            return Err(Error::Corrupted);
        }
        let (nonce, sealed) = bytes.split_at(NONCE_LEN);
        let nonce: aead::Nonce = nonce.try_into().map_err(|_| Error::Corrupted)?;

        let plaintext = aead::open(master_key.expose(), &nonce, INDEX_DOMAIN, sealed)?;
        let repr: IndexRepr =
            ciborium::from_reader(plaintext.as_slice()).map_err(|_| Error::Corrupted)?;

        let index = Self {
            index_version: repr.index_version,
            entries: repr.entries,
        };
        index.check_invariants()?;
        Ok(index)
    }

    /// Vérifie les invariants d'un index déchiffré.
    ///
    /// L'index est authentifié, donc produit par quelqu'un qui détient la clé
    /// maîtresse. La vérification n'en reste pas moins nécessaire : un vault
    /// forgé par un tiers *puis remis à sa victime* ne doit pas pouvoir faire
    /// écrire l'extraction hors de sa destination, ni faire boucler la
    /// résolution d'un chemin.
    fn check_invariants(&self) -> Result<()> {
        let ordonne = self
            .entries
            .windows(2)
            .all(|paire| paire[0].path < paire[1].path);
        if !ordonne {
            return Err(Error::Corrupted);
        }
        for entry in &self.entries {
            let coherent = match entry.kind {
                EntryKind::File => {
                    entry.size.is_some()
                        && entry.blob_id.is_some()
                        && entry.blob_padded_size.is_some()
                }
                EntryKind::Directory => {
                    entry.size.is_none()
                        && entry.blob_id.is_none()
                        && entry.blob_padded_size.is_none()
                }
            };
            if !coherent {
                return Err(Error::Corrupted);
            }
        }
        Ok(())
    }

    fn position(&self, path: &VaultPath) -> std::result::Result<usize, usize> {
        self.entries.binary_search_by(|entry| entry.path.cmp(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chemin(composants: &[&[u8]]) -> VaultPath {
        VaultPath::from_components(composants.iter().map(|c| c.to_vec())).expect("chemin valide")
    }

    fn fichier(path: VaultPath, size: u64) -> IndexEntry {
        IndexEntry {
            path,
            kind: EntryKind::File,
            size: Some(size),
            modified: 1_700_000_000,
            blob_id: Some(BlobId::generate()),
            blob_padded_size: Some(4096),
        }
    }

    fn dossier(path: VaultPath) -> IndexEntry {
        IndexEntry {
            path,
            kind: EntryKind::Directory,
            size: None,
            modified: 1_700_000_000,
            blob_id: None,
            blob_padded_size: None,
        }
    }

    fn index_peuple() -> Index {
        let mut index = Index::new();
        index.replace(dossier(chemin(&[b"photos"])));
        index.replace(fichier(chemin(&[b"photos", b"a.jpg"]), 10));
        index.replace(fichier(chemin(&[b"photos", b"b.jpg"]), 20));
        index.replace(fichier(chemin(&[b"notes.txt"]), 30));
        index
    }

    #[test]
    fn un_index_neuf_est_vide() {
        let index = Index::new();
        assert_eq!(index.list(&VaultPath::root()).len(), 0);
        assert_eq!(index.index_version(), 0);
        assert_eq!(index.list(&VaultPath::root()).len(), 0);
        assert!(index.referenced_blobs().is_empty());
        assert!(index.get(&chemin(&[b"absent"])).is_none());
    }

    #[test]
    fn les_entrees_restent_triees_quel_que_soit_l_ordre_d_ajout() {
        let index = index_peuple();
        let chemins: Vec<_> = index
            .list(&VaultPath::root())
            .into_iter()
            .map(|entry| entry.path.clone())
            .collect();
        let mut attendus = chemins.clone();
        attendus.sort();
        assert_eq!(chemins, attendus);
        assert_eq!(index.list(&VaultPath::root()).len(), 4);
        assert_eq!(index.index_version(), 4);
    }

    /// VR-I3 : deux entrées ne peuvent pas partager le même chemin. C'est
    /// `replace` qui le garantit — écrire au même chemin remplace, et ne
    /// duplique jamais. La *politique* de collision, elle, est appliquée en
    /// amont par [`crate::ops`], qui décide de refuser, remplacer ou renommer.
    #[test]
    fn deux_entrees_ne_peuvent_pas_partager_un_chemin() {
        let mut index = index_peuple();
        index.replace(fichier(chemin(&[b"notes.txt"]), 1));

        assert_eq!(index.list(&VaultPath::root()).len(), 4);
        let chemins: Vec<_> = index
            .list(&VaultPath::root())
            .into_iter()
            .map(|entree| entree.path.clone())
            .collect();
        let mut uniques = chemins.clone();
        uniques.dedup();
        assert_eq!(chemins, uniques);
    }

    #[test]
    fn remplacer_rend_l_entree_evincee() {
        let mut index = index_peuple();
        let ancienne = index
            .replace(fichier(chemin(&[b"notes.txt"]), 99))
            .expect("une entrée était présente");
        assert_eq!(ancienne.size, Some(30));
        assert_eq!(
            index.get(&chemin(&[b"notes.txt"])).expect("présente").size,
            Some(99)
        );

        assert!(index.replace(fichier(chemin(&[b"neuf.txt"]), 1)).is_none());
        assert_eq!(index.list(&VaultPath::root()).len(), 5);
    }

    #[test]
    fn lister_ne_rend_que_la_descendance() {
        let index = index_peuple();
        assert_eq!(index.list(&VaultPath::root()).len(), 4);
        assert_eq!(index.list(&chemin(&[b"photos"])).len(), 3);
        assert_eq!(index.list(&chemin(&[b"notes.txt"])).len(), 1);
        assert!(index.list(&chemin(&[b"absent"])).is_empty());
    }

    #[test]
    fn supprimer_rend_les_entrees_retirees() {
        let mut index = index_peuple();
        let retirees = index
            .remove(&chemin(&[b"photos"]), true)
            .expect("retirable");
        assert_eq!(retirees.len(), 3);
        assert_eq!(index.list(&VaultPath::root()).len(), 1);
        assert!(index.get(&chemin(&[b"photos", b"a.jpg"])).is_none());
    }

    #[test]
    fn supprimer_refuse_un_dossier_peuple_sans_recursion() {
        let mut index = index_peuple();
        assert!(matches!(
            index.remove(&chemin(&[b"photos"]), false),
            Err(Error::DirectoryNotEmpty)
        ));
        assert_eq!(index.list(&VaultPath::root()).len(), 4);

        assert!(matches!(
            index.remove(&chemin(&[b"absent"]), true),
            Err(Error::NotFound)
        ));

        // Une feuille se retire sans récursion.
        assert_eq!(
            index
                .remove(&chemin(&[b"notes.txt"]), false)
                .expect("retirable")
                .len(),
            1
        );
    }

    #[test]
    fn les_blobs_references_sont_ceux_des_fichiers() {
        let index = index_peuple();
        assert_eq!(
            index.referenced_blobs().len(),
            3,
            "les dossiers n'ont pas de blob"
        );
    }

    #[test]
    fn l_index_fait_l_aller_retour_chiffre() {
        let master = MasterKey::generate();
        let index = index_peuple();

        let chiffre = index.encrypt(&master).expect("chiffrable");
        assert!(chiffre.len() > NONCE_LEN + TAG_LEN);
        // FR-036 : aucun nom réel ne doit transparaître.
        assert!(!chiffre.windows(9).any(|f| f == b"notes.txt"));

        let relu = Index::decrypt(&master, &chiffre).expect("déchiffrable");
        assert_eq!(relu, index);
    }

    #[test]
    fn deux_chiffrements_du_meme_index_different() {
        let master = MasterKey::generate();
        let index = index_peuple();
        assert_ne!(
            index.encrypt(&master).expect("chiffrable"),
            index.encrypt(&master).expect("chiffrable"),
            "un nonce neuf à chaque écriture"
        );
    }

    #[test]
    fn un_index_altere_ou_etranger_est_refuse() {
        let master = MasterKey::generate();
        let autre = MasterKey::generate();
        let chiffre = index_peuple().encrypt(&master).expect("chiffrable");

        assert!(matches!(
            Index::decrypt(&autre, &chiffre),
            Err(Error::Authentication)
        ));

        let mut altere = chiffre.clone();
        let dernier = altere.len() - 1;
        altere[dernier] ^= 0x01;
        assert!(matches!(
            Index::decrypt(&master, &altere),
            Err(Error::Authentication)
        ));

        assert!(matches!(
            Index::decrypt(&master, b""),
            Err(Error::Corrupted)
        ));
        assert!(matches!(
            Index::decrypt(&master, &chiffre[..NONCE_LEN + TAG_LEN - 1]),
            Err(Error::Corrupted)
        ));
    }

    /// Un vault forgé par un tiers puis remis à sa victime ne doit pas passer
    /// les invariants, même s'il est correctement authentifié.
    #[test]
    fn un_index_forge_est_refuse_malgre_son_authentification() {
        let master = MasterKey::generate();

        let sceller = |repr: &IndexRepr| {
            let mut plaintext = Vec::new();
            ciborium::into_writer(repr, &mut plaintext).expect("encodable");
            let nonce = aead::random_nonce();
            let sealed =
                aead::seal(master.expose(), &nonce, INDEX_DOMAIN, &plaintext).expect("scellable");
            let mut file = nonce.to_vec();
            file.extend_from_slice(&sealed);
            file
        };

        let desordonne = IndexRepr {
            index_version: 1,
            entries: vec![fichier(chemin(&[b"z"]), 1), fichier(chemin(&[b"a"]), 1)],
        };
        assert!(matches!(
            Index::decrypt(&master, &sceller(&desordonne)),
            Err(Error::Corrupted)
        ));

        let doublon = IndexRepr {
            index_version: 1,
            entries: vec![fichier(chemin(&[b"a"]), 1), fichier(chemin(&[b"a"]), 2)],
        };
        assert!(matches!(
            Index::decrypt(&master, &sceller(&doublon)),
            Err(Error::Corrupted)
        ));

        let dossier_avec_blob = IndexRepr {
            index_version: 1,
            entries: vec![IndexEntry {
                blob_id: Some(BlobId::generate()),
                ..dossier(chemin(&[b"a"]))
            }],
        };
        assert!(matches!(
            Index::decrypt(&master, &sceller(&dossier_avec_blob)),
            Err(Error::Corrupted)
        ));

        let fichier_sans_blob = IndexRepr {
            index_version: 1,
            entries: vec![IndexEntry {
                blob_id: None,
                ..fichier(chemin(&[b"a"]), 1)
            }],
        };
        assert!(matches!(
            Index::decrypt(&master, &sceller(&fichier_sans_blob)),
            Err(Error::Corrupted)
        ));

        let cbor_illisible = {
            let nonce = aead::random_nonce();
            let sealed = aead::seal(
                master.expose(),
                &nonce,
                INDEX_DOMAIN,
                b"pas du CBOR d'index",
            )
            .expect("scellable");
            let mut file = nonce.to_vec();
            file.extend_from_slice(&sealed);
            file
        };
        assert!(matches!(
            Index::decrypt(&master, &cbor_illisible),
            Err(Error::Corrupted)
        ));
    }

    #[test]
    fn les_entrees_gardent_leurs_octets_bruts() {
        let master = MasterKey::generate();
        let mut index = Index::new();
        index.replace(fichier(chemin(&[&[0xff, 0xfe, b'x']]), 1));

        let relu = Index::decrypt(&master, &index.encrypt(&master).expect("chiffrable"))
            .expect("déchiffrable");
        assert_eq!(
            relu.list(&VaultPath::root())[0].path.file_name(),
            Some(&[0xff, 0xfe, b'x'][..])
        );
    }

    /// VR-S1 : après effacement, l'index ne contient plus rien — ni entrées,
    /// ni numéro de révision.
    #[test]
    fn l_effacement_vide_l_index() {
        let mut index = index_peuple();
        index.zeroize();
        assert_eq!(index.list(&VaultPath::root()).len(), 0);
        assert_eq!(index.index_version(), 0);
        assert_eq!(index, Index::new());
    }

    #[test]
    fn le_debug_et_l_egalite_existent() {
        let index = index_peuple();
        assert!(format!("{index:?}").contains("Index"));
        assert_eq!(index.clone(), index);
        assert_ne!(index, Index::new());
        assert_eq!(EntryKind::File, EntryKind::File);
        assert_ne!(EntryKind::File, EntryKind::Directory);
        assert!(format!("{:?}", EntryKind::Directory).contains("Directory"));
    }
}
