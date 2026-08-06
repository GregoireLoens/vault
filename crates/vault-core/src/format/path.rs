//! Chemins internes au vault — T017.
//!
//! Un [`VaultPath`] est une suite de composants conservés en **octets bruts**,
//! tels que le système de fichiers les a fournis (VR-I1). Aucune conversion,
//! aucune normalisation Unicode : c'est le seul moyen de restituer un nom à
//! l'identique (FR-015, FR-027) entre des systèmes dont les conventions
//! diffèrent.
//!
//! Conséquence assumée et documentée dans `docs/format.md` : deux noms qui ne
//! diffèrent que par leur normalisation Unicode — `é` composé contre `e` suivi
//! d'un accent combinant — sont **deux entrées distinctes**.
//!
//! Les règles de composition (VR-I4) sont vérifiées à la construction *et* à la
//! désérialisation. Un index forgé ne doit pas pouvoir faire écrire
//! l'extraction hors du répertoire de destination.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Séparateurs de chemin refusés à l'intérieur d'un composant.
///
/// `\` est refusé y compris sur les systèmes où il n'est pas un séparateur :
/// un vault créé sous Unix doit pouvoir s'extraire sous Windows sans qu'un nom
/// de fichier s'y transforme en sous-répertoire.
const SEPARATORS: [u8; 2] = *b"/\\";

/// Chemin relatif d'une entrée dans le vault.
///
/// La racine est le chemin vide.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(
    try_from = "Vec<serde_bytes::ByteBuf>",
    into = "Vec<serde_bytes::ByteBuf>"
)]
pub struct VaultPath {
    components: Vec<Vec<u8>>,
}

impl VaultPath {
    /// La racine du vault : un chemin sans aucun composant.
    #[must_use]
    pub fn root() -> Self {
        Self::default()
    }

    /// Construit un chemin depuis une suite de composants.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPath`] si l'un des composants viole VR-I4.
    pub fn from_components<I, C>(components: I) -> Result<Self>
    where
        I: IntoIterator<Item = C>,
        C: Into<Vec<u8>>,
    {
        let mut path = Self::root();
        for component in components {
            path.push(component.into())?;
        }
        Ok(path)
    }

    /// Ajoute un composant en fin de chemin.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPath`] si le composant est vide, vaut `.` ou `..`,
    /// contient un séparateur de chemin ou un octet nul (VR-I4).
    pub fn push(&mut self, component: impl Into<Vec<u8>>) -> Result<()> {
        let component = component.into();
        validate(&component)?;
        self.components.push(component);
        Ok(())
    }

    /// Renvoie un nouveau chemin prolongé d'un composant.
    ///
    /// # Errors
    ///
    /// Voir [`VaultPath::push`].
    pub fn join(&self, component: impl Into<Vec<u8>>) -> Result<Self> {
        let mut joined = self.clone();
        joined.push(component)?;
        Ok(joined)
    }

    /// Les composants du chemin, dans l'ordre.
    pub fn components(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.components.iter().map(Vec::as_slice)
    }

    /// Vrai s'il s'agit de la racine du vault.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    /// Nombre de composants.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.components.len()
    }

    /// Le dernier composant, ou `None` à la racine.
    #[must_use]
    pub fn file_name(&self) -> Option<&[u8]> {
        self.components.last().map(Vec::as_slice)
    }

    /// Le chemin du parent, ou `None` à la racine.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        if self.is_root() {
            return None;
        }
        let mut parent = self.clone();
        parent.components.pop();
        Some(parent)
    }

    /// Vrai si `self` est `prefix` ou l'un de ses descendants.
    ///
    /// La comparaison porte sur des composants entiers : `photos-2024` n'est
    /// pas un descendant de `photos`.
    #[must_use]
    pub fn starts_with(&self, prefix: &Self) -> bool {
        self.components.len() >= prefix.components.len()
            && self.components[..prefix.components.len()] == prefix.components[..]
    }

    /// Représentation lisible, pour l'affichage uniquement.
    ///
    /// Le remplacement des octets invalides rend cette représentation
    /// **non réversible** : elle ne doit jamais servir à reconstruire un
    /// chemin, seulement à le montrer à un utilisateur.
    #[must_use]
    pub fn to_display_string(&self) -> String {
        self.components
            .iter()
            .map(|component| String::from_utf8_lossy(component).into_owned())
            .collect::<Vec<_>>()
            .join("/")
    }

    /// Convertit en chemin relatif du système de fichiers hôte.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPath`] si un composant n'est pas représentable sur la
    /// plateforme courante — cas qui ne peut survenir que sous Windows, dont
    /// les noms de fichiers sont de l'UTF-16 et non des octets arbitraires.
    pub fn to_os_path(&self) -> Result<std::path::PathBuf> {
        let mut path = std::path::PathBuf::new();
        for component in &self.components {
            path.push(os_component(component)?);
        }
        Ok(path)
    }

    /// Efface les octets du chemin sur place.
    ///
    /// Un nom de fichier réel est une donnée à protéger au même titre qu'un
    /// contenu (principe I) : il ne doit pas rester dans le tas après le
    /// verrouillage de la session.
    pub(crate) fn zeroize(&mut self) {
        use zeroize::Zeroize;
        for component in &mut self.components {
            component.zeroize();
        }
        self.components.clear();
    }

    /// Construit un chemin de vault depuis un chemin relatif de l'hôte.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPath`] si le chemin est absolu, remonte d'un cran, ou
    /// contient un composant que VR-I4 refuse.
    pub fn from_os_path(path: &std::path::Path) -> Result<Self> {
        let mut vault_path = Self::root();
        for component in path.components() {
            match component {
                std::path::Component::Normal(name) => vault_path.push(os_bytes(name))?,
                // Racine, préfixe de volume, `.` et `..` n'ont aucun sens dans
                // un chemin de vault, qui est relatif par construction.
                _ => return Err(Error::InvalidPath),
            }
        }
        Ok(vault_path)
    }
}

/// Vérifie qu'un composant respecte VR-I4.
fn validate(component: &[u8]) -> Result<()> {
    let refuse = component.is_empty()
        || component == b"."
        || component == b".."
        || component
            .iter()
            .any(|byte| SEPARATORS.contains(byte) || *byte == 0);
    if refuse {
        return Err(Error::InvalidPath);
    }
    Ok(())
}

// Le `Result` est inutile sous Unix, où tout octet est un nom de fichier
// valide. Il est conservé pour que les deux variantes aient la même signature :
// sous Windows, la conversion échoue réellement sur un nom non-UTF-8. Une
// signature qui changerait selon la plateforme déplacerait le `#[cfg]` chez
// l'appelant, où il serait bien plus facile à oublier.
#[cfg(unix)]
#[allow(clippy::unnecessary_wraps)]
fn os_component(component: &[u8]) -> Result<std::ffi::OsString> {
    use std::os::unix::ffi::OsStringExt;
    Ok(std::ffi::OsString::from_vec(component.to_vec()))
}

#[cfg(unix)]
fn os_bytes(name: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    name.as_bytes().to_vec()
}

// Sous Windows, un nom de fichier n'est pas une suite d'octets arbitraires
// mais de l'UTF-16 : seuls les composants qui sont de l'UTF-8 valide peuvent
// être restitués. Un vault créé sous Unix avec un nom non-UTF-8 est donc
// listable mais non extractible tel quel sous Windows — la limite est réelle
// et doit apparaître dans `docs/format.md` plutôt que d'être contournée par
// une conversion approximative qui trahirait FR-027.
//
// Ces deux fonctions n'existent pas dans la compilation Linux : elles ne
// créent donc aucune ligne non couverte sur la plateforme d'intégration
// continue, et sont exercées par la matrice Windows de la CI.
#[cfg(windows)]
fn os_component(component: &[u8]) -> Result<std::ffi::OsString> {
    match std::str::from_utf8(component) {
        Ok(text) => Ok(std::ffi::OsString::from(text)),
        Err(_) => Err(Error::InvalidPath),
    }
}

#[cfg(windows)]
fn os_bytes(name: &std::ffi::OsStr) -> Vec<u8> {
    name.to_string_lossy().into_owned().into_bytes()
}

impl TryFrom<Vec<serde_bytes::ByteBuf>> for VaultPath {
    type Error = Error;

    fn try_from(components: Vec<serde_bytes::ByteBuf>) -> Result<Self> {
        Self::from_components(components.into_iter().map(serde_bytes::ByteBuf::into_vec))
    }
}

impl From<VaultPath> for Vec<serde_bytes::ByteBuf> {
    fn from(path: VaultPath) -> Self {
        path.components
            .into_iter()
            .map(serde_bytes::ByteBuf::from)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chemin(composants: &[&[u8]]) -> VaultPath {
        VaultPath::from_components(composants.iter().map(|c| c.to_vec())).expect("chemin valide")
    }

    #[test]
    fn la_racine_est_vide() {
        let racine = VaultPath::root();
        assert!(racine.is_root());
        assert_eq!(racine.depth(), 0);
        assert_eq!(racine.file_name(), None);
        assert_eq!(racine.parent(), None);
        assert_eq!(racine.to_display_string(), "");
        assert_eq!(racine.components().len(), 0);
    }

    #[test]
    fn un_chemin_conserve_ses_composants() {
        let path = chemin(&[b"photos", b"2024", b"plage.jpg"]);
        assert_eq!(path.depth(), 3);
        assert_eq!(path.file_name(), Some(&b"plage.jpg"[..]));
        assert_eq!(path.to_display_string(), "photos/2024/plage.jpg");
        assert_eq!(path.parent(), Some(chemin(&[b"photos", b"2024"])));
        assert_eq!(
            path.components().collect::<Vec<_>>(),
            vec![&b"photos"[..], &b"2024"[..], &b"plage.jpg"[..]]
        );
    }

    /// VR-I1 : les octets sont conservés tels quels, sans normalisation.
    #[test]
    fn les_octets_ne_sont_pas_normalises() {
        let compose = chemin(&["é".as_bytes()]);
        let decompose = chemin(&["e\u{0301}".as_bytes()]);
        assert_ne!(compose, decompose);

        let non_utf8 = chemin(&[&[0xff, 0xfe]]);
        assert_eq!(non_utf8.file_name(), Some(&[0xff, 0xfe][..]));
    }

    /// VR-I4 : la liste exhaustive des composants refusés.
    #[test]
    fn les_composants_hostiles_sont_refuses() {
        let hostiles: [&[u8]; 6] = [b"", b".", b"..", b"a/b", b"a\\b", b"a\0b"];
        let refuses: Vec<bool> = hostiles
            .iter()
            .map(|hostile| VaultPath::from_components([hostile.to_vec()]).is_err())
            .collect();
        assert_eq!(refuses, vec![true; hostiles.len()], "{hostiles:?}");
    }

    #[test]
    fn push_et_join_valident_aussi() {
        let mut path = VaultPath::root();
        assert!(path.push(b"ok".to_vec()).is_ok());
        assert!(matches!(path.push(b"..".to_vec()), Err(Error::InvalidPath)));
        assert_eq!(
            path.depth(),
            1,
            "un composant refusé ne doit pas être ajouté"
        );

        assert_eq!(path.join(b"enfant".to_vec()).expect("valide").depth(), 2);
        assert!(matches!(path.join(b"".to_vec()), Err(Error::InvalidPath)));
    }

    #[test]
    fn starts_with_compare_des_composants_entiers() {
        let photos = chemin(&[b"photos"]);
        assert!(chemin(&[b"photos", b"a.jpg"]).starts_with(&photos));
        assert!(photos.starts_with(&photos));
        assert!(photos.starts_with(&VaultPath::root()));
        assert!(!chemin(&[b"photos-2024"]).starts_with(&photos));
        assert!(!VaultPath::root().starts_with(&photos));
    }

    #[test]
    fn aller_retour_avec_un_chemin_du_systeme() {
        let path = chemin(&[b"dossier", b"fichier.txt"]);
        let os = path.to_os_path().expect("représentable");
        assert_eq!(VaultPath::from_os_path(&os).expect("relisible"), path);
    }

    #[test]
    fn un_chemin_du_systeme_hostile_est_refuse() {
        let hostiles = ["/absolu", "../evasion", "./ici"];
        let refuses: Vec<bool> = hostiles
            .iter()
            .map(|hostile| VaultPath::from_os_path(std::path::Path::new(hostile)).is_err())
            .collect();
        assert_eq!(refuses, vec![true; hostiles.len()], "{hostiles:?}");
        assert!(
            VaultPath::from_os_path(std::path::Path::new(""))
                .expect("le chemin vide est la racine")
                .is_root()
        );
    }

    #[test]
    fn la_serialisation_cbor_fait_un_aller_retour() {
        let path = chemin(&[b"photos", &[0xff, 0x00_u8.wrapping_add(1)]]);
        let mut encoded = Vec::new();
        ciborium::into_writer(&path, &mut encoded).expect("encodable");
        let decoded: VaultPath = ciborium::from_reader(&encoded[..]).expect("décodable");
        assert_eq!(decoded, path);
    }

    /// VR-I4 vaut aussi à la désérialisation : un index forgé ne doit pas
    /// pouvoir faire remonter l'extraction hors de sa destination.
    #[test]
    fn la_deserialisation_refuse_un_chemin_forge() {
        let forge: Vec<serde_bytes::ByteBuf> = vec![serde_bytes::ByteBuf::from(b"..".to_vec())];
        let mut encoded = Vec::new();
        ciborium::into_writer(&forge, &mut encoded).expect("encodable");
        let decoded: std::result::Result<VaultPath, _> = ciborium::from_reader(&encoded[..]);
        assert!(decoded.is_err());
    }

    #[test]
    fn l_effacement_vide_le_chemin() {
        let mut path = chemin(&[b"photos", b"prive.jpg"]);
        path.zeroize();
        assert!(path.is_root());
        assert_eq!(path.to_display_string(), "");
    }

    #[test]
    fn l_ordre_est_total_et_deterministe() {
        let mut chemins = vec![chemin(&[b"b"]), chemin(&[b"a", b"z"]), chemin(&[b"a"])];
        chemins.sort();
        assert_eq!(
            chemins,
            vec![chemin(&[b"a"]), chemin(&[b"a", b"z"]), chemin(&[b"b"])]
        );
    }
}
