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
    /// [`Error::UnrepresentableName`] si un composant n'est pas représentable
    /// sous les règles de nommage de la plateforme courante — voir
    /// [`NamingRules`].
    pub fn to_os_path(&self) -> Result<std::path::PathBuf> {
        self.to_os_path_under(NamingRules::current())
    }

    /// Convertit en chemin relatif sous un jeu de règles donné.
    ///
    /// Publiée pour deux raisons : elle permet de savoir **avant** un transfert
    /// si un vault s'extraira sur une plateforme donnée, et elle rend le refus
    /// vérifiable depuis n'importe quel système — sans quoi la branche de refus
    /// ne serait exercée que sur les plateformes qui la déclenchent.
    ///
    /// # Errors
    ///
    /// [`Error::UnrepresentableName`] si un composant n'est pas représentable
    /// sous ces règles.
    pub fn to_os_path_under(&self, rules: NamingRules) -> Result<std::path::PathBuf> {
        let mut path = std::path::PathBuf::new();
        for component in &self.components {
            if !rules.accepts(component) {
                return Err(Error::UnrepresentableName);
            }
            path.push(os_component(component));
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

/// Ce qu'un système de fichiers hôte accepte comme nom de fichier.
///
/// VR-I1 impose de conserver les noms en octets bruts, et c'est ce qui permet de
/// les restituer à l'identique. Mais **tous les hôtes n'acceptent pas toutes les
/// suites d'octets**, et un vault se transporte d'une plateforme à l'autre :
///
/// | Plateforme | Contrainte |
/// |---|---|
/// | Linux et la plupart des systèmes POSIX | tout octet sauf `/` et l'octet nul |
/// | macOS — APFS et HFS+ | UTF-8 valide obligatoire ; le noyau refuse le reste |
/// | Windows — NTFS | UTF-8 valide, sans `< > : " \| ? *` ni caractère de contrôle, sans point ni espace final, et hors noms de périphériques réservés |
///
/// Ces règles sont énumérées ici plutôt que dispersées dans du code conditionnel
/// pour deux raisons : elles sont **vérifiables sur n'importe quelle
/// plateforme**, et l'extraction peut refuser proprement, avant d'écrire quoi
/// que ce soit, plutôt que de laisser le système rendre une erreur opaque au
/// milieu d'une arborescence à moitié extraite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamingRules {
    /// Tout octet, hors ceux que VR-I4 écarte déjà.
    Bytes,
    /// UTF-8 valide obligatoire.
    Utf8,
    /// UTF-8 valide, plus les interdits propres à Windows.
    Windows,
}

impl NamingRules {
    /// Les règles de la plateforme courante.
    #[must_use]
    #[cfg(windows)]
    pub const fn current() -> Self {
        Self::Windows
    }

    /// Les règles de la plateforme courante.
    #[must_use]
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub const fn current() -> Self {
        Self::Utf8
    }

    /// Les règles de la plateforme courante.
    #[must_use]
    #[cfg(not(any(windows, target_os = "macos", target_os = "ios")))]
    pub const fn current() -> Self {
        Self::Bytes
    }

    /// Vrai si ce composant est représentable sous ces règles.
    #[must_use]
    pub fn accepts(self, component: &[u8]) -> bool {
        match self {
            Self::Bytes => true,
            Self::Utf8 => std::str::from_utf8(component).is_ok(),
            Self::Windows => std::str::from_utf8(component).is_ok_and(windows_accepts),
        }
    }
}

/// Caractères que NTFS refuse dans un nom de fichier.
const WINDOWS_FORBIDDEN: [char; 7] = ['<', '>', ':', '"', '|', '?', '*'];

/// Vrai si Windows accepte ce nom.
fn windows_accepts(nom: &str) -> bool {
    !nom.chars()
        .any(|c| WINDOWS_FORBIDDEN.contains(&c) || c.is_control())
        && !nom.ends_with('.')
        && !nom.ends_with(' ')
        && !est_nom_reserve(nom)
}

/// Vrai si le nom est celui d'un périphérique réservé de Windows.
///
/// La comparaison porte sur le tronc, extension exclue : `CON.txt` est réservé
/// au même titre que `CON`.
fn est_nom_reserve(nom: &str) -> bool {
    let tronc = nom.split('.').next().unwrap_or(nom).to_ascii_uppercase();
    if matches!(tronc.as_str(), "CON" | "PRN" | "AUX" | "NUL") {
        return true;
    }
    ["COM", "LPT"].into_iter().any(|prefixe| {
        tronc.strip_prefix(prefixe).is_some_and(|reste| {
            reste.len() == 1 && reste.starts_with(|c: char| c.is_ascii_digit())
        })
    })
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

// La représentabilité a déjà été vérifiée par `NamingRules::accepts` : ces
// conversions ne peuvent plus échouer, et n'ont donc pas à rendre un `Result`.
#[cfg(unix)]
fn os_component(component: &[u8]) -> std::ffi::OsString {
    use std::os::unix::ffi::OsStringExt;
    std::ffi::OsString::from_vec(component.to_vec())
}

#[cfg(unix)]
fn os_bytes(name: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    name.as_bytes().to_vec()
}

// Sous Windows, un nom de fichier est de l'UTF-16 : `NamingRules::Windows` a
// déjà garanti que le composant est de l'UTF-8 valide, si bien que la
// conversion « avec perte » n'en subit aucune.
//
// Ce code n'existe pas dans la compilation Linux : il ne crée aucune ligne non
// couverte sur la plateforme d'intégration continue, et la matrice Windows de
// la CI l'exerce.
#[cfg(windows)]
fn os_component(component: &[u8]) -> std::ffi::OsString {
    std::ffi::OsString::from(String::from_utf8_lossy(component).into_owned())
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

    /// Les trois jeux de règles, vérifiés depuis n'importe quelle plateforme.
    #[test]
    fn les_regles_de_nommage_disent_ce_que_chaque_hote_accepte() {
        let portable = b"photo-01 (copie).jpg";
        for regles in [NamingRules::Bytes, NamingRules::Utf8, NamingRules::Windows] {
            assert!(regles.accepts(portable), "{regles:?}");
        }

        // Octets non-UTF-8 : Linux les accepte, macOS et Windows non.
        let non_utf8 = &[0xff, 0xfe][..];
        assert!(NamingRules::Bytes.accepts(non_utf8));
        assert!(!NamingRules::Utf8.accepts(non_utf8));
        assert!(!NamingRules::Windows.accepts(non_utf8));

        // Interdits propres à Windows, tous de l'UTF-8 valide par ailleurs.
        // Les verdicts sont collectés puis comparés d'un bloc : un message de
        // diagnostic par itération ne serait jamais évalué, donc jamais
        // couvert (principe VIII).
        let refuses_par_windows: [&[u8]; 17] = [
            b"deux:points",
            b"eto*ile",
            b"interro?gation",
            b"chevron<",
            b"chevron>",
            b"barre|verticale",
            b"guillemet\"",
            b"controle\x01",
            b"point.final.",
            b"espace final ",
            b"CON",
            b"con.txt",
            b"NUL",
            b"aux",
            b"PRN.log",
            b"COM1",
            b"lpt9.txt",
        ];
        let verdicts: Vec<(bool, bool)> = refuses_par_windows
            .iter()
            .map(|nom| {
                (
                    NamingRules::Utf8.accepts(nom),
                    NamingRules::Windows.accepts(nom),
                )
            })
            .collect();
        assert_eq!(
            verdicts,
            vec![(true, false); refuses_par_windows.len()],
            "{refuses_par_windows:?}"
        );

        // Ces noms ressemblent à des réservés sans en être.
        let acceptes: [&[u8]; 4] = [b"CONTACT", b"COM", b"COM10", b"NULLE"];
        let verdicts: Vec<bool> = acceptes
            .iter()
            .map(|nom| NamingRules::Windows.accepts(nom))
            .collect();
        assert_eq!(verdicts, vec![true; acceptes.len()], "{acceptes:?}");

        assert_eq!(NamingRules::current(), NamingRules::current());
        assert!(format!("{:?}", NamingRules::Bytes).contains("Bytes"));
    }

    /// Un nom parfaitement valide dans le vault peut être inextractible
    /// ailleurs. Le refus arrive **avant** toute écriture.
    #[test]
    fn un_nom_non_representable_est_refuse_sous_les_regles_de_l_hote() {
        let hostile = chemin(&[b"rapport:2026.txt"]);

        assert!(hostile.to_os_path_under(NamingRules::Bytes).is_ok());
        assert!(matches!(
            hostile.to_os_path_under(NamingRules::Windows),
            Err(Error::UnrepresentableName)
        ));

        // Sur la plateforme courante, la conversion suit `current()`.
        assert_eq!(
            hostile.to_os_path().is_ok(),
            NamingRules::current().accepts(b"rapport:2026.txt")
        );
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
