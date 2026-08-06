//! Versionnement du format — T022.
//!
//! VR-H1 : `magic` et `format_version` sont lus avant toute autre chose. Une
//! version inconnue provoque un **refus explicite** d'ouverture, jamais une
//! tentative de lecture approximative.
//!
//! Le principe IV impose par ailleurs que toute version future sache lire les
//! formats antérieurs. [`is_readable`] est le point unique où cette liste
//! s'étendra, plutôt que de laisser la comparaison se disséminer dans le code.

use crate::error::{Error, Result};

/// Constante d'identification du format, en tête de l'en-tête.
///
/// Elle ne change pas d'une version de format à l'autre : c'est
/// [`FORMAT_VERSION`] qui porte l'évolution.
pub const MAGIC: [u8; 8] = *b"VAULTFMT";

/// Version du format produite par cette version du logiciel.
pub const FORMAT_VERSION: u32 = 1;

/// Versions de format que cette version du logiciel sait lire.
const READABLE_VERSIONS: &[u32] = &[1];

/// Vrai si cette version du logiciel sait lire ce format.
#[must_use]
pub fn is_readable(version: u32) -> bool {
    READABLE_VERSIONS.contains(&version)
}

/// Vérifie qu'un en-tête est bien celui d'un vault d'une version lisible.
///
/// # Errors
///
/// - [`Error::Corrupted`] si la constante d'identification ne correspond pas :
///   le fichier n'est pas un en-tête de vault.
/// - [`Error::UnsupportedFormatVersion`] si la version est inconnue (VR-H1).
pub fn check(magic: &[u8], version: u32) -> Result<()> {
    if magic != MAGIC {
        return Err(Error::Corrupted);
    }
    if !is_readable(version) {
        return Err(Error::UnsupportedFormatVersion {
            found: version,
            supported: FORMAT_VERSION,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_version_courante_est_lisible() {
        assert!(is_readable(FORMAT_VERSION));
        assert!(check(&MAGIC, FORMAT_VERSION).is_ok());
    }

    #[test]
    fn une_magie_etrangere_est_refusee() {
        assert!(matches!(
            check(b"AUTRE!!!", FORMAT_VERSION),
            Err(Error::Corrupted)
        ));
        assert!(matches!(
            check(b"court", FORMAT_VERSION),
            Err(Error::Corrupted)
        ));
    }

    /// VR-H1 : refus explicite, dans les deux sens. Une version supérieure
    /// n'est pas lisible, et une version inférieure inexistante non plus — il
    /// n'y a pas de « version 0 » à deviner.
    #[test]
    fn une_version_inconnue_est_refusee_explicitement() {
        for inconnue in [0, FORMAT_VERSION + 1, u32::MAX] {
            assert!(!is_readable(inconnue));
            let erreur = check(&MAGIC, inconnue).expect_err("aurait dû refuser");
            assert!(matches!(
                erreur,
                Error::UnsupportedFormatVersion { found, supported }
                    if found == inconnue && supported == FORMAT_VERSION
            ));
        }
    }
}
