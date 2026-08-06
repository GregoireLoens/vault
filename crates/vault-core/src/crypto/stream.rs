//! Chiffrement du contenu par morceaux — T021.
//!
//! Construction **STREAM** (Hoang, Reyhanitabar, Rogaway, Vizár) fournie par
//! le crate `aead-stream` (D-003), en morceaux de 64 KiB. Le contenu ne
//! transite jamais en entier par la mémoire : SC-010 exige qu'un fichier de
//! 4 Go se traite sur une machine de 2 Go.
//!
//! Ce que STREAM apporte par rapport à un simple découpage :
//!
//! - chaque morceau est authentifié **à sa position** : réordonner deux
//!   morceaux est détecté ;
//! - le dernier morceau porte une marque de fin : tronquer un blob est détecté
//!   (FR-039, VR-B2) ;
//! - supprimer un morceau intermédiaire décale tous les suivants, donc échoue.
//!
//! Le nonce fait **19 octets** et non 24 : `StreamBE32` prélève 5 octets du
//! nonce de XChaCha20-Poly1305 pour y loger son compteur de morceau et son
//! drapeau de fin. C'est la construction qui l'impose, pas un choix.

use std::io::{Read, Write};

use aead_stream::{DecryptorBE32, EncryptorBE32, StreamBE32};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use zeroize::Zeroizing;

use crate::crypto::aead::TAG_LEN;
use crate::crypto::keys::SecretKey;
use crate::crypto::random;
use crate::error::{Error, Result};

/// Taille d'un morceau de clair, en octets.
pub(crate) const CHUNK_SIZE: usize = 64 * 1024;

/// Longueur du nonce STREAM, en octets : 24 − 5 octets de compteur.
pub(crate) const STREAM_NONCE_LEN: usize = 19;

/// Nonce d'un flux chiffré.
pub(crate) type StreamNonce = [u8; STREAM_NONCE_LEN];

type Cipher = XChaCha20Poly1305;
type Primitive = StreamBE32<Cipher>;
type NonceArray = aead_stream::Nonce<Cipher, Primitive>;

/// Tire un nonce de flux du CSPRNG du système.
pub(crate) fn random_nonce() -> StreamNonce {
    random::bytes::<STREAM_NONCE_LEN>()
}

/// Nombre de morceaux d'un clair de cette longueur.
///
/// Un contenu vide occupe **un** morceau, vide et marqué comme dernier : sans
/// lui, un blob vide ne porterait aucune marque de fin et sa troncature
/// deviendrait indétectable.
pub(crate) fn chunk_count(plaintext_len: u64) -> u64 {
    plaintext_len.div_ceil(CHUNK_SIZE as u64).max(1)
}

/// Longueur du chiffré produit pour un clair de cette longueur.
pub(crate) fn ciphertext_len(plaintext_len: u64) -> u64 {
    plaintext_len + chunk_count(plaintext_len) * TAG_LEN as u64
}

/// Chiffre `reader` vers `writer` et renvoie la longueur du clair traité.
///
/// `max_plaintext` borne le volume accepté : au-delà, l'opération s'arrête sur
/// [`Error::FileTooLarge`] (FR-023). La borne est vérifiée au fil de la
/// lecture, ce qui couvre le cas d'une source qui grandit pendant l'ajout.
///
/// # Errors
///
/// - [`Error::Io`] si la lecture de la source ou l'écriture échoue ;
/// - [`Error::FileTooLarge`] si la source dépasse `max_plaintext` ;
/// - [`Error::Corrupted`] si l'AEAD refuse un morceau, ce qui suppose un
///   dépassement du compteur de morceaux inatteignable ici.
pub(crate) fn encrypt<R: Read, W: Write>(
    key: &SecretKey,
    nonce: &StreamNonce,
    associated_data: &[u8],
    mut reader: R,
    writer: &mut W,
    max_plaintext: u64,
) -> Result<u64> {
    let mut encryptor = EncryptorBE32::<Cipher>::new(&Key::from(**key), &NonceArray::from(*nonce));

    let mut total = 0u64;
    let mut pending = read_chunk(&mut reader)?;

    loop {
        total += pending.len() as u64;
        if total > max_plaintext {
            return Err(Error::FileTooLarge {
                limit: max_plaintext,
            });
        }

        let next = read_chunk(&mut reader)?;
        if next.is_empty() {
            encryptor
                .encrypt_last_in_place(associated_data, &mut *pending)
                .map_err(|_| Error::Corrupted)?;
            writer.write_all(&pending)?;
            return Ok(total);
        }

        encryptor
            .encrypt_next_in_place(associated_data, &mut *pending)
            .map_err(|_| Error::Corrupted)?;
        writer.write_all(&pending)?;
        pending = next;
    }
}

/// Déchiffre exactement `plaintext_len` octets de `reader` vers `writer`.
///
/// La longueur du clair vient de l'index **chiffré**, ce qui la rend
/// authentifiée : elle n'est pas déductible du blob, dont la taille est noyée
/// par le remplissage. Elle détermine le découpage en morceaux et le nombre
/// d'octets de chiffré à lire, le reste du blob étant du remplissage à ignorer.
///
/// C-016 : chaque morceau est authentifié **avant** d'être écrit. Une
/// altération interrompt l'opération sans jamais livrer d'octet non vérifié.
///
/// # Errors
///
/// - [`Error::Corrupted`] si le blob est tronqué, ou si sa longueur annoncée
///   ne tient pas en mémoire sur la plateforme courante ;
/// - [`Error::Authentication`] si un morceau ne s'authentifie pas — altéré,
///   réordonné, ou emprunté à un autre blob ;
/// - [`Error::Io`] si l'écriture vers la destination échoue.
pub(crate) fn decrypt<R: Read, W: Write>(
    key: &SecretKey,
    nonce: &StreamNonce,
    associated_data: &[u8],
    mut reader: R,
    writer: &mut W,
    plaintext_len: u64,
) -> Result<()> {
    let mut decryptor = DecryptorBE32::<Cipher>::new(&Key::from(**key), &NonceArray::from(*nonce));

    let chunks = chunk_count(plaintext_len);
    let mut remaining = plaintext_len;

    for _ in 1..chunks {
        let mut chunk = read_exactly(&mut reader, CHUNK_SIZE + TAG_LEN)?;
        decryptor
            .decrypt_next_in_place(associated_data, &mut *chunk)
            .map_err(|_| Error::Authentication)?;
        writer.write_all(&chunk)?;
        remaining -= CHUNK_SIZE as u64;
    }

    let last_len = usize::try_from(remaining).map_err(|_| Error::Corrupted)?;
    let mut chunk = read_exactly(&mut reader, last_len + TAG_LEN)?;
    decryptor
        .decrypt_last_in_place(associated_data, &mut *chunk)
        .map_err(|_| Error::Authentication)?;
    writer.write_all(&chunk)?;
    Ok(())
}

/// Lit un morceau entier, ou moins seulement en fin de source.
fn read_chunk<R: Read>(reader: &mut R) -> Result<Zeroizing<Vec<u8>>> {
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut filled = 0;
    while filled < CHUNK_SIZE {
        // `read` a le droit de renvoyer moins que demandé sans être en fin de
        // source. Sans cette boucle, un tube ou un fichier lu par à-coups
        // produirait des morceaux courts au milieu du flux, et le morceau
        // suivant serait pris pour le dernier.
        let read = reader.read(&mut buffer[filled..])?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    buffer.truncate(filled);
    Ok(Zeroizing::new(buffer))
}

/// Lit exactement `len` octets, ou échoue en [`Error::Corrupted`].
fn read_exactly<R: Read>(reader: &mut R, len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut buffer = vec![0u8; len];
    reader
        .read_exact(&mut buffer)
        .map_err(|_| Error::Corrupted)?;
    Ok(Zeroizing::new(buffer))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cle() -> SecretKey {
        Zeroizing::new([11u8; 32])
    }

    fn chiffre(clair: &[u8]) -> (StreamNonce, Vec<u8>) {
        let nonce = random_nonce();
        let mut chiffre = Vec::new();
        let ecrits =
            encrypt(&cle(), &nonce, b"aad", clair, &mut chiffre, u64::MAX).expect("chiffrable");
        assert_eq!(ecrits, clair.len() as u64);
        assert_eq!(chiffre.len() as u64, ciphertext_len(clair.len() as u64));
        (nonce, chiffre)
    }

    fn dechiffre(nonce: &StreamNonce, chiffre: &[u8], len: u64) -> Result<Vec<u8>> {
        let mut clair = Vec::new();
        decrypt(&cle(), nonce, b"aad", chiffre, &mut clair, len)?;
        Ok(clair)
    }

    #[test]
    fn le_decompte_de_morceaux_couvre_les_bords() {
        assert_eq!(chunk_count(0), 1);
        assert_eq!(chunk_count(1), 1);
        assert_eq!(chunk_count(CHUNK_SIZE as u64), 1);
        assert_eq!(chunk_count(CHUNK_SIZE as u64 + 1), 2);
        assert_eq!(chunk_count(2 * CHUNK_SIZE as u64), 2);
        assert_eq!(ciphertext_len(0), TAG_LEN as u64);
        assert_eq!(
            ciphertext_len(CHUNK_SIZE as u64 + 1),
            CHUNK_SIZE as u64 + 1 + 2 * TAG_LEN as u64
        );
    }

    /// Les tailles choisies encadrent chaque frontière de morceau : c'est là
    /// que se logent les erreurs de découpage.
    #[test]
    fn l_aller_retour_est_fidele_sur_toutes_les_tailles_frontieres() {
        for taille in [
            0,
            1,
            CHUNK_SIZE - 1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            2 * CHUNK_SIZE,
            2 * CHUNK_SIZE + 7,
        ] {
            let clair: Vec<u8> = (0..taille)
                .map(|i| u8::try_from(i % 251).expect("reste inférieur à 251"))
                .collect();
            let (nonce, chiffre) = chiffre(&clair);
            assert_eq!(
                dechiffre(&nonce, &chiffre, taille as u64).expect("déchiffrable"),
                clair,
                "taille {taille}"
            );
        }
    }

    #[test]
    fn le_clair_n_apparait_pas_dans_le_chiffre() {
        let clair = b"donnee tres reconnaissable".repeat(400);
        let (_, chiffre) = chiffre(&clair);
        assert!(
            !chiffre
                .windows(b"donnee tres reconnaissable".len())
                .any(|f| f == b"donnee tres reconnaissable"),
            "le clair ne doit pas transparaître"
        );
    }

    /// FR-039, VR-B2 : la troncature d'un blob doit être détectée. Retirer le
    /// dernier morceau ne suffit pas à produire un flux valide, puisque le
    /// morceau précédent n'est pas marqué comme dernier.
    #[test]
    fn la_troncature_est_detectee() {
        let clair = vec![7u8; CHUNK_SIZE + 100];
        let (nonce, chiffre) = chiffre(&clair);

        // Le blob est amputé de son dernier morceau, et la longueur annoncée
        // ajustée en conséquence : c'est l'attaque que STREAM doit bloquer.
        let tronque = &chiffre[..CHUNK_SIZE + TAG_LEN];
        assert!(matches!(
            dechiffre(&nonce, tronque, CHUNK_SIZE as u64),
            Err(Error::Authentication)
        ));

        // Amputation brute, sans ajustement : la lecture manque d'octets.
        assert!(matches!(
            dechiffre(&nonce, &chiffre[..chiffre.len() - 1], clair.len() as u64),
            Err(Error::Corrupted)
        ));
    }

    #[test]
    fn toute_alteration_est_detectee() {
        let clair = vec![7u8; CHUNK_SIZE + 100];
        let (nonce, chiffre) = chiffre(&clair);

        let positions = [0, 10, CHUNK_SIZE, chiffre.len() - 1];
        let detectees: Vec<bool> = positions
            .iter()
            .map(|position| {
                let mut altere = chiffre.clone();
                altere[*position] ^= 0x01;
                dechiffre(&nonce, &altere, clair.len() as u64).is_err()
            })
            .collect();
        assert_eq!(
            detectees,
            vec![true; positions.len()],
            "positions {positions:?}"
        );

        let mut autre_nonce = nonce;
        autre_nonce[0] ^= 0x01;
        assert!(matches!(
            dechiffre(&autre_nonce, &chiffre, clair.len() as u64),
            Err(Error::Authentication)
        ));
    }

    /// Réordonner deux morceaux est détecté : chaque morceau est authentifié à
    /// sa position dans le flux.
    #[test]
    fn la_permutation_de_morceaux_est_detectee() {
        let clair: Vec<u8> = (0..3 * CHUNK_SIZE)
            .map(|i| u8::try_from(i % 251).expect("reste inférieur à 251"))
            .collect();
        let (nonce, chiffre) = chiffre(&clair);

        let taille = CHUNK_SIZE + TAG_LEN;
        let mut permute = chiffre.clone();
        let (premier, reste) = permute.split_at_mut(taille);
        premier.swap_with_slice(&mut reste[..taille]);

        assert!(matches!(
            dechiffre(&nonce, &permute, clair.len() as u64),
            Err(Error::Authentication)
        ));
    }

    #[test]
    fn des_donnees_associees_differentes_font_echouer() {
        let (nonce, chiffre) = chiffre(b"contenu");
        let mut clair = Vec::new();
        assert!(matches!(
            decrypt(&cle(), &nonce, b"autre", &chiffre[..], &mut clair, 7),
            Err(Error::Authentication)
        ));
        assert!(clair.is_empty(), "aucun octet non vérifié ne doit sortir");
    }

    /// FR-023, C-009 : la borne de taille arrête le traitement.
    #[test]
    fn la_borne_de_taille_est_appliquee() {
        let clair = vec![0u8; CHUNK_SIZE * 2];
        let mut sortie = Vec::new();
        let erreur = encrypt(
            &cle(),
            &random_nonce(),
            b"aad",
            &clair[..],
            &mut sortie,
            CHUNK_SIZE as u64,
        );
        assert!(matches!(
            erreur,
            Err(Error::FileTooLarge { limit }) if limit == CHUNK_SIZE as u64
        ));
    }

    /// Une source qui rend moins d'octets que demandé à chaque appel ne doit
    /// pas produire de morceau court au milieu du flux.
    #[test]
    fn une_source_avare_ne_casse_pas_le_decoupage() {
        struct Avare<'a>(&'a [u8]);
        impl Read for Avare<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                let taille = self.0.len().min(buffer.len()).min(1000);
                buffer[..taille].copy_from_slice(&self.0[..taille]);
                self.0 = &self.0[taille..];
                Ok(taille)
            }
        }

        let clair: Vec<u8> = (0..CHUNK_SIZE + 500)
            .map(|i| u8::try_from(i % 251).expect("reste inférieur à 251"))
            .collect();
        let nonce = random_nonce();
        let mut chiffre = Vec::new();
        encrypt(
            &cle(),
            &nonce,
            b"aad",
            Avare(&clair),
            &mut chiffre,
            u64::MAX,
        )
        .expect("chiffrable");
        assert_eq!(chiffre.len() as u64, ciphertext_len(clair.len() as u64));
        assert_eq!(
            dechiffre(&nonce, &chiffre, clair.len() as u64).expect("déchiffrable"),
            clair
        );
    }

    #[test]
    fn une_erreur_de_lecture_remonte() {
        struct Cassee;
        impl Read for Cassee {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("lecture cassée"))
            }
        }

        let mut sortie = Vec::new();
        assert!(matches!(
            encrypt(
                &cle(),
                &random_nonce(),
                b"aad",
                Cassee,
                &mut sortie,
                u64::MAX
            ),
            Err(Error::Io(_))
        ));
    }

    #[test]
    fn une_erreur_d_ecriture_remonte() {
        struct Cassee;
        impl Write for Cassee {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("écriture cassée"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("écriture cassée"))
            }
        }

        assert!(Write::flush(&mut Cassee).is_err());
        let clair = vec![0u8; 2 * CHUNK_SIZE];
        assert!(matches!(
            encrypt(
                &cle(),
                &random_nonce(),
                b"aad",
                &clair[..],
                &mut Cassee,
                u64::MAX
            ),
            Err(Error::Io(_))
        ));

        let (nonce, chiffre) = chiffre(b"contenu");
        assert!(matches!(
            decrypt(&cle(), &nonce, b"aad", &chiffre[..], &mut Cassee, 7),
            Err(Error::Io(_))
        ));
    }
}
