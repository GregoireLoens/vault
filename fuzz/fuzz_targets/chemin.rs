//! Exploration des chemins de vault — 002, T024.
//!
//! §5 du format : les composants sont conservés en **octets bruts**, donc
//! n'importe quelle suite d'octets peut leur être soumise. VR-I4 fixe ce qui
//! doit être refusé ; rien ne doit paniquer.

fn main() {
    afl::fuzz!(|donnees: &[u8]| {
        // L'octet nul sépare les composants : il ne peut pas figurer dans l'un
        // d'eux, ce qui en fait un séparateur sans ambiguïté.
        let composants: Vec<Vec<u8>> = donnees.split(|octet| *octet == 0).map(<[u8]>::to_vec).collect();
        let _ = vault_core::fuzzing::chemin_depuis_composants(composants);
    });
}
