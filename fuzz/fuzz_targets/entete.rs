//! Exploration de l'en-tête — 002, T024.
//!
//! §3 du format : le fichier `header` est le seul élément en clair d'un vault,
//! donc le premier que touche quiconque a accès au répertoire. Son décodage doit
//! refuser explicitement, jamais paniquer.

fn main() {
    afl::fuzz!(|donnees: &[u8]| {
        // Le résultat est ignoré : ce qui est éprouvé n'est pas *quelle* erreur
        // survient, mais qu'il en survienne une plutôt qu'une panique.
        let _ = vault_core::fuzzing::en_tete_depuis_octets(donnees);
    });
}
