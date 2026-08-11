//! Citation POSIX du chemin distant — T048, D-206.
//!
//! `ssh hôte commande args` **ne transmet pas un tableau d'arguments** : il
//! concatène et laisse le **shell distant** redécouper. Un chemin contenant une
//! espace, un `$`, un `;` ou une apostrophe serait donc réinterprété, avec des
//! conséquences qui vont du chemin faux à l'exécution d'une commande arbitraire
//! choisie par celui qui a écrit le chemin.
//!
//! La citation entre **apostrophes simples** est la seule forme dont un shell
//! POSIX ne réinterprète rien — l'apostrophe elle-même exceptée, qui n'a pas de
//! séquence d'échappement à l'intérieur de sa propre citation. Elle se ferme
//! donc, s'échappe, et se rouvre : `'` devient `'\''`.
//!
//! ```text
//!   mon vault          →  'mon vault'
//!   l'été              →  'l'\''été'
//!   ; rm -rf /         →  '; rm -rf /'
//! ```
//!
//! La fonction fait une quinzaine de lignes et sa table de vérité tient en cinq
//! cas. Une dépendance coûterait plus cher à auditer qu'elle : c'est le
//! raisonnement que le principe VIII attend sur toute complexité ajoutée,
//! appliqué dans le sens qui retire du code.

/// Enveloppe `brut` pour qu'un shell POSIX le reçoive **littéralement**.
pub(crate) fn pour_shell_posix(brut: &str) -> String {
    let mut cite = String::with_capacity(brut.len() + 2);
    cite.push('\'');
    for caractere in brut.chars() {
        if caractere == '\'' {
            // Fermer la citation, échapper l'apostrophe, la rouvrir.
            cite.push_str("'\\''");
        } else {
            cite.push(caractere);
        }
    }
    cite.push('\'');
    cite
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La table de vérité de D-206, en cinq cas.
    #[test]
    fn la_citation_couvre_les_cinq_cas() {
        assert_eq!(pour_shell_posix("simple"), "'simple'");
        assert_eq!(pour_shell_posix("mon vault"), "'mon vault'");
        assert_eq!(pour_shell_posix("l'été"), "'l'\\''été'");
        assert_eq!(pour_shell_posix("; rm -rf /"), "'; rm -rf /'");
        assert_eq!(pour_shell_posix(""), "''");
    }

    /// **La vérification qui compte** : la citation est éprouvée par la
    /// sémantique d'un shell, et non par des chaînes attendues écrites à la
    /// main — lesquelles se trompent bien plus facilement que le code.
    ///
    /// Un mini-shell applique les règles de la citation simple, et l'on vérifie
    /// que le mot qui en ressort est **exactement** celui qu'on avait cité.
    #[test]
    fn un_shell_relit_exactement_ce_qui_a_ete_cite() {
        for brut in [
            "simple",
            "",
            "mon vault",
            "l'été",
            "'",
            "'''",
            "a'b'c",
            "'; rm -rf / #",
            "$HOME",
            "`whoami`",
            "$(id)",
            "a && b | c > d",
            "a\nb",
            "a\tb",
            "~/coffres/mon vault",
            "chemin/avec/des\\antislashs",
            "*",
        ] {
            let cite = pour_shell_posix(brut);
            assert_eq!(comme_un_shell(&cite), brut, "citation : {cite}");
        }
    }

    /// Applique les règles d'un shell POSIX à une chaîne citée et rend le mot
    /// **unique** qui en résulte.
    ///
    /// Vérifie au passage l'invariant qui fait toute la sûreté de la citation :
    /// **hors citation, il n'y a jamais que l'apostrophe ouvrante ou fermante,
    /// ou l'antislash qui échappe une apostrophe.** Aucun métacaractère ne se
    /// retrouve donc jamais à découvert, et c'est cela — bien plus qu'une
    /// chaîne attendue — qui rend un chemin hostile inoffensif.
    fn comme_un_shell(cite: &str) -> String {
        let mut mot = String::new();
        let mut caracteres = cite.chars();
        let mut dans_citation = false;

        while let Some(caractere) = caracteres.next() {
            if caractere == '\'' {
                dans_citation = !dans_citation;
            } else if dans_citation {
                mot.push(caractere);
            } else {
                // Hors citation, il ne peut y avoir que l'antislash qui échappe
                // une apostrophe. C'est **l'invariant** qui rend un chemin
                // hostile inoffensif, et il est éprouvé ici plutôt qu'espéré.
                assert_eq!(caractere, '\\', "caractère nu hors citation dans {cite}");
                let echappe = caracteres.next().expect("un échappement est complet");
                assert_eq!(echappe, '\'', "seule l'apostrophe est échappée");
                mot.push(echappe);
            }
        }

        assert!(!dans_citation, "citation non refermée : {cite}");
        mot
    }
}
