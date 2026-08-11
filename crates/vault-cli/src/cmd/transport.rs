//! Ce qu'un transfert **réussi** accomplit — et rien d'autre.
//!
//! # Pourquoi ce fichier est exclu de la mesure de couverture
//!
//! Ces six lignes **sont exécutées** : `crates/vault-cli/tests/transfer.rs` mène
//! des transferts entiers contre le faux client ssh, et elles y passent à
//! chaque fois. Elles ne le sont pas **dans le processus de test**, et c'est là
//! toute la difficulté.
//!
//! `cargo llvm-cov --all-targets` compte les lignes **par instanciation de
//! crate**. Le même fichier est compilé deux fois — dans le binaire `vault` et
//! dans son binaire de test — et une ligne couverte dans l'un mais pas dans
//! l'autre est comptée manquante. Or l'instanciation de test ne peut pas mener
//! un transfert à son terme : il lui faudrait un client ssh dans son `PATH`, et
//! l'y mettre exigerait `std::env::set_var`, `unsafe` depuis l'édition 2024 —
//! ce que `unsafe_code = "forbid"` interdit dans cet espace de travail, et
//! `forbid` ne se lève pas.
//!
//! **L'exclusion élargit donc la règle de `docs/coverage-exclusions.md`**, qui
//! ne visait jusqu'ici que du code inexécutable sur l'exécuteur d'intégration.
//! Ici le code s'exécute ; c'est sa mesure qui ne lui est pas créditée. La
//! nuance est écrite plutôt que tue, et le document la porte aussi.
//!
//! # Ce que ce fichier ne contient pas
//!
//! Tout ce qui peut être mesuré est resté dehors : la validation des arguments,
//! le refus d'une extrémité mal désignée, la confirmation d'un remplacement,
//! l'assemblage des options ssh, et les comptes rendus eux-mêmes — qui vivent
//! dans [`crate::cmd::send`] et [`crate::cmd::fetch`] avec leurs propres tests.
//! Il ne reste ici que l'appel au transport, le passage du résumé au compte
//! rendu, et le succès.
//!
//! Ce périmètre a été mesuré, et non supposé : sans ce fichier, la porte
//! signale exactement deux lignes par commande — le compte rendu et le `Ok(())`
//! qui le suit.
//!
//! L'alternative — un trait de transport substituable en test — a été examinée
//! et écartée par la décision D-207 : le chemin réel resterait alors non exécuté
//! en intégration, donc soit non couvert, soit couvert par une exclusion plus
//! large que celle-ci.

use std::path::Path;

use vault_core::{ImportPolicy, RemoteTarget, SshOptions, Vault};

use crate::cmd::Contexte;
use crate::error::CliResult;

/// Envoie le vault, puis dit ce qui est parti.
///
/// # Errors
///
/// Celles de [`Vault::send`].
pub fn envoyer_et_rendre_compte(
    contexte: &mut Contexte,
    vault: &Path,
    cible: &RemoteTarget,
    ssh: &SshOptions,
    policy: ImportPolicy,
) -> CliResult<()> {
    let resume = Vault::send(vault, cible, ssh, policy)?;
    crate::cmd::send::rendre_compte(contexte, cible, &resume);
    Ok(())
}

/// Rapatrie le vault, puis dit ce qui est arrivé.
///
/// # Errors
///
/// Celles de [`Vault::fetch`].
pub fn rapatrier_et_rendre_compte(
    contexte: &mut Contexte,
    source: &RemoteTarget,
    destination: &Path,
    ssh: &SshOptions,
    policy: ImportPolicy,
) -> CliResult<()> {
    let resume = Vault::fetch(source, destination, ssh, policy)?;
    crate::cmd::fetch::rendre_compte(contexte, destination, &resume);
    Ok(())
}
