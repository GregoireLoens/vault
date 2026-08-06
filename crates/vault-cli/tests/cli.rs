//! Contrat de la ligne de commande — début de T046.
//!
//! Les assertions sur les codes de retour et les messages arrivent avec la
//! phase 3. Ce test existe dès la phase 1 pour que la porte de couverture du
//! principe VIII soit tenue dès le premier commit, plutôt qu'armée puis
//! contournée en attendant du code « vraiment testable ».

use assert_cmd::Command;

#[test]
fn le_binaire_demarre_et_sort_proprement() {
    Command::cargo_bin("vault")
        .expect("le binaire vault doit être construit")
        .assert()
        .success();
}
