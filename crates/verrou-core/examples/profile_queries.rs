//! Search time per query over 10,000 mock items:
//! `cargo run --release -p verrou-core --example profile_queries`.
use std::time::Instant;
use verrou_core::{Filter, Sort, Vault, mock};

fn main() {
    let vault = Vault::new(mock::vault_items(10_000, 7, mock::MockLanguage::En));
    for q in [
        "g",
        "gi",
        "git",
        "gith",
        "githu",
        "github",
        "github pro",
        "société",
        "zzzz",
        "tag:banque",
        "",
    ] {
        let mut best = std::time::Duration::MAX;
        let mut n = 0;
        for _ in 0..30 {
            let t = Instant::now();
            n = vault.search(q, &Filter::All, Sort::Relevance).len();
            best = best.min(t.elapsed());
        }
        println!("{q:>12}: {best:>10.2?}  ({n} results)");
    }
}
