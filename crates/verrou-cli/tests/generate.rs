//! `verrou generate`: passwords and passphrases, without the app.

use std::process::{Command, Output};

fn verrou(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_verrou"))
        .arg("generate")
        .args(args)
        // Nothing may depend on the link: `generate` does not contact the app.
        .env("VERROU_CLI_CONFIG", "/nonexistent/verrou-cli.json")
        .env_remove("VERROU_ALIAS_DOMAIN")
        .output()
        .expect("verrou")
}

fn stdout(args: &[&str]) -> String {
    let output = verrou(args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .trim_end_matches('\n')
        .to_owned()
}

#[test]
fn password_flags_still_work() {
    let p = stdout(&[]);
    assert_eq!(p.chars().count(), 20);
    let p = stdout(&["-l", "32", "--no-symbols"]);
    assert_eq!(p.len(), 32);
    assert!(p.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn passphrase_defaults_to_french_and_hyphens() {
    let p = stdout(&["--words", "5"]);
    let words: Vec<_> = p.split('-').collect();
    assert_eq!(words.len(), 5, "{p}");
    assert!(
        words
            .iter()
            .all(|w| w.bytes().all(|b| b.is_ascii_lowercase()))
    );
}

#[test]
fn passphrase_options() {
    let p = stdout(&[
        "--words",
        "6",
        "--separator",
        " ",
        "--capitalize",
        "--number",
        "--lang",
        "en",
    ]);
    let words: Vec<_> = p.split(' ').collect();
    assert_eq!(words.len(), 6, "{p}");
    assert!(
        words
            .iter()
            .all(|w| w.starts_with(|c: char| c.is_ascii_uppercase()))
    );
    let numbered = words
        .iter()
        .filter(|w| w.ends_with(|c: char| c.is_ascii_digit()))
        .count();
    assert_eq!(numbered, 1, "{p}");

    let p = stdout(&["-w", "4", "--separator", "digit"]);
    assert_eq!(p.chars().filter(char::is_ascii_digit).count(), 3, "{p}");
    assert_eq!(p.split(|c: char| c.is_ascii_digit()).count(), 4, "{p}");
}

#[test]
fn json_reports_entropy() {
    let output = Command::new(env!("CARGO_BIN_EXE_verrou"))
        .args(["--json", "generate", "--words", "5", "--lang", "en"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["value"].as_str().unwrap().split('-').count() >= 5);
    let bits = json["entropy_bits"].as_f64().unwrap();
    assert!((bits - 5.0 * 7776f64.log2()).abs() < 1e-6, "{bits}");
}

#[test]
fn invalid_combinations_are_refused() {
    for args in [
        &["--words", "2"][..],
        &["--words", "21"],
        &["--words", "5", "--separator", "x"],
        &["--words", "5", "--lang", "de"],
        &["--words", "5", "--length", "30"],
        &["--words", "5", "--no-symbols"],
        &["--capitalize"],
        &["--number"],
        &["--separator", "."],
        &["-l", "30", "alias", "--domain", "example.com"],
        &["--words", "5", "alias", "--domain", "example.com"],
        &["alias", "--domain", "example.com", "--words", "5"],
        &["alias", "--domain", "not a domain"],
        &["alias", "--domain", "localhost"],
        &["alias"],
    ] {
        let output = verrou(args);
        assert!(!output.status.success(), "{args:?} should have failed");
    }
}

fn alias_parts(alias: &str) -> (&str, &str) {
    alias.split_once('@').unwrap_or_else(|| panic!("{alias}"))
}

fn random(text: &str) -> bool {
    text.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

#[test]
fn alias_starts_with_the_site() {
    let alias = stdout(&[
        "alias",
        "--domain",
        "Alias.Example.com",
        "--uri",
        "https://www.netflix.com/signup",
    ]);
    let (local, domain) = alias_parts(&alias);
    assert_eq!(domain, "alias.example.com");
    let (site, suffix) = local.split_once('.').unwrap();
    assert_eq!(site, "netflix");
    assert_eq!(suffix.len(), 5);
    assert!(random(suffix), "{alias}");

    let alias = stdout(&["alias", "--domain", "example.com"]);
    assert!(alias.starts_with("alias."), "{alias}");
}

#[test]
fn alias_without_the_site() {
    let alias = stdout(&[
        "alias",
        "--domain",
        "example.com",
        "--uri",
        "netflix.com",
        "--no-site",
    ]);
    let (local, domain) = alias_parts(&alias);
    assert_eq!(domain, "example.com");
    assert_eq!(local.len(), 10);
    assert!(random(local), "{alias}");
}

#[test]
fn alias_domain_from_the_environment() {
    let output = Command::new(env!("CARGO_BIN_EXE_verrou"))
        .args(["--json", "generate", "alias", "--uri", "github.com"])
        .env("VERROU_CLI_CONFIG", "/nonexistent/verrou-cli.json")
        .env("VERROU_ALIAS_DOMAIN", "mail.example.org")
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let alias = json["value"].as_str().unwrap();
    assert!(alias.starts_with("github."), "{alias}");
    assert!(alias.ends_with("@mail.example.org"), "{alias}");
}

#[test]
fn alias_without_a_domain_says_where_to_set_it() {
    let output = verrou(&["alias"]);
    assert!(!output.status.success());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("--domain"), "{message}");
}
