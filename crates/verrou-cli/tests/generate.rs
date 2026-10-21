//! `verrou generate`: passwords and passphrases, without the app.

use std::process::{Command, Output};

fn verrou(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_verrou"))
        .arg("generate")
        .args(args)
        // Nothing may depend on the link: `generate` does not contact the app.
        .env("VERROU_CLI_CONFIG", "/nonexistent/verrou-cli.json")
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
    ] {
        let output = verrou(args);
        assert!(!output.status.success(), "{args:?} should have failed");
    }
}
