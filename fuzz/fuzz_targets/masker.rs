//! `verrou run`'s output masker, on any secrets and any output cut into any
//! writes: the output doesn't depend on how it was cut, and no secret shows
//! in it (once the "concealed" marks are taken out).
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use verrou_cli::run::{CONCEALED, Masker};

#[derive(Arbitrary, Debug)]
struct Run {
    secrets: Vec<String>,
    output: Vec<u8>,
    cuts: Vec<u16>,
}

fn masked(secrets: &[String], writes: &[&[u8]]) -> Vec<u8> {
    let mut masker = Masker::new(secrets.iter().map(String::as_str));
    let mut out = Vec::new();
    for write in writes {
        out.extend(masker.feed(write));
    }
    out.extend(masker.finish());
    out
}

fuzz_target!(|run: Run| {
    let secrets: Vec<String> = run.secrets.into_iter().take(4).collect();
    let whole = masked(&secrets, &[&run.output]);

    let mut writes = Vec::new();
    let mut rest: &[u8] = &run.output;
    for cut in run.cuts {
        if rest.is_empty() {
            break;
        }
        let at = usize::from(cut) % (rest.len() + 1);
        let (head, tail) = rest.split_at(at);
        writes.push(head);
        rest = tail;
    }
    writes.push(rest);
    assert_eq!(masked(&secrets, &writes), whole, "depends on how the output is cut");

    // The marks become a byte no UTF-8 secret contains: no secret can span them.
    let mut plain = Vec::with_capacity(whole.len());
    let mut i = 0;
    while i < whole.len() {
        if whole[i..].starts_with(CONCEALED.as_bytes()) {
            plain.push(0xFF);
            i += CONCEALED.len();
        } else {
            plain.push(whole[i]);
            i += 1;
        }
    }
    for secret in secrets.iter().filter(|s| s.len() >= 3) {
        let secret = secret.as_bytes();
        assert!(
            !plain.windows(secret.len()).any(|w| w == secret),
            "a secret shows in the output"
        );
    }
});
