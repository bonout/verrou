use verrou_core::passphrase::Language;

pub fn is_fingerprint(phrase: &str) -> bool {
    starts_with_words(phrase, 5)
}

fn starts_with_words(rest: &str, count: usize) -> bool {
    Language::English
        .words()
        .iter()
        .any(|word| match rest.strip_prefix(word) {
            Some("") => count == 1,
            Some(tail) => {
                count > 1
                    && tail
                        .strip_prefix('-')
                        .is_some_and(|tail| starts_with_words(tail, count - 1))
            }
            None => false,
        })
}
