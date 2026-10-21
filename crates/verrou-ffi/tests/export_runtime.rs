//! Every `async` method exported to Swift must run on the Tokio runtime
//! (`#[uniffi::export(async_runtime = "tokio")]`): without it, the first
//! network call fails ("must be called from the context of a Tokio 1.x
//! runtime"). Rust tests don't see it, they provide their own runtime: so
//! we check the sources.

use std::fs;
use std::path::Path;

/// The `{ … }` block starting at `start` (position of an opening brace).
fn block(source: &str, start: usize) -> &str {
    let mut depth = 0usize;
    for (offset, c) in source[start..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[start..start + offset];
                }
            }
            _ => {}
        }
    }
    &source[start..]
}

#[test]
fn async_exports_run_on_tokio() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut missing = Vec::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap();
        let mut from = 0;
        while let Some(found) = source[from..].find("#[uniffi::export") {
            let at = from + found;
            let attr_end = at + source[at..].find(']').unwrap();
            let attr = &source[at..=attr_end];
            from = attr_end;
            if attr.contains("callback_interface") || attr.contains("tokio") {
                continue;
            }
            let rest = source[attr_end + 1..].trim_start();
            let is_async = if rest.starts_with("impl") {
                let open = attr_end + 1 + source[attr_end + 1..].find('{').unwrap();
                block(&source, open).contains("pub async fn")
            } else {
                rest.split('(').next().unwrap_or("").contains("async fn")
            };
            if is_async {
                let line = source[..at].lines().count() + 1;
                missing.push(format!("{}:{line}", path.display()));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "async export without the Tokio runtime: {missing:?}"
    );
}
