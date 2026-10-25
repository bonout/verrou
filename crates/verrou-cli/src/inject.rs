//! `verrou inject`: a template whose `{{ verrou://<item>/<field> }}`
//! references are replaced by the fields' values (a configuration file
//! written with its secrets, without them going through the terminal).
//!
//! Only what is between double braces and starts with `verrou://` is a
//! reference: other `{{ … }}` (another template language) pass as is.

use crate::run::{Reference, SCHEME};

/// A piece of the template: text as is, or a reference to resolve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Piece<'a> {
    Text(&'a str),
    Secret(Reference),
}

/// The template cut into pieces; an invalid reference is an error, with its
/// line.
pub fn parse(template: &str) -> Result<Vec<Piece<'_>>, String> {
    let mut pieces = Vec::new();
    let mut rest = template;
    let mut done = 0;
    while let Some(open) = rest.find("{{") {
        let Some(close) = rest[open + 2..].find("}}") else {
            break;
        };
        let inner = rest[open + 2..open + 2 + close].trim();
        let end = open + 2 + close + 2;
        if inner.starts_with(SCHEME) {
            let line = template[..done + open].matches('\n').count() + 1;
            let reference = Reference::parse(inner)
                .unwrap_or_else(|| Err(format!("\"{inner}\": invalid reference")))
                .map_err(|e| format!("line {line}: {e}"))?;
            if open > 0 {
                pieces.push(Piece::Text(&rest[..open]));
            }
            pieces.push(Piece::Secret(reference));
        } else {
            pieces.push(Piece::Text(&rest[..end]));
        }
        done += end;
        rest = &rest[end..];
    }
    if !rest.is_empty() {
        pieces.push(Piece::Text(rest));
    }
    Ok(pieces)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(item: &str, field: &str) -> Piece<'static> {
        Piece::Secret(Reference {
            item: item.into(),
            field: field.into(),
        })
    }

    #[test]
    fn references_are_found() {
        assert_eq!(
            parse("user: {{ verrou://DB/username }}\npass: {{verrou://DB/password}}\n").unwrap(),
            vec![
                Piece::Text("user: "),
                secret("DB", "username"),
                Piece::Text("\npass: "),
                secret("DB", "password"),
                Piece::Text("\n"),
            ]
        );
    }

    #[test]
    fn a_title_keeps_its_spaces() {
        assert_eq!(
            parse("{{ verrou://Production database/api key }}").unwrap(),
            vec![secret("Production database", "api key")]
        );
    }

    #[test]
    fn other_braces_pass_as_is() {
        assert_eq!(
            parse("{{ .Values.x }} and {{ unclosed").unwrap(),
            vec![
                Piece::Text("{{ .Values.x }}"),
                Piece::Text(" and {{ unclosed"),
            ]
        );
        assert_eq!(parse("").unwrap(), vec![]);
    }

    #[test]
    fn an_invalid_reference_says_its_line() {
        let error = parse("a\nb {{ verrou://nofield }}").unwrap_err();
        assert!(error.starts_with("line 2:"), "{error}");
    }
}
