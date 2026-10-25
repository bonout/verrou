//! `verrou item create` and `verrou item edit`: fields given as
//! assignments, the 1Password CLI way, and `--generate-password`.
//!
//! - `name=value`: sets the field (`password`, `username`, `totp`,
//!   `notes`, a card's `number`…, otherwise a custom field, by its name);
//!   an empty value clears it.
//! - `name[password]=value` (or `[concealed]`, `[hidden]`): a hidden custom
//!   field; `name[text]=value`: a visible one.
//! - `name[delete]`: removes the custom field.

use verrou_bridge::protocol::FieldChange;
use verrou_core::generator::PasswordOptions;

/// One assignment, as typed.
pub fn parse_assignment(text: &str) -> Result<FieldChange, String> {
    let invalid =
        || format!("\"{text}\": expected name=value, name[password]=value or name[delete]");
    let (head, value) = match text.split_once('=') {
        Some((head, value)) => (head, Some(value)),
        None => (text, None),
    };
    let (name, kind) = match head.strip_suffix(']').and_then(|h| h.rsplit_once('[')) {
        Some((name, kind)) => (name, Some(kind.trim().to_lowercase())),
        None => (head, None),
    };
    let name = name.trim();
    if name.is_empty() {
        return Err(invalid());
    }
    let (value, hidden) = match (kind.as_deref(), value) {
        (Some("delete"), _) => (None, false),
        (_, None) => return Err(invalid()),
        (None | Some("text" | "string" | "url" | "email" | "phone" | "otp" | "totp"), Some(v)) => {
            (Some(v), false)
        }
        (Some("password" | "concealed" | "hidden"), Some(v)) => (Some(v), true),
        (Some(other), _) => {
            return Err(format!(
                "\"{text}\": unknown field type \"{other}\" (text, password or delete)"
            ));
        }
    };
    Ok(FieldChange {
        name: name.to_owned(),
        value: value.map(str::to_owned),
        hidden,
    })
}

/// `--generate-password=letters,digits,symbols,32`: what is listed is
/// used (letters always), the number is the length. Without a recipe: 20
/// characters of every kind.
pub fn password_recipe(recipe: Option<&str>) -> Result<PasswordOptions, String> {
    let mut options = PasswordOptions {
        length: 20,
        symbols: true,
        digits: true,
        avoid_ambiguous: true,
    };
    let Some(recipe) = recipe.filter(|r| !r.trim().is_empty()) else {
        return Ok(options);
    };
    options.symbols = false;
    options.digits = false;
    for part in recipe.split(',').map(str::trim) {
        match part {
            "letters" => {}
            "digits" => options.digits = true,
            "symbols" => options.symbols = true,
            number => {
                options.length = number
                    .parse()
                    .ok()
                    .filter(|n| (8..=128).contains(n))
                    .ok_or_else(|| {
                        format!(
                            "\"{part}\": expected letters, digits, symbols or a length (8 to 128)"
                        )
                    })?;
            }
        }
    }
    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(text: &str) -> (String, Option<String>, bool) {
        let c = parse_assignment(text).unwrap();
        (c.name.clone(), c.value.clone(), c.hidden)
    }

    #[test]
    fn assignments() {
        assert_eq!(
            change("password=a=b"),
            ("password".into(), Some("a=b".into()), false)
        );
        assert_eq!(
            change("API key[password]=sk_live"),
            ("API key".into(), Some("sk_live".into()), true)
        );
        assert_eq!(
            change("notes="),
            ("notes".into(), Some(String::new()), false)
        );
        assert_eq!(
            change("Old field[delete]"),
            ("Old field".into(), None, false)
        );
        assert!(parse_assignment("novalue").is_err());
        assert!(parse_assignment("=x").is_err());
        assert!(parse_assignment("x[weird]=1").is_err());
    }

    #[test]
    fn recipes() {
        let default = password_recipe(None).unwrap();
        assert_eq!(default.length, 20);
        assert!(default.symbols && default.digits);
        let recipe = password_recipe(Some("letters,digits,32")).unwrap();
        assert_eq!(recipe.length, 32);
        assert!(recipe.digits && !recipe.symbols);
        assert!(password_recipe(Some("letters,4")).is_err());
        assert!(password_recipe(Some("emoji")).is_err());
    }
}
