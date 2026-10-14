//! Coffre fictif, déterministe, pour le développement, les tests, les captures
//! d'écran et les mesures de performance.
//!
//! Aucune donnée réelle : les adresses sont en `@exemple.fr` / `example.com`,
//! les cartes sont les numéros de test publics des réseaux de paiement, les
//! mots de passe et graines TOTP sont tirés d'un générateur à graine fixe.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::generator::{self, PasswordOptions};
use crate::model::{Field, FieldKind, Item, ItemKind};
use crate::secret::SecretString;

/// 2026-10-01 00:00 UTC : les dates fictives remontent à partir de là.
const NOW: i64 = 1_790_812_800;
const DAY: i64 = 86_400;

/// (titre, domaine, dossier, étiquettes, favori, 2FA)
type Service = (
    &'static str,
    &'static str,
    &'static str,
    &'static [&'static str],
    bool,
    bool,
);

const SERVICES: &[Service] = &[
    ("GitHub", "github.com", "Travail", &["dev"], true, true),
    (
        "Google",
        "accounts.google.com",
        "Personnel",
        &["mail"],
        true,
        true,
    ),
    (
        "Apple ID",
        "appleid.apple.com",
        "Personnel",
        &[],
        true,
        true,
    ),
    ("Amazon", "amazon.fr", "Achats", &["shopping"], false, false),
    (
        "Netflix",
        "netflix.com",
        "Maison",
        &["streaming"],
        false,
        false,
    ),
    (
        "Spotify",
        "spotify.com",
        "Maison",
        &["streaming"],
        false,
        false,
    ),
    (
        "Free",
        "subscribe.free.fr",
        "Maison",
        &["box", "factures"],
        false,
        false,
    ),
    (
        "EDF",
        "particulier.edf.fr",
        "Maison",
        &["factures"],
        false,
        false,
    ),
    (
        "Ameli",
        "ameli.fr",
        "Administratif",
        &["santé"],
        false,
        false,
    ),
    (
        "Impôts",
        "impots.gouv.fr",
        "Administratif",
        &["france-connect"],
        true,
        false,
    ),
    (
        "Doctolib",
        "doctolib.fr",
        "Administratif",
        &["santé"],
        false,
        true,
    ),
    (
        "SNCF Connect",
        "sncf-connect.com",
        "Voyages",
        &["train"],
        false,
        false,
    ),
    ("Airbnb", "airbnb.fr", "Voyages", &[], false, false),
    ("Booking.com", "booking.com", "Voyages", &[], false, false),
    (
        "Revolut",
        "app.revolut.com",
        "Finances",
        &["banque"],
        false,
        true,
    ),
    (
        "Boursorama",
        "clients.boursobank.com",
        "Finances",
        &["banque"],
        true,
        true,
    ),
    (
        "Qonto",
        "app.qonto.com",
        "Finances",
        &["banque", "pro"],
        false,
        true,
    ),
    ("Notion", "notion.so", "Travail", &["pro"], false, false),
    (
        "Linear",
        "linear.app",
        "Travail",
        &["dev", "pro"],
        false,
        true,
    ),
    ("Figma", "figma.com", "Travail", &["design"], false, false),
    ("Slack", "slack.com", "Travail", &["pro"], false, false),
    ("Discord", "discord.com", "Personnel", &[], false, true),
    (
        "Steam",
        "store.steampowered.com",
        "Loisirs",
        &["jeux"],
        false,
        true,
    ),
    (
        "PlayStation Network",
        "playstation.com",
        "Loisirs",
        &["jeux"],
        false,
        false,
    ),
    ("Strava", "strava.com", "Loisirs", &["sport"], false, false),
    (
        "Garmin Connect",
        "connect.garmin.com",
        "Loisirs",
        &["sport"],
        false,
        false,
    ),
    (
        "Proton",
        "account.proton.me",
        "Personnel",
        &["mail"],
        false,
        true,
    ),
    (
        "OVHcloud",
        "ovh.com",
        "Travail",
        &["dev", "infra"],
        false,
        true,
    ),
    (
        "Cloudflare",
        "dash.cloudflare.com",
        "Travail",
        &["dev", "infra"],
        true,
        true,
    ),
    (
        "AWS",
        "signin.aws.amazon.com",
        "Travail",
        &["dev", "infra"],
        false,
        true,
    ),
    (
        "Docker Hub",
        "hub.docker.com",
        "Travail",
        &["dev"],
        false,
        false,
    ),
    ("npm", "npmjs.com", "Travail", &["dev"], false, true),
    ("Vercel", "vercel.com", "Travail", &["dev"], false, false),
    (
        "Stripe",
        "dashboard.stripe.com",
        "Travail",
        &["pro"],
        false,
        true,
    ),
    (
        "Leboncoin",
        "leboncoin.fr",
        "Achats",
        &["shopping"],
        false,
        false,
    ),
    ("Vinted", "vinted.fr", "Achats", &["shopping"], false, false),
    ("Deliveroo", "deliveroo.fr", "Achats", &[], false, false),
    ("Uber", "uber.com", "Voyages", &[], false, false),
    ("BlaBlaCar", "blablacar.fr", "Voyages", &[], false, false),
    ("La Poste", "laposte.fr", "Administratif", &[], false, false),
    (
        "Vaultwarden",
        "vault.example.net",
        "Maison",
        &["homelab"],
        true,
        true,
    ),
    (
        "Jellyfin",
        "medias.example.net",
        "Maison",
        &["homelab"],
        false,
        false,
    ),
    (
        "Nextcloud",
        "cloud.example.net",
        "Maison",
        &["homelab"],
        false,
        true,
    ),
    (
        "Grafana Cloud",
        "grafana.net",
        "Travail",
        &["infra"],
        false,
        false,
    ),
    (
        "Société Générale",
        "particuliers.sg.fr",
        "Finances",
        &["banque"],
        false,
        false,
    ),
    (
        "Crédit Agricole",
        "credit-agricole.fr",
        "Finances",
        &["banque"],
        false,
        false,
    ),
    (
        "Le Monde",
        "lemonde.fr",
        "Loisirs",
        &["presse"],
        false,
        false,
    ),
    ("Duolingo", "duolingo.com", "Loisirs", &[], false, false),
];

const FIRST_NAMES: &[&str] = &[
    "camille", "louis", "lea", "hugo", "chloe", "lucas", "manon", "jules", "ines", "arthur",
];
const LAST_NAMES: &[&str] = &[
    "martin", "bernard", "dubois", "thomas", "robert", "richard", "petit", "durand", "leroy",
];
const FOLDERS: &[&str] = &[
    "Personnel",
    "Travail",
    "Finances",
    "Maison",
    "Administratif",
    "Voyages",
    "Achats",
    "Loisirs",
];
const TAGS: &[&str] = &["dev", "pro", "famille", "ancien", "à-vérifier", "partagé"];

/// Coffre fictif d'au moins `count` éléments (les éléments soignés d'abord,
/// puis du remplissage pour les mesures de performance).
/// Apps du Mac reliées à un identifiant du coffre fictif.
const MAC_APPS: [(&str, &str); 3] = [
    ("Slack", "com.tinyspeck.slackmacgap"),
    ("Discord", "com.hnc.Discord"),
    ("Notion", "notion.id"),
];

/// Organisation et collection du coffre fictif (identifiant, nom).
pub const MOCK_ORGANIZATION: (&str, &str) =
    ("0f1e2d3c-4b5a-4968-8776-655443322110", "Famille Martin");
pub const MOCK_COLLECTION: (&str, &str) =
    ("1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", "Comptes communs");

pub fn vault_items(count: usize, seed: u64) -> Vec<Item> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut builder = Builder {
        rng: &mut rng,
        next_id: 0,
    };
    let mut items = Vec::with_capacity(count.max(80));

    for (title, domain, folder, tags, favorite, totp) in SERVICES {
        let username = if title.contains("Apple") || domain.ends_with("google.com") {
            "camille.martin@exemple.fr".to_owned()
        } else if tags.contains(&"dev") {
            "camille-dev".to_owned()
        } else {
            "camille.martin@exemple.fr".to_owned()
        };
        let mut item = builder.login(title, domain, &username, folder, tags, *favorite, *totp);
        // Quelques identifiants reliés à leur app du Mac (remplissage par ⌘\).
        if let Some((_, bundle_id)) = MAC_APPS.iter().find(|(t, _)| t == title) {
            item.urls.push(format!("macapp://{bundle_id}"));
        }
        items.push(item);
    }
    // Deux comptes sur le même site, pour la correspondance et la recherche.
    items.push(builder.login(
        "GitHub — compte pro",
        "github.com",
        "camille-pro",
        "Travail",
        &["dev", "pro"],
        false,
        true,
    ));
    // Un compte commun, rangé dans le coffre partagé de la famille.
    let mut family = builder.login(
        "Google — famille",
        "accounts.google.com",
        "famille.martin@exemple.fr",
        "Personnel",
        &["famille"],
        false,
        false,
    );
    family.shared = Some(crate::Sharing {
        organization_id: MOCK_ORGANIZATION.0.to_owned(),
        organization: MOCK_ORGANIZATION.1.to_owned(),
        collections: vec![(MOCK_COLLECTION.0.to_owned(), MOCK_COLLECTION.1.to_owned())],
        read_only: false,
        hide_passwords: false,
    });
    items.push(family);

    items.extend(builder.cards());
    items.extend(builder.identities());
    items.extend(builder.notes());
    items.push(builder.ssh_key());

    while items.len() < count {
        items.push(builder.filler());
    }
    items
}

struct Builder<'a> {
    rng: &'a mut ChaCha20Rng,
    next_id: u64,
}

impl Builder<'_> {
    fn id(&mut self) -> String {
        self.next_id += 1;
        // Forme d'UUID, comme les identifiants Vaultwarden.
        let a: u64 = self.rng.r#gen();
        format!(
            "{:08x}-{:04x}-4{:03x}-a{:03x}-{:012x}",
            (a >> 32) as u32,
            (a >> 16) as u16,
            self.next_id & 0xfff,
            (a >> 4) & 0xfff,
            a & 0xffff_ffff_ffff
        )
    }

    fn dates(&mut self) -> (i64, i64) {
        let created = NOW - self.rng.gen_range(30..2000) * DAY;
        let modified =
            (created + self.rng.gen_range(0..900) * DAY).min(NOW - self.rng.gen_range(0..20) * DAY);
        (created, modified.max(created))
    }

    fn password(&mut self) -> String {
        const HABITS: [&str; 3] = ["soleil2019", "Azerty123!", "motdepasse"];
        let length = *[16, 20, 24, 32]
            .get(self.rng.gen_range(0..4))
            .unwrap_or(&20);
        let strong = generator::password_with(
            self.rng,
            &PasswordOptions {
                length,
                ..PasswordOptions::default()
            },
        );
        // Un identifiant sur treize garde une vieille habitude (faible,
        // réutilisé) : de quoi montrer l'audit. Sans tirage de plus, pour que
        // le reste du coffre fictif ne change pas.
        if self.next_id % 13 == 5 {
            return HABITS[(self.next_id / 13) as usize % HABITS.len()].to_owned();
        }
        strong
    }

    fn totp_secret(&mut self) -> String {
        let bytes: [u8; 20] = self.rng.r#gen();
        data_encoding::BASE32_NOPAD.encode(&bytes)
    }

    #[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
    fn login(
        &mut self,
        title: &str,
        domain: &str,
        username: &str,
        folder: &str,
        tags: &[&str],
        favorite: bool,
        totp: bool,
    ) -> Item {
        let (created, modified) = self.dates();
        let mut fields = vec![
            Field::new("username", "Identifiant", FieldKind::Username, username),
            Field::new(
                "password",
                "Mot de passe",
                FieldKind::Password,
                self.password(),
            ),
        ];
        if totp {
            let secret = self.totp_secret();
            fields.push(Field::new(
                "totp",
                "Code à usage unique",
                FieldKind::Totp,
                secret,
            ));
        }
        Item {
            id: self.id(),
            kind: ItemKind::Login,
            title: title.to_owned(),
            subtitle: username.to_owned(),
            urls: vec![format!("https://{domain}")],
            folder: Some(folder.to_owned()),
            tags: tags.iter().map(|t| (*t).to_owned()).collect(),
            favorite,
            created,
            modified,
            fields,
            notes: None,
            reprompt: false,
            state: crate::ItemState::Active,
            shared: None,
        }
    }

    fn cards(&mut self) -> Vec<Item> {
        // Numéros de test publics (Stripe, réseaux de paiement) : jamais valides.
        let cards = [
            (
                "Visa Boursorama",
                "4242 4242 4242 4242",
                "Visa",
                "09/29",
                true,
            ),
            (
                "Mastercard Revolut",
                "5555 5555 5555 4444",
                "Mastercard",
                "03/28",
                false,
            ),
            (
                "Amex Gold",
                "3782 822463 10005",
                "American Express",
                "11/27",
                false,
            ),
        ];
        cards
            .iter()
            .map(|(title, number, brand, expiry, favorite)| {
                let (created, modified) = self.dates();
                let last4: String = number
                    .chars()
                    .filter(char::is_ascii_digit)
                    .rev()
                    .take(4)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                let cvv_len = if brand.starts_with("American") { 4 } else { 3 };
                Item {
                    id: self.id(),
                    kind: ItemKind::Card,
                    title: (*title).to_owned(),
                    subtitle: format!("{brand} •••• {last4}"),
                    urls: Vec::new(),
                    folder: Some("Finances".to_owned()),
                    tags: vec!["banque".to_owned()],
                    favorite: *favorite,
                    created,
                    modified,
                    fields: vec![
                        Field::new("cardholder", "Titulaire", FieldKind::Text, "CAMILLE MARTIN"),
                        Field::new("brand", "Réseau", FieldKind::Text, *brand),
                        Field::new("number", "Numéro", FieldKind::CardNumber, *number),
                        Field::new("expiry", "Expiration", FieldKind::Expiry, *expiry),
                        Field::new(
                            "code",
                            "Cryptogramme",
                            FieldKind::Pin,
                            generator::pin(self.rng, cvv_len),
                        ),
                    ],
                    notes: None,
                    // Comme souvent dans Bitwarden : les cartes redemandent confirmation.
                    reprompt: true,
                    state: crate::ItemState::Active,
                    shared: None,
                }
            })
            .collect()
    }

    fn identities(&mut self) -> Vec<Item> {
        let (created, modified) = self.dates();
        let me = Item {
            id: self.id(),
            kind: ItemKind::Identity,
            title: "Camille Martin".to_owned(),
            subtitle: "camille.martin@exemple.fr".to_owned(),
            urls: Vec::new(),
            folder: Some("Personnel".to_owned()),
            tags: Vec::new(),
            favorite: true,
            created,
            modified,
            fields: vec![
                Field::new("first_name", "Prénom", FieldKind::Text, "Camille"),
                Field::new("last_name", "Nom", FieldKind::Text, "Martin"),
                Field::new(
                    "email",
                    "E-mail",
                    FieldKind::Email,
                    "camille.martin@exemple.fr",
                ),
                Field::new("phone", "Téléphone", FieldKind::Phone, "+33 6 12 34 56 78"),
                Field::new(
                    "birthdate",
                    "Date de naissance",
                    FieldKind::Date,
                    "14/03/1991",
                ),
                Field::new(
                    "address",
                    "Adresse",
                    FieldKind::Address,
                    "12 rue des Lilas\n74000 Annecy\nFrance",
                ),
            ],
            notes: None,
            reprompt: false,
            state: crate::ItemState::Active,
            shared: None,
        };
        let (created, modified) = self.dates();
        let passport = Item {
            id: self.id(),
            kind: ItemKind::Identity,
            title: "Passeport".to_owned(),
            subtitle: "Camille Martin".to_owned(),
            urls: Vec::new(),
            folder: Some("Administratif".to_owned()),
            tags: vec!["voyage".to_owned()],
            favorite: false,
            created,
            modified,
            fields: vec![
                Field::new("number", "Numéro", FieldKind::Concealed, "24AB12345"),
                Field::new("issued", "Délivré le", FieldKind::Date, "02/06/2022"),
                Field::new("expires", "Expire le", FieldKind::Date, "01/06/2032"),
                Field::new(
                    "authority",
                    "Autorité",
                    FieldKind::Text,
                    "Préfecture de la Haute-Savoie",
                ),
            ],
            notes: None,
            reprompt: false,
            state: crate::ItemState::Active,
            shared: None,
        };
        vec![me, passport]
    }

    fn notes(&mut self) -> Vec<Item> {
        let notes = [
            (
                "Wi-Fi maison",
                "Réseau : Martin-5G\nMot de passe : appelez Camille",
                "Maison",
                true,
            ),
            (
                "Codes de secours GitHub",
                "a1b2c-3d4e5\nf6g7h-8i9j0\nk1l2m-3n4o5\np6q7r-8s9t0",
                "Travail",
                false,
            ),
            (
                "Alarme et portail",
                "Code alarme : demander\nBadge portail : tiroir de l'entrée",
                "Maison",
                false,
            ),
            (
                "Contrat d'assurance habitation",
                "Assureur fictif\nContrat n° HAB-000-123\nFranchise : 150 €",
                "Administratif",
                false,
            ),
        ];
        let mut notes = notes
            .iter()
            .map(|(title, body, folder, favorite)| {
                let (created, modified) = self.dates();
                Item {
                    id: self.id(),
                    kind: ItemKind::SecureNote,
                    title: (*title).to_owned(),
                    // Jamais un extrait du contenu : la note est secrète, et le
                    // sous-titre est affiché et indexé en clair.
                    subtitle: "Note sécurisée".to_owned(),
                    urls: Vec::new(),
                    folder: Some((*folder).to_owned()),
                    tags: Vec::new(),
                    favorite: *favorite,
                    created,
                    modified,
                    fields: Vec::new(),
                    notes: Some(SecretString::new(*body)),
                    reprompt: false,
                    state: crate::ItemState::Active,
                    shared: None,
                }
            })
            .collect::<Vec<_>>();
        // Le Wi-Fi suit le modèle de Verrou : champs prédéfinis et QR code.
        if let Some(wifi) = notes.first_mut() {
            use crate::template::{MARKER, Template, WIFI_PASSWORD, WIFI_SECURITY, WIFI_SSID};
            Template::Wifi.singular().clone_into(&mut wifi.subtitle);
            wifi.fields = vec![
                Field::new("custom-0", WIFI_SSID, FieldKind::Text, "Martin-5G"),
                Field::new(
                    "custom-1",
                    WIFI_PASSWORD,
                    FieldKind::Concealed,
                    "lilas-portail-27",
                ),
                Field::new("custom-2", WIFI_SECURITY, FieldKind::Text, "WPA2"),
                Field::new(MARKER, MARKER, FieldKind::Text, Template::Wifi.key()),
            ];
        }
        notes
    }

    fn ssh_key(&mut self) -> Item {
        let (created, modified) = self.dates();
        let key: [u8; 32] = self.rng.r#gen();
        let public = format!(
            "ssh-ed25519 {} camille@macbook",
            data_encoding::BASE64
                .encode(&[&[0, 0, 0, 11][..], b"ssh-ed25519", &[0, 0, 0, 32], &key].concat())
        );
        Item {
            id: self.id(),
            kind: ItemKind::SshKey,
            title: "Clé SSH du N100".to_owned(),
            subtitle: "SHA256:fictive…".to_owned(),
            urls: Vec::new(),
            folder: Some("Travail".to_owned()),
            tags: vec!["infra".to_owned()],
            favorite: false,
            created,
            modified,
            fields: vec![
                Field::new("public_key", "Clé publique", FieldKind::Multiline, public),
                Field::new(
                    "private_key",
                    "Clé privée",
                    FieldKind::Concealed,
                    "-----BEGIN OPENSSH PRIVATE KEY-----\n(clé fictive)\n-----END OPENSSH PRIVATE KEY-----",
                ),
            ],
            notes: None,
            reprompt: false,
            state: crate::ItemState::Active,
            shared: None,
        }
    }

    fn filler(&mut self) -> Item {
        let (title, domain, _, _, _, _) = SERVICES[self.rng.gen_range(0..SERVICES.len())];
        let first = FIRST_NAMES[self.rng.gen_range(0..FIRST_NAMES.len())];
        let last = LAST_NAMES[self.rng.gen_range(0..LAST_NAMES.len())];
        let folder = FOLDERS[self.rng.gen_range(0..FOLDERS.len())];
        let tag = TAGS[self.rng.gen_range(0..TAGS.len())];
        let username = format!("{first}.{last}{}@exemple.fr", self.rng.gen_range(1..999));
        let totp = self.rng.gen_bool(0.25);
        let display = format!("{title} — {}", capitalise(first));
        self.login(&display, domain, &username, folder, &[tag], false, totp)
    }
}

fn capitalise(word: &str) -> String {
    let mut chars = word.chars();
    chars
        .next()
        .map_or_else(String::new, |c| c.to_uppercase().chain(chars).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let a = vault_items(200, 42);
        let b = vault_items(200, 42);
        assert_eq!(a, b);
        assert_eq!(a.len(), 200);
    }

    #[test]
    fn every_kind_is_represented() {
        let items = vault_items(0, 1);
        for kind in ItemKind::ALL {
            assert!(items.iter().any(|i| i.kind == kind), "{kind:?} manquant");
        }
    }

    #[test]
    fn ids_are_unique() {
        let items = vault_items(5_000, 3);
        let mut ids: Vec<_> = items.iter().map(|i| i.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), items.len());
    }
}
