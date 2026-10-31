//! Mock vault, deterministic, for development, tests, screenshots
//! and performance measurements.
//!
//! Five languages, the app's: an English-speaking user's vault (the default),
//! and a French, German, Spanish and Italian-speaking user's, each with the
//! services, banks and names of that country. All have the same items, in
//! the same order, of the same kinds, with the same ids and secrets for a
//! given seed: only the words change.
//!
//! No real data: addresses are `example.com`, `@exemple.fr`,
//! `@beispiel.de`, `@ejemplo.es` or `@esempio.it`,
//! cards are the payment networks' public test numbers,
//! passwords and TOTP seeds are drawn from a fixed-seed generator.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::generator::{self, PasswordOptions};
use crate::model::{Field, FieldKind, Item, ItemKind};
use crate::secret::SecretString;

/// 2026-10-01 00:00 UTC: mock dates go back from there.
const NOW: i64 = 1_790_812_800;
const DAY: i64 = 86_400;

/// Language of the mock vault's words (titles, folders, labels, notes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum MockLanguage {
    #[default]
    En,
    Fr,
    De,
    Es,
    It,
}

impl MockLanguage {
    /// From a language code (`fr`, `de-DE`, `en-US`…): French for `fr…`,
    /// German for `de…`, Spanish for `es…`, Italian for `it…`, English
    /// otherwise.
    pub fn from_code(code: &str) -> Self {
        let code = code.trim().to_ascii_lowercase();
        match code.get(..2) {
            Some("fr") => Self::Fr,
            Some("de") => Self::De,
            Some("es") => Self::Es,
            Some("it") => Self::It,
            _ => Self::En,
        }
    }

    fn texts(self) -> &'static Texts {
        match self {
            Self::En => &EN,
            Self::Fr => &FR,
            Self::De => &DE,
            Self::Es => &ES,
            Self::It => &IT,
        }
    }
}

/// (title, domain, folder, tags, favorite, 2FA)
type Service = (
    &'static str,
    &'static str,
    &'static str,
    &'static [&'static str],
    bool,
    bool,
);

/// (title, addresses, username, password, days since the
/// last change, TOTP seed)
type Duplicate = (
    &'static str,
    &'static [&'static str],
    &'static str,
    &'static str,
    i64,
    Option<&'static str>,
);

/// (title, number, brand, expiry, favorite)
type Card = (&'static str, &'static str, &'static str, &'static str, bool);

/// (title, body, folder, favorite)
type Note = (&'static str, &'static str, &'static str, bool);

/// Labels of the fields the mock vault fills itself. The English ones are
/// verrou-core's (Vaultwarden conversion, templates), which the apps
/// translate.
struct Labels {
    username: &'static str,
    password: &'static str,
    totp: &'static str,
    cardholder: &'static str,
    brand: &'static str,
    number: &'static str,
    expiry: &'static str,
    code: &'static str,
    first_name: &'static str,
    last_name: &'static str,
    email: &'static str,
    phone: &'static str,
    birthdate: &'static str,
    address: &'static str,
    issued: &'static str,
    expires: &'static str,
    authority: &'static str,
    public_key: &'static str,
    private_key: &'static str,
}

/// Everything in the mock vault that depends on the language.
struct Texts {
    services: &'static [Service],
    first_names: &'static [&'static str],
    last_names: &'static [&'static str],
    folders: &'static [&'static str],
    tags: &'static [&'static str],
    /// Weak habits, for the password audit.
    habits: [&'static str; 3],
    labels: Labels,
    /// The owner: full name, first name, email, dev and work usernames.
    name: &'static str,
    first_name: &'static str,
    last_name: &'static str,
    email: &'static str,
    dev_username: &'static str,
    /// Filler addresses' domain.
    mail_domain: &'static str,
    /// Second GitHub account: title, username, folder, tags.
    github_pro: (
        &'static str,
        &'static str,
        &'static str,
        &'static [&'static str],
    ),
    /// Shared family account: title, username, folder, tags.
    family: (
        &'static str,
        &'static str,
        &'static str,
        &'static [&'static str],
    ),
    organization: &'static str,
    collection: &'static str,
    cards: [Card; 3],
    cards_folder: &'static str,
    cards_tag: &'static str,
    cardholder: &'static str,
    identity_folder: &'static str,
    phone: &'static str,
    birthdate: &'static str,
    address: &'static str,
    passport: &'static str,
    passport_folder: &'static str,
    passport_tag: &'static str,
    passport_number: &'static str,
    passport_issued: &'static str,
    passport_expires: &'static str,
    passport_authority: &'static str,
    notes: [Note; 4],
    secure_note: &'static str,
    wifi_ssid: &'static str,
    wifi_password: &'static str,
    ssh_title: &'static str,
    ssh_folder: &'static str,
    ssh_user: &'static str,
    ssh_private: &'static str,
    ssh_fingerprint: &'static str,
    duplicates: &'static [Duplicate],
    duplicate_cards: [&'static str; 2],
    fake_key: &'static str,
}

const EN: Texts = Texts {
    services: &[
        ("GitHub", "github.com", "Work", &["dev"], true, true),
        (
            "Google",
            "accounts.google.com",
            "Personal",
            &["mail"],
            true,
            true,
        ),
        ("Apple ID", "appleid.apple.com", "Personal", &[], true, true),
        (
            "Amazon",
            "amazon.com",
            "Shopping",
            &["shopping"],
            false,
            false,
        ),
        (
            "Netflix",
            "netflix.com",
            "Home",
            &["streaming"],
            false,
            false,
        ),
        (
            "Spotify",
            "spotify.com",
            "Home",
            &["streaming"],
            false,
            false,
        ),
        (
            "Xfinity",
            "xfinity.com",
            "Home",
            &["internet", "bills"],
            false,
            false,
        ),
        ("Con Edison", "coned.com", "Home", &["bills"], false, false),
        (
            "Kaiser Permanente",
            "healthy.kaiserpermanente.org",
            "Admin",
            &["health"],
            false,
            false,
        ),
        ("IRS", "irs.gov", "Admin", &["taxes"], true, false),
        ("Zocdoc", "zocdoc.com", "Admin", &["health"], false, true),
        ("Amtrak", "amtrak.com", "Travel", &["train"], false, false),
        ("Airbnb", "airbnb.com", "Travel", &[], false, false),
        ("Booking.com", "booking.com", "Travel", &[], false, false),
        (
            "Revolut",
            "app.revolut.com",
            "Finance",
            &["bank"],
            false,
            true,
        ),
        (
            "Chase",
            "secure.chase.com",
            "Finance",
            &["bank"],
            true,
            true,
        ),
        (
            "Mercury",
            "app.mercury.com",
            "Finance",
            &["bank", "work"],
            false,
            true,
        ),
        ("Notion", "notion.so", "Work", &["work"], false, false),
        (
            "Linear",
            "linear.app",
            "Work",
            &["dev", "work"],
            false,
            true,
        ),
        ("Figma", "figma.com", "Work", &["design"], false, false),
        ("Slack", "slack.com", "Work", &["work"], false, false),
        ("Discord", "discord.com", "Personal", &[], false, true),
        (
            "Steam",
            "store.steampowered.com",
            "Hobbies",
            &["games"],
            false,
            true,
        ),
        (
            "PlayStation Network",
            "playstation.com",
            "Hobbies",
            &["games"],
            false,
            false,
        ),
        (
            "Strava",
            "strava.com",
            "Hobbies",
            &["fitness"],
            false,
            false,
        ),
        (
            "Garmin Connect",
            "connect.garmin.com",
            "Hobbies",
            &["fitness"],
            false,
            false,
        ),
        (
            "Proton",
            "account.proton.me",
            "Personal",
            &["mail"],
            false,
            true,
        ),
        (
            "DigitalOcean",
            "cloud.digitalocean.com",
            "Work",
            &["dev", "infra"],
            false,
            true,
        ),
        (
            "Cloudflare",
            "dash.cloudflare.com",
            "Work",
            &["dev", "infra"],
            true,
            true,
        ),
        (
            "AWS",
            "signin.aws.amazon.com",
            "Work",
            &["dev", "infra"],
            false,
            true,
        ),
        (
            "Docker Hub",
            "hub.docker.com",
            "Work",
            &["dev"],
            false,
            false,
        ),
        ("npm", "npmjs.com", "Work", &["dev"], false, true),
        ("Vercel", "vercel.com", "Work", &["dev"], false, false),
        (
            "Stripe",
            "dashboard.stripe.com",
            "Work",
            &["work"],
            false,
            true,
        ),
        ("eBay", "ebay.com", "Shopping", &["shopping"], false, false),
        ("Etsy", "etsy.com", "Shopping", &["shopping"], false, false),
        ("DoorDash", "doordash.com", "Shopping", &[], false, false),
        ("Uber", "uber.com", "Travel", &[], false, false),
        ("Lyft", "lyft.com", "Travel", &[], false, false),
        ("USPS", "usps.com", "Admin", &[], false, false),
        (
            "Vaultwarden",
            "vault.example.net",
            "Home",
            &["homelab"],
            true,
            true,
        ),
        (
            "Jellyfin",
            "media.example.net",
            "Home",
            &["homelab"],
            false,
            false,
        ),
        (
            "Nextcloud",
            "cloud.example.net",
            "Home",
            &["homelab"],
            false,
            true,
        ),
        (
            "Grafana Cloud",
            "grafana.net",
            "Work",
            &["infra"],
            false,
            false,
        ),
        (
            "Bank of America",
            "bankofamerica.com",
            "Finance",
            &["bank"],
            false,
            false,
        ),
        (
            "Wells Fargo",
            "wellsfargo.com",
            "Finance",
            &["bank"],
            false,
            false,
        ),
        (
            "The New York Times",
            "nytimes.com",
            "Hobbies",
            &["news"],
            false,
            false,
        ),
        ("Duolingo", "duolingo.com", "Hobbies", &[], false, false),
    ],
    first_names: &[
        "emily", "james", "olivia", "liam", "sophia", "noah", "ava", "ethan", "mia", "lucas",
    ],
    last_names: &[
        "smith", "johnson", "williams", "brown", "jones", "miller", "davis", "wilson", "taylor",
    ],
    folders: &[
        "Personal", "Work", "Finance", "Home", "Admin", "Travel", "Shopping", "Hobbies",
    ],
    tags: &["dev", "work", "family", "old", "to-review", "shared"],
    habits: ["sunshine2019", "Qwerty123!", "password1"],
    labels: Labels {
        username: "Username",
        password: "Password",
        totp: "One-time code",
        cardholder: "Cardholder",
        brand: "Brand",
        number: "Number",
        expiry: "Expiration",
        code: "Security code",
        first_name: "First name",
        last_name: "Last name",
        email: "Email",
        phone: "Phone",
        birthdate: "Date of birth",
        address: "Address",
        issued: "Issue date",
        expires: "Expiry date",
        authority: "Issuing authority",
        public_key: "Public key",
        private_key: "Private key",
    },
    name: "Emily Parker",
    first_name: "Emily",
    last_name: "Parker",
    email: "emily.parker@example.com",
    dev_username: "emily-dev",
    mail_domain: "example.com",
    github_pro: (
        "GitHub — work account",
        "emily-work",
        "Work",
        &["dev", "work"],
    ),
    family: (
        "Google — family",
        "parker.family@example.com",
        "Personal",
        &["family"],
    ),
    organization: "Parker Family",
    collection: "Shared accounts",
    cards: [
        ("Chase Visa", "4242 4242 4242 4242", "Visa", "09/29", true),
        (
            "Revolut Mastercard",
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
    ],
    cards_folder: "Finance",
    cards_tag: "bank",
    cardholder: "EMILY PARKER",
    identity_folder: "Personal",
    phone: "+1 415 555 0132",
    birthdate: "03/14/1991",
    address: "1427 Maple Street\nPortland, OR 97205\nUnited States",
    passport: "Passport",
    passport_folder: "Admin",
    passport_tag: "travel",
    passport_number: "A12345678",
    passport_issued: "06/02/2022",
    passport_expires: "06/01/2032",
    passport_authority: "United States Department of State",
    notes: [
        (
            "Home Wi-Fi",
            "Network: Parker-5G\nPassword: ask Emily",
            "Home",
            true,
        ),
        (
            "GitHub recovery codes",
            "a1b2c-3d4e5\nf6g7h-8i9j0\nk1l2m-3n4o5\np6q7r-8s9t0",
            "Work",
            false,
        ),
        (
            "Alarm and gate",
            "Alarm code: ask\nGate fob: hallway drawer",
            "Home",
            false,
        ),
        (
            "Home insurance policy",
            "Sample insurer\nPolicy no. HOM-000-123\nDeductible: $500",
            "Admin",
            false,
        ),
    ],
    secure_note: "Secure note",
    wifi_ssid: "Parker-5G",
    wifi_password: "maple-porch-27",
    ssh_title: "N100 SSH key",
    ssh_folder: "Work",
    ssh_user: "emily@macbook",
    ssh_private: "-----BEGIN OPENSSH PRIVATE KEY-----\n(sample key)\n-----END OPENSSH PRIVATE KEY-----",
    ssh_fingerprint: "SHA256:sample…",
    duplicates: &[
        (
            "GEICO",
            &["https://www.geico.com"],
            "emily.parker@example.com",
            "geico-Lilac-42",
            3,
            Some("JBSWY3DPEHPK3PXP"),
        ),
        (
            "GEICO - Policy center",
            &["https://www.geico.com/account/policies"],
            "Emily.Parker@example.com",
            "geico-Lilac-42",
            400,
            None,
        ),
        (
            "geico.com",
            &[],
            "emily.parker@example.com",
            "geico-Lilac-42",
            700,
            None,
        ),
        ("GEICO", &[], "", "geico-Lilac-42", 900, None),
        (
            "Google",
            &["https://accounts.google.com"],
            "emily.parker@example.com",
            "g-Linden-77",
            10,
            Some("GEZDGNBVGY3TQOJQ"),
        ),
        (
            "google.com",
            &["https://google.com/"],
            "emily.parker+news@example.com",
            "g-old-2019",
            800,
            None,
        ),
        (
            "Gmail",
            &["https://mail.google.com"],
            "emily.parker@example.com",
            "g-Linden-77",
            200,
            None,
        ),
        (
            "Facebook",
            &["https://m.facebook.com"],
            "emily.parker@example.com",
            "fb-Maple-13",
            30,
            None,
        ),
        (
            "facebook.com (emily)",
            &["http://facebook.com:443/login"],
            "emily.parker@example.com",
            "fb-Maple-13",
            600,
            None,
        ),
        (
            "Netflix",
            &["https://www.netflix.com"],
            "emily@example.com",
            "shared-Willow-8",
            50,
            None,
        ),
        (
            "Netflix — Jordan",
            &["https://netflix.com/browse"],
            "jordan@example.com",
            "shared-Willow-8",
            90,
            None,
        ),
        (
            "Nextcloud",
            &["https://cloud.example.com"],
            "emily",
            "nc-Birch-1",
            20,
            None,
        ),
        (
            "Vaultwarden",
            &["https://vault.example.com"],
            "emily",
            "vw-Hornbeam-2",
            25,
            None,
        ),
        ("Router", &[], "admin", "router-Beech-5", 100, None),
        ("router", &[], "Admin", "router-old", 1000, None),
        (
            "Slack",
            &["https://slack.com", "macapp://com.tinyspeck.slackmacgap"],
            "emily.parker@example.com",
            "slack-Elm-3",
            40,
            None,
        ),
        (
            "Slack (app)",
            &["macapp://com.tinyspeck.slackmacgap"],
            "emily.parker@example.com",
            "slack-Elm-3",
            300,
            None,
        ),
        (
            "Amazon",
            &["https://www.amazon.com"],
            "emily.parker@example.com",
            "amz-Poplar-4",
            60,
            None,
        ),
        (
            "Amazon",
            &["https://amazon.com/ap/signin"],
            "",
            "amz-Ash-6",
            500,
            None,
        ),
    ],
    duplicate_cards: ["Visa Chase Sapphire", "Visa card"],
    fake_key: "sample key",
};

const FR: Texts = Texts {
    services: &[
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
    ],
    first_names: &[
        "camille", "louis", "lea", "hugo", "chloe", "lucas", "manon", "jules", "ines", "arthur",
    ],
    last_names: &[
        "martin", "bernard", "dubois", "thomas", "robert", "richard", "petit", "durand", "leroy",
    ],
    folders: &[
        "Personnel",
        "Travail",
        "Finances",
        "Maison",
        "Administratif",
        "Voyages",
        "Achats",
        "Loisirs",
    ],
    tags: &["dev", "pro", "famille", "ancien", "à-vérifier", "partagé"],
    habits: ["soleil2019", "Azerty123!", "motdepasse"],
    labels: Labels {
        username: "Nom d'utilisateur",
        password: "Mot de passe",
        totp: "Code à usage unique",
        cardholder: "Titulaire",
        brand: "Réseau",
        number: "Numéro",
        expiry: "Expiration",
        code: "Cryptogramme",
        first_name: "Prénom",
        last_name: "Nom",
        email: "E-mail",
        phone: "Téléphone",
        birthdate: "Date de naissance",
        address: "Adresse",
        issued: "Délivré le",
        expires: "Expire le",
        authority: "Autorité",
        public_key: "Clé publique",
        private_key: "Clé privée",
    },
    name: "Camille Martin",
    first_name: "Camille",
    last_name: "Martin",
    email: "camille.martin@exemple.fr",
    dev_username: "camille-dev",
    mail_domain: "exemple.fr",
    github_pro: (
        "GitHub — compte pro",
        "camille-pro",
        "Travail",
        &["dev", "pro"],
    ),
    family: (
        "Google — famille",
        "famille.martin@exemple.fr",
        "Personnel",
        &["famille"],
    ),
    organization: "Famille Martin",
    collection: "Comptes communs",
    cards: [
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
    ],
    cards_folder: "Finances",
    cards_tag: "banque",
    cardholder: "CAMILLE MARTIN",
    identity_folder: "Personnel",
    phone: "+33 6 12 34 56 78",
    birthdate: "14/03/1991",
    address: "12 rue des Lilas\n74000 Annecy\nFrance",
    passport: "Passeport",
    passport_folder: "Administratif",
    passport_tag: "voyage",
    passport_number: "24AB12345",
    passport_issued: "02/06/2022",
    passport_expires: "01/06/2032",
    passport_authority: "Préfecture de la Haute-Savoie",
    notes: [
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
    ],
    secure_note: "Note sécurisée",
    wifi_ssid: "Martin-5G",
    wifi_password: "lilas-portail-27",
    ssh_title: "Clé SSH du N100",
    ssh_folder: "Travail",
    ssh_user: "camille@macbook",
    ssh_private: "-----BEGIN OPENSSH PRIVATE KEY-----\n(clé fictive)\n-----END OPENSSH PRIVATE KEY-----",
    ssh_fingerprint: "SHA256:fictive…",
    duplicates: &[
        (
            "Maif",
            &["https://www.maif.fr"],
            "camille.martin@exemple.fr",
            "maif-Lilas-42",
            3,
            Some("JBSWY3DPEHPK3PXP"),
        ),
        (
            "MAIF - Espace sociétaire",
            &["https://connect.maif.fr/espace-perso"],
            "Camille.Martin@exemple.fr",
            "maif-Lilas-42",
            400,
            None,
        ),
        (
            "maif.fr",
            &[],
            "camille.martin@exemple.fr",
            "maif-Lilas-42",
            700,
            None,
        ),
        ("Maif", &[], "", "maif-Lilas-42", 900, None),
        (
            "Google",
            &["https://accounts.google.com"],
            "camille.martin@exemple.fr",
            "g-Tilleul-77",
            10,
            Some("GEZDGNBVGY3TQOJQ"),
        ),
        (
            "google.com",
            &["https://google.com/"],
            "camille.martin+news@exemple.fr",
            "g-ancien-2019",
            800,
            None,
        ),
        (
            "Gmail",
            &["https://mail.google.com"],
            "camille.martin@exemple.fr",
            "g-Tilleul-77",
            200,
            None,
        ),
        (
            "Facebook",
            &["https://m.facebook.com"],
            "camille.martin@exemple.fr",
            "fb-Erable-13",
            30,
            None,
        ),
        (
            "facebook.com (camille)",
            &["http://facebook.com:443/login"],
            "camille.martin@exemple.fr",
            "fb-Erable-13",
            600,
            None,
        ),
        (
            "Netflix",
            &["https://www.netflix.com"],
            "camille@exemple.fr",
            "partage-Saule-8",
            50,
            None,
        ),
        (
            "Netflix — Dominique",
            &["https://netflix.com/browse"],
            "dominique@exemple.fr",
            "partage-Saule-8",
            90,
            None,
        ),
        (
            "Nextcloud",
            &["https://cloud.exemple.fr"],
            "camille",
            "nc-Bouleau-1",
            20,
            None,
        ),
        (
            "Vaultwarden",
            &["https://vault.exemple.fr"],
            "camille",
            "vw-Charme-2",
            25,
            None,
        ),
        ("Routeur", &[], "admin", "routeur-Hetre-5", 100, None),
        ("routeur", &[], "Admin", "routeur-ancien", 1000, None),
        (
            "Slack",
            &["https://slack.com", "macapp://com.tinyspeck.slackmacgap"],
            "camille.martin@exemple.fr",
            "slack-Orme-3",
            40,
            None,
        ),
        (
            "Slack (app)",
            &["macapp://com.tinyspeck.slackmacgap"],
            "camille.martin@exemple.fr",
            "slack-Orme-3",
            300,
            None,
        ),
        (
            "Amazon",
            &["https://www.amazon.fr"],
            "camille.martin@exemple.fr",
            "amz-Peuplier-4",
            60,
            None,
        ),
        (
            "Amazon",
            &["https://amazon.fr/ap/signin"],
            "",
            "amz-Frene-6",
            500,
            None,
        ),
    ],
    duplicate_cards: ["Visa Boursorama", "Carte Visa"],
    fake_key: "clé fictive",
};

const DE: Texts = Texts {
    services: &[
        ("GitHub", "github.com", "Arbeit", &["dev"], true, true),
        (
            "Google",
            "accounts.google.com",
            "Persönlich",
            &["mail"],
            true,
            true,
        ),
        (
            "Apple ID",
            "appleid.apple.com",
            "Persönlich",
            &[],
            true,
            true,
        ),
        (
            "Amazon",
            "amazon.de",
            "Einkäufe",
            &["shopping"],
            false,
            false,
        ),
        (
            "Netflix",
            "netflix.com",
            "Zuhause",
            &["streaming"],
            false,
            false,
        ),
        (
            "Spotify",
            "spotify.com",
            "Zuhause",
            &["streaming"],
            false,
            false,
        ),
        (
            "Telekom",
            "telekom.de",
            "Zuhause",
            &["internet", "rechnungen"],
            false,
            false,
        ),
        ("E.ON", "eon.de", "Zuhause", &["rechnungen"], false, false),
        (
            "Techniker Krankenkasse",
            "tk.de",
            "Verwaltung",
            &["gesundheit"],
            false,
            false,
        ),
        (
            "ELSTER",
            "elster.de",
            "Verwaltung",
            &["steuern"],
            true,
            false,
        ),
        (
            "Doctolib",
            "doctolib.de",
            "Verwaltung",
            &["gesundheit"],
            false,
            true,
        ),
        ("DB Navigator", "bahn.de", "Reisen", &["bahn"], false, false),
        ("Airbnb", "airbnb.de", "Reisen", &[], false, false),
        ("Booking.com", "booking.com", "Reisen", &[], false, false),
        ("N26", "app.n26.com", "Finanzen", &["bank"], false, true),
        ("DKB", "banking.dkb.de", "Finanzen", &["bank"], true, true),
        (
            "Qonto",
            "app.qonto.com",
            "Finanzen",
            &["bank", "arbeit"],
            false,
            true,
        ),
        ("Notion", "notion.so", "Arbeit", &["arbeit"], false, false),
        (
            "Linear",
            "linear.app",
            "Arbeit",
            &["dev", "arbeit"],
            false,
            true,
        ),
        ("Figma", "figma.com", "Arbeit", &["design"], false, false),
        ("Slack", "slack.com", "Arbeit", &["arbeit"], false, false),
        ("Discord", "discord.com", "Persönlich", &[], false, true),
        (
            "Steam",
            "store.steampowered.com",
            "Freizeit",
            &["spiele"],
            false,
            true,
        ),
        (
            "PlayStation Network",
            "playstation.com",
            "Freizeit",
            &["spiele"],
            false,
            false,
        ),
        ("Strava", "strava.com", "Freizeit", &["sport"], false, false),
        (
            "Garmin Connect",
            "connect.garmin.com",
            "Freizeit",
            &["sport"],
            false,
            false,
        ),
        (
            "Proton",
            "account.proton.me",
            "Persönlich",
            &["mail"],
            false,
            true,
        ),
        (
            "Hetzner",
            "accounts.hetzner.com",
            "Arbeit",
            &["dev", "infra"],
            false,
            true,
        ),
        (
            "Cloudflare",
            "dash.cloudflare.com",
            "Arbeit",
            &["dev", "infra"],
            true,
            true,
        ),
        (
            "AWS",
            "signin.aws.amazon.com",
            "Arbeit",
            &["dev", "infra"],
            false,
            true,
        ),
        (
            "Docker Hub",
            "hub.docker.com",
            "Arbeit",
            &["dev"],
            false,
            false,
        ),
        ("npm", "npmjs.com", "Arbeit", &["dev"], false, true),
        ("Vercel", "vercel.com", "Arbeit", &["dev"], false, false),
        (
            "Stripe",
            "dashboard.stripe.com",
            "Arbeit",
            &["arbeit"],
            false,
            true,
        ),
        (
            "Kleinanzeigen",
            "kleinanzeigen.de",
            "Einkäufe",
            &["shopping"],
            false,
            false,
        ),
        (
            "Zalando",
            "zalando.de",
            "Einkäufe",
            &["shopping"],
            false,
            false,
        ),
        ("Lieferando", "lieferando.de", "Einkäufe", &[], false, false),
        ("Uber", "uber.com", "Reisen", &[], false, false),
        ("FlixBus", "flixbus.de", "Reisen", &[], false, false),
        (
            "Deutsche Post",
            "deutschepost.de",
            "Verwaltung",
            &[],
            false,
            false,
        ),
        (
            "Vaultwarden",
            "vault.example.net",
            "Zuhause",
            &["homelab"],
            true,
            true,
        ),
        (
            "Jellyfin",
            "medien.example.net",
            "Zuhause",
            &["homelab"],
            false,
            false,
        ),
        (
            "Nextcloud",
            "cloud.example.net",
            "Zuhause",
            &["homelab"],
            false,
            true,
        ),
        (
            "Grafana Cloud",
            "grafana.net",
            "Arbeit",
            &["infra"],
            false,
            false,
        ),
        (
            "Sparkasse München",
            "sskm.de",
            "Finanzen",
            &["bank"],
            false,
            false,
        ),
        (
            "Commerzbank",
            "commerzbank.de",
            "Finanzen",
            &["bank"],
            false,
            false,
        ),
        (
            "Der Spiegel",
            "spiegel.de",
            "Freizeit",
            &["presse"],
            false,
            false,
        ),
        ("Duolingo", "duolingo.com", "Freizeit", &[], false, false),
    ],
    first_names: &[
        "anna", "lukas", "lea", "leon", "mia", "finn", "emma", "paul", "hannah", "jonas",
    ],
    last_names: &[
        "mueller",
        "schmidt",
        "schneider",
        "fischer",
        "weber",
        "meyer",
        "wagner",
        "becker",
        "hoffmann",
    ],
    folders: &[
        "Persönlich",
        "Arbeit",
        "Finanzen",
        "Zuhause",
        "Verwaltung",
        "Reisen",
        "Einkäufe",
        "Freizeit",
    ],
    tags: &["dev", "arbeit", "familie", "alt", "prüfen", "geteilt"],
    habits: ["sommer2019", "Qwertz123!", "passwort1"],
    labels: Labels {
        username: "Benutzername",
        password: "Passwort",
        totp: "Einmalcode",
        cardholder: "Karteninhaber",
        brand: "Kartennetz",
        number: "Nummer",
        expiry: "Gültig bis",
        code: "Prüfnummer",
        first_name: "Vorname",
        last_name: "Nachname",
        email: "E-Mail",
        phone: "Telefon",
        birthdate: "Geburtsdatum",
        address: "Adresse",
        issued: "Ausstellungsdatum",
        expires: "Gültig bis",
        authority: "Behörde",
        public_key: "Öffentlicher Schlüssel",
        private_key: "Privater Schlüssel",
    },
    name: "Anna Schneider",
    first_name: "Anna",
    last_name: "Schneider",
    email: "anna.schneider@beispiel.de",
    dev_username: "anna-dev",
    mail_domain: "beispiel.de",
    github_pro: (
        "GitHub — Arbeitskonto",
        "anna-arbeit",
        "Arbeit",
        &["dev", "arbeit"],
    ),
    family: (
        "Google — Familie",
        "familie.schneider@beispiel.de",
        "Persönlich",
        &["familie"],
    ),
    organization: "Familie Schneider",
    collection: "Gemeinsame Konten",
    cards: [
        ("DKB Visa", "4242 4242 4242 4242", "Visa", "09/29", true),
        (
            "N26 Mastercard",
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
    ],
    cards_folder: "Finanzen",
    cards_tag: "bank",
    cardholder: "ANNA SCHNEIDER",
    identity_folder: "Persönlich",
    phone: "+49 151 23456789",
    birthdate: "14.03.1991",
    address: "Lindenstraße 12\n80331 München\nDeutschland",
    passport: "Reisepass",
    passport_folder: "Verwaltung",
    passport_tag: "reise",
    passport_number: "C4J7K2M9T",
    passport_issued: "02.06.2022",
    passport_expires: "01.06.2032",
    passport_authority: "Landeshauptstadt München",
    notes: [
        (
            "WLAN Zuhause",
            "Netzwerk: Schneider-5G\nPasswort: Anna fragen",
            "Zuhause",
            true,
        ),
        (
            "GitHub-Wiederherstellungscodes",
            "a1b2c-3d4e5\nf6g7h-8i9j0\nk1l2m-3n4o5\np6q7r-8s9t0",
            "Arbeit",
            false,
        ),
        (
            "Alarmanlage und Tor",
            "Alarmcode: nachfragen\nTorchip: Schublade im Flur",
            "Zuhause",
            false,
        ),
        (
            "Hausratversicherung",
            "Beispielversicherer\nVertragsnr. HR-000-123\nSelbstbeteiligung: 150 €",
            "Verwaltung",
            false,
        ),
    ],
    secure_note: "Sichere Notiz",
    wifi_ssid: "Schneider-5G",
    wifi_password: "linden-tor-27",
    ssh_title: "SSH-Schlüssel des N100",
    ssh_folder: "Arbeit",
    ssh_user: "anna@macbook",
    ssh_private: "-----BEGIN OPENSSH PRIVATE KEY-----\n(Beispielschlüssel)\n-----END OPENSSH PRIVATE KEY-----",
    ssh_fingerprint: "SHA256:beispiel…",
    duplicates: &[
        (
            "Gothaer",
            &["https://www.gothaer.de"],
            "anna.schneider@beispiel.de",
            "gothaer-Flieder-42",
            3,
            Some("JBSWY3DPEHPK3PXP"),
        ),
        (
            "Gothaer - Meine Gothaer",
            &["https://www.gothaer.de/meine-gothaer"],
            "Anna.Schneider@beispiel.de",
            "gothaer-Flieder-42",
            400,
            None,
        ),
        (
            "gothaer.de",
            &[],
            "anna.schneider@beispiel.de",
            "gothaer-Flieder-42",
            700,
            None,
        ),
        ("Gothaer", &[], "", "gothaer-Flieder-42", 900, None),
        (
            "Google",
            &["https://accounts.google.com"],
            "anna.schneider@beispiel.de",
            "g-Linde-77",
            10,
            Some("GEZDGNBVGY3TQOJQ"),
        ),
        (
            "google.com",
            &["https://google.com/"],
            "anna.schneider+news@beispiel.de",
            "g-alt-2019",
            800,
            None,
        ),
        (
            "Gmail",
            &["https://mail.google.com"],
            "anna.schneider@beispiel.de",
            "g-Linde-77",
            200,
            None,
        ),
        (
            "Facebook",
            &["https://m.facebook.com"],
            "anna.schneider@beispiel.de",
            "fb-Ahorn-13",
            30,
            None,
        ),
        (
            "facebook.com (anna)",
            &["http://facebook.com:443/login"],
            "anna.schneider@beispiel.de",
            "fb-Ahorn-13",
            600,
            None,
        ),
        (
            "Netflix",
            &["https://www.netflix.com"],
            "anna@beispiel.de",
            "geteilt-Weide-8",
            50,
            None,
        ),
        (
            "Netflix — Sabine",
            &["https://netflix.com/browse"],
            "sabine@beispiel.de",
            "geteilt-Weide-8",
            90,
            None,
        ),
        (
            "Nextcloud",
            &["https://cloud.beispiel.de"],
            "anna",
            "nc-Birke-1",
            20,
            None,
        ),
        (
            "Vaultwarden",
            &["https://vault.beispiel.de"],
            "anna",
            "vw-Hainbuche-2",
            25,
            None,
        ),
        ("Router", &[], "admin", "router-Buche-5", 100, None),
        ("router", &[], "Admin", "router-alt", 1000, None),
        (
            "Slack",
            &["https://slack.com", "macapp://com.tinyspeck.slackmacgap"],
            "anna.schneider@beispiel.de",
            "slack-Ulme-3",
            40,
            None,
        ),
        (
            "Slack (App)",
            &["macapp://com.tinyspeck.slackmacgap"],
            "anna.schneider@beispiel.de",
            "slack-Ulme-3",
            300,
            None,
        ),
        (
            "Amazon",
            &["https://www.amazon.de"],
            "anna.schneider@beispiel.de",
            "amz-Pappel-4",
            60,
            None,
        ),
        (
            "Amazon",
            &["https://amazon.de/ap/signin"],
            "",
            "amz-Esche-6",
            500,
            None,
        ),
    ],
    duplicate_cards: ["Visa DKB", "Visa-Karte"],
    fake_key: "Beispielschlüssel",
};

const ES: Texts = Texts {
    services: &[
        ("GitHub", "github.com", "Trabajo", &["dev"], true, true),
        (
            "Google",
            "accounts.google.com",
            "Personal",
            &["correo"],
            true,
            true,
        ),
        ("Apple ID", "appleid.apple.com", "Personal", &[], true, true),
        ("Amazon", "amazon.es", "Compras", &["compras"], false, false),
        (
            "Netflix",
            "netflix.com",
            "Casa",
            &["streaming"],
            false,
            false,
        ),
        (
            "Spotify",
            "spotify.com",
            "Casa",
            &["streaming"],
            false,
            false,
        ),
        (
            "Movistar",
            "movistar.es",
            "Casa",
            &["fibra", "facturas"],
            false,
            false,
        ),
        (
            "Iberdrola",
            "iberdrola.es",
            "Casa",
            &["facturas"],
            false,
            false,
        ),
        (
            "Sanitas",
            "sanitas.es",
            "Trámites",
            &["salud"],
            false,
            false,
        ),
        (
            "Agencia Tributaria",
            "agenciatributaria.gob.es",
            "Trámites",
            &["cl@ve"],
            true,
            false,
        ),
        (
            "Doctoralia",
            "doctoralia.es",
            "Trámites",
            &["salud"],
            false,
            true,
        ),
        ("Renfe", "renfe.com", "Viajes", &["tren"], false, false),
        ("Airbnb", "airbnb.es", "Viajes", &[], false, false),
        ("Booking.com", "booking.com", "Viajes", &[], false, false),
        (
            "Revolut",
            "app.revolut.com",
            "Finanzas",
            &["banco"],
            false,
            true,
        ),
        ("BBVA", "bbva.es", "Finanzas", &["banco"], true, true),
        (
            "Qonto",
            "app.qonto.com",
            "Finanzas",
            &["banco", "trabajo"],
            false,
            true,
        ),
        ("Notion", "notion.so", "Trabajo", &["trabajo"], false, false),
        (
            "Linear",
            "linear.app",
            "Trabajo",
            &["dev", "trabajo"],
            false,
            true,
        ),
        ("Figma", "figma.com", "Trabajo", &["diseño"], false, false),
        ("Slack", "slack.com", "Trabajo", &["trabajo"], false, false),
        ("Discord", "discord.com", "Personal", &[], false, true),
        (
            "Steam",
            "store.steampowered.com",
            "Ocio",
            &["juegos"],
            false,
            true,
        ),
        (
            "PlayStation Network",
            "playstation.com",
            "Ocio",
            &["juegos"],
            false,
            false,
        ),
        ("Strava", "strava.com", "Ocio", &["deporte"], false, false),
        (
            "Garmin Connect",
            "connect.garmin.com",
            "Ocio",
            &["deporte"],
            false,
            false,
        ),
        (
            "Proton",
            "account.proton.me",
            "Personal",
            &["correo"],
            false,
            true,
        ),
        (
            "Arsys",
            "arsys.es",
            "Trabajo",
            &["dev", "infra"],
            false,
            true,
        ),
        (
            "Cloudflare",
            "dash.cloudflare.com",
            "Trabajo",
            &["dev", "infra"],
            true,
            true,
        ),
        (
            "AWS",
            "signin.aws.amazon.com",
            "Trabajo",
            &["dev", "infra"],
            false,
            true,
        ),
        (
            "Docker Hub",
            "hub.docker.com",
            "Trabajo",
            &["dev"],
            false,
            false,
        ),
        ("npm", "npmjs.com", "Trabajo", &["dev"], false, true),
        ("Vercel", "vercel.com", "Trabajo", &["dev"], false, false),
        (
            "Stripe",
            "dashboard.stripe.com",
            "Trabajo",
            &["trabajo"],
            false,
            true,
        ),
        (
            "Wallapop",
            "es.wallapop.com",
            "Compras",
            &["compras"],
            false,
            false,
        ),
        (
            "El Corte Inglés",
            "elcorteingles.es",
            "Compras",
            &["compras"],
            false,
            false,
        ),
        ("Glovo", "glovoapp.com", "Compras", &[], false, false),
        ("Cabify", "cabify.com", "Viajes", &[], false, false),
        ("BlaBlaCar", "blablacar.es", "Viajes", &[], false, false),
        ("Correos", "correos.es", "Trámites", &[], false, false),
        (
            "Vaultwarden",
            "vault.example.net",
            "Casa",
            &["homelab"],
            true,
            true,
        ),
        (
            "Jellyfin",
            "medios.example.net",
            "Casa",
            &["homelab"],
            false,
            false,
        ),
        (
            "Nextcloud",
            "cloud.example.net",
            "Casa",
            &["homelab"],
            false,
            true,
        ),
        (
            "Grafana Cloud",
            "grafana.net",
            "Trabajo",
            &["infra"],
            false,
            false,
        ),
        (
            "Banco Santander",
            "bancosantander.es",
            "Finanzas",
            &["banco"],
            false,
            false,
        ),
        (
            "CaixaBank",
            "caixabank.es",
            "Finanzas",
            &["banco"],
            false,
            false,
        ),
        ("El País", "elpais.com", "Ocio", &["prensa"], false, false),
        ("Duolingo", "duolingo.com", "Ocio", &[], false, false),
    ],
    first_names: &[
        "lucia",
        "hugo",
        "sofia",
        "martin",
        "martina",
        "pablo",
        "paula",
        "alejandro",
        "valeria",
        "daniel",
    ],
    last_names: &[
        "garcia",
        "rodriguez",
        "gonzalez",
        "fernandez",
        "lopez",
        "martinez",
        "sanchez",
        "perez",
        "gomez",
    ],
    folders: &[
        "Personal",
        "Trabajo",
        "Finanzas",
        "Casa",
        "Trámites",
        "Viajes",
        "Compras",
        "Ocio",
    ],
    tags: &[
        "dev",
        "trabajo",
        "familia",
        "antiguo",
        "revisar",
        "compartido",
    ],
    habits: ["verano2019", "Qwerty123!", "contraseña"],
    labels: Labels {
        username: "Usuario",
        password: "Contraseña",
        totp: "Código de un solo uso",
        cardholder: "Titular",
        brand: "Red",
        number: "Número",
        expiry: "Caducidad",
        code: "CVV",
        first_name: "Nombre",
        last_name: "Apellidos",
        email: "Correo electrónico",
        phone: "Teléfono",
        birthdate: "Fecha de nacimiento",
        address: "Dirección",
        issued: "Fecha de expedición",
        expires: "Fecha de caducidad",
        authority: "Autoridad",
        public_key: "Clave pública",
        private_key: "Clave privada",
    },
    name: "Lucía García",
    first_name: "Lucía",
    last_name: "García",
    email: "lucia.garcia@ejemplo.es",
    dev_username: "lucia-dev",
    mail_domain: "ejemplo.es",
    github_pro: (
        "GitHub — cuenta del trabajo",
        "lucia-trabajo",
        "Trabajo",
        &["dev", "trabajo"],
    ),
    family: (
        "Google — familia",
        "familia.garcia@ejemplo.es",
        "Personal",
        &["familia"],
    ),
    organization: "Familia García",
    collection: "Cuentas compartidas",
    cards: [
        ("Visa BBVA", "4242 4242 4242 4242", "Visa", "09/29", true),
        (
            "Mastercard Revolut",
            "5555 5555 5555 4444",
            "Mastercard",
            "03/28",
            false,
        ),
        (
            "Amex Oro",
            "3782 822463 10005",
            "American Express",
            "11/27",
            false,
        ),
    ],
    cards_folder: "Finanzas",
    cards_tag: "banco",
    cardholder: "LUCIA GARCIA",
    identity_folder: "Personal",
    phone: "+34 612 34 56 78",
    birthdate: "14/03/1991",
    address: "Calle de las Lilas, 12, 3.º B\n28013 Madrid\nEspaña",
    passport: "Pasaporte",
    passport_folder: "Trámites",
    passport_tag: "viaje",
    passport_number: "PAA123456",
    passport_issued: "02/06/2022",
    passport_expires: "01/06/2032",
    passport_authority: "Dirección General de la Policía",
    notes: [
        (
            "Wi-Fi de casa",
            "Red: Garcia-5G\nContraseña: pregunta a Lucía",
            "Casa",
            true,
        ),
        (
            "Códigos de recuperación de GitHub",
            "a1b2c-3d4e5\nf6g7h-8i9j0\nk1l2m-3n4o5\np6q7r-8s9t0",
            "Trabajo",
            false,
        ),
        (
            "Alarma y portal",
            "Código de la alarma: preguntar\nMando del portal: cajón de la entrada",
            "Casa",
            false,
        ),
        (
            "Póliza del seguro de hogar",
            "Aseguradora ficticia\nPóliza n.º HOG-000-123\nFranquicia: 150 €",
            "Trámites",
            false,
        ),
    ],
    secure_note: "Nota segura",
    wifi_ssid: "Garcia-5G",
    wifi_password: "lilas-portal-27",
    ssh_title: "Clave SSH del N100",
    ssh_folder: "Trabajo",
    ssh_user: "lucia@macbook",
    ssh_private: "-----BEGIN OPENSSH PRIVATE KEY-----\n(clave ficticia)\n-----END OPENSSH PRIVATE KEY-----",
    ssh_fingerprint: "SHA256:ficticia…",
    duplicates: &[
        (
            "Mapfre",
            &["https://www.mapfre.es"],
            "lucia.garcia@ejemplo.es",
            "mapfre-Lila-42",
            3,
            Some("JBSWY3DPEHPK3PXP"),
        ),
        (
            "MAPFRE - Área de clientes",
            &["https://www.mapfre.es/area-clientes/"],
            "Lucia.Garcia@ejemplo.es",
            "mapfre-Lila-42",
            400,
            None,
        ),
        (
            "mapfre.es",
            &[],
            "lucia.garcia@ejemplo.es",
            "mapfre-Lila-42",
            700,
            None,
        ),
        ("Mapfre", &[], "", "mapfre-Lila-42", 900, None),
        (
            "Google",
            &["https://accounts.google.com"],
            "lucia.garcia@ejemplo.es",
            "g-Tilo-77",
            10,
            Some("GEZDGNBVGY3TQOJQ"),
        ),
        (
            "google.com",
            &["https://google.com/"],
            "lucia.garcia+news@ejemplo.es",
            "g-antigua-2019",
            800,
            None,
        ),
        (
            "Gmail",
            &["https://mail.google.com"],
            "lucia.garcia@ejemplo.es",
            "g-Tilo-77",
            200,
            None,
        ),
        (
            "Facebook",
            &["https://m.facebook.com"],
            "lucia.garcia@ejemplo.es",
            "fb-Arce-13",
            30,
            None,
        ),
        (
            "facebook.com (lucia)",
            &["http://facebook.com:443/login"],
            "lucia.garcia@ejemplo.es",
            "fb-Arce-13",
            600,
            None,
        ),
        (
            "Netflix",
            &["https://www.netflix.com"],
            "lucia@ejemplo.es",
            "compartida-Sauce-8",
            50,
            None,
        ),
        (
            "Netflix — Carmen",
            &["https://netflix.com/browse"],
            "carmen@ejemplo.es",
            "compartida-Sauce-8",
            90,
            None,
        ),
        (
            "Nextcloud",
            &["https://cloud.ejemplo.es"],
            "lucia",
            "nc-Abedul-1",
            20,
            None,
        ),
        (
            "Vaultwarden",
            &["https://vault.ejemplo.es"],
            "lucia",
            "vw-Carpe-2",
            25,
            None,
        ),
        ("Router", &[], "admin", "router-Haya-5", 100, None),
        ("router", &[], "Admin", "router-antiguo", 1000, None),
        (
            "Slack",
            &["https://slack.com", "macapp://com.tinyspeck.slackmacgap"],
            "lucia.garcia@ejemplo.es",
            "slack-Olmo-3",
            40,
            None,
        ),
        (
            "Slack (app)",
            &["macapp://com.tinyspeck.slackmacgap"],
            "lucia.garcia@ejemplo.es",
            "slack-Olmo-3",
            300,
            None,
        ),
        (
            "Amazon",
            &["https://www.amazon.es"],
            "lucia.garcia@ejemplo.es",
            "amz-Alamo-4",
            60,
            None,
        ),
        (
            "Amazon",
            &["https://amazon.es/ap/signin"],
            "",
            "amz-Fresno-6",
            500,
            None,
        ),
    ],
    duplicate_cards: ["Visa BBVA", "Tarjeta Visa"],
    fake_key: "clave ficticia",
};

const IT: Texts = Texts {
    services: &[
        ("GitHub", "github.com", "Lavoro", &["dev"], true, true),
        (
            "Google",
            "accounts.google.com",
            "Personale",
            &["posta"],
            true,
            true,
        ),
        (
            "Apple ID",
            "appleid.apple.com",
            "Personale",
            &[],
            true,
            true,
        ),
        (
            "Amazon",
            "amazon.it",
            "Acquisti",
            &["shopping"],
            false,
            false,
        ),
        (
            "Netflix",
            "netflix.com",
            "Casa",
            &["streaming"],
            false,
            false,
        ),
        (
            "Spotify",
            "spotify.com",
            "Casa",
            &["streaming"],
            false,
            false,
        ),
        (
            "TIM",
            "tim.it",
            "Casa",
            &["fibra", "bollette"],
            false,
            false,
        ),
        (
            "Enel Energia",
            "enel.it",
            "Casa",
            &["bollette"],
            false,
            false,
        ),
        (
            "Fascicolo Sanitario",
            "fascicolosanitario.gov.it",
            "Pratiche",
            &["salute"],
            false,
            false,
        ),
        (
            "Agenzia delle Entrate",
            "agenziaentrate.gov.it",
            "Pratiche",
            &["spid"],
            true,
            false,
        ),
        (
            "MioDottore",
            "miodottore.it",
            "Pratiche",
            &["salute"],
            false,
            true,
        ),
        (
            "Trenitalia",
            "trenitalia.com",
            "Viaggi",
            &["treno"],
            false,
            false,
        ),
        ("Airbnb", "airbnb.it", "Viaggi", &[], false, false),
        ("Booking.com", "booking.com", "Viaggi", &[], false, false),
        (
            "Revolut",
            "app.revolut.com",
            "Finanze",
            &["banca"],
            false,
            true,
        ),
        (
            "Fineco",
            "finecobank.com",
            "Finanze",
            &["banca"],
            true,
            true,
        ),
        (
            "Qonto",
            "app.qonto.com",
            "Finanze",
            &["banca", "lavoro"],
            false,
            true,
        ),
        ("Notion", "notion.so", "Lavoro", &["lavoro"], false, false),
        (
            "Linear",
            "linear.app",
            "Lavoro",
            &["dev", "lavoro"],
            false,
            true,
        ),
        ("Figma", "figma.com", "Lavoro", &["design"], false, false),
        ("Slack", "slack.com", "Lavoro", &["lavoro"], false, false),
        ("Discord", "discord.com", "Personale", &[], false, true),
        (
            "Steam",
            "store.steampowered.com",
            "Tempo libero",
            &["giochi"],
            false,
            true,
        ),
        (
            "PlayStation Network",
            "playstation.com",
            "Tempo libero",
            &["giochi"],
            false,
            false,
        ),
        (
            "Strava",
            "strava.com",
            "Tempo libero",
            &["sport"],
            false,
            false,
        ),
        (
            "Garmin Connect",
            "connect.garmin.com",
            "Tempo libero",
            &["sport"],
            false,
            false,
        ),
        (
            "Proton",
            "account.proton.me",
            "Personale",
            &["posta"],
            false,
            true,
        ),
        (
            "Aruba",
            "aruba.it",
            "Lavoro",
            &["dev", "infra"],
            false,
            true,
        ),
        (
            "Cloudflare",
            "dash.cloudflare.com",
            "Lavoro",
            &["dev", "infra"],
            true,
            true,
        ),
        (
            "AWS",
            "signin.aws.amazon.com",
            "Lavoro",
            &["dev", "infra"],
            false,
            true,
        ),
        (
            "Docker Hub",
            "hub.docker.com",
            "Lavoro",
            &["dev"],
            false,
            false,
        ),
        ("npm", "npmjs.com", "Lavoro", &["dev"], false, true),
        ("Vercel", "vercel.com", "Lavoro", &["dev"], false, false),
        (
            "Stripe",
            "dashboard.stripe.com",
            "Lavoro",
            &["lavoro"],
            false,
            true,
        ),
        (
            "Subito",
            "subito.it",
            "Acquisti",
            &["shopping"],
            false,
            false,
        ),
        (
            "Vinted",
            "vinted.it",
            "Acquisti",
            &["shopping"],
            false,
            false,
        ),
        ("Just Eat", "justeat.it", "Acquisti", &[], false, false),
        ("Italo", "italotreno.com", "Viaggi", &[], false, false),
        ("BlaBlaCar", "blablacar.it", "Viaggi", &[], false, false),
        ("Poste Italiane", "poste.it", "Pratiche", &[], false, false),
        (
            "Vaultwarden",
            "vault.example.net",
            "Casa",
            &["homelab"],
            true,
            true,
        ),
        (
            "Jellyfin",
            "media.example.net",
            "Casa",
            &["homelab"],
            false,
            false,
        ),
        (
            "Nextcloud",
            "cloud.example.net",
            "Casa",
            &["homelab"],
            false,
            true,
        ),
        (
            "Grafana Cloud",
            "grafana.net",
            "Lavoro",
            &["infra"],
            false,
            false,
        ),
        (
            "Intesa Sanpaolo",
            "intesasanpaolo.com",
            "Finanze",
            &["banca"],
            false,
            false,
        ),
        (
            "UniCredit",
            "unicredit.it",
            "Finanze",
            &["banca"],
            false,
            false,
        ),
        (
            "Corriere della Sera",
            "corriere.it",
            "Tempo libero",
            &["giornali"],
            false,
            false,
        ),
        (
            "Duolingo",
            "duolingo.com",
            "Tempo libero",
            &[],
            false,
            false,
        ),
    ],
    first_names: &[
        "giulia",
        "francesco",
        "sofia",
        "alessandro",
        "aurora",
        "lorenzo",
        "ginevra",
        "mattia",
        "alice",
        "leonardo",
    ],
    last_names: &[
        "rossi", "russo", "ferrari", "esposito", "bianchi", "romano", "colombo", "ricci", "marino",
    ],
    folders: &[
        "Personale",
        "Lavoro",
        "Finanze",
        "Casa",
        "Pratiche",
        "Viaggi",
        "Acquisti",
        "Tempo libero",
    ],
    tags: &[
        "dev",
        "lavoro",
        "famiglia",
        "vecchio",
        "da-verificare",
        "condiviso",
    ],
    habits: ["sole2019", "Qwerty123!", "juventus"],
    labels: Labels {
        username: "Nome utente",
        password: "Password",
        totp: "Codice monouso",
        cardholder: "Titolare",
        brand: "Circuito",
        number: "Numero",
        expiry: "Scadenza",
        code: "CVV",
        first_name: "Nome",
        last_name: "Cognome",
        email: "Email",
        phone: "Telefono",
        birthdate: "Data di nascita",
        address: "Indirizzo",
        issued: "Data di rilascio",
        expires: "Data di scadenza",
        authority: "Autorità",
        public_key: "Chiave pubblica",
        private_key: "Chiave privata",
    },
    name: "Giulia Rossi",
    first_name: "Giulia",
    last_name: "Rossi",
    email: "giulia.rossi@esempio.it",
    dev_username: "giulia-dev",
    mail_domain: "esempio.it",
    github_pro: (
        "GitHub — account di lavoro",
        "giulia-lavoro",
        "Lavoro",
        &["dev", "lavoro"],
    ),
    family: (
        "Google — famiglia",
        "famiglia.rossi@esempio.it",
        "Personale",
        &["famiglia"],
    ),
    organization: "Famiglia Rossi",
    collection: "Account condivisi",
    cards: [
        ("Visa Fineco", "4242 4242 4242 4242", "Visa", "09/29", true),
        (
            "Mastercard Revolut",
            "5555 5555 5555 4444",
            "Mastercard",
            "03/28",
            false,
        ),
        (
            "Amex Oro",
            "3782 822463 10005",
            "American Express",
            "11/27",
            false,
        ),
    ],
    cards_folder: "Finanze",
    cards_tag: "banca",
    cardholder: "GIULIA ROSSI",
    identity_folder: "Personale",
    phone: "+39 347 123 4567",
    birthdate: "14/03/1991",
    address: "Via dei Lillà 12\n20121 Milano MI\nItalia",
    passport: "Passaporto",
    passport_folder: "Pratiche",
    passport_tag: "viaggio",
    passport_number: "YA1234567",
    passport_issued: "02/06/2022",
    passport_expires: "01/06/2032",
    passport_authority: "Questura di Milano",
    notes: [
        (
            "Wi-Fi di casa",
            "Rete: Rossi-5G\nPassword: chiedi a Giulia",
            "Casa",
            true,
        ),
        (
            "Codici di recupero GitHub",
            "a1b2c-3d4e5\nf6g7h-8i9j0\nk1l2m-3n4o5\np6q7r-8s9t0",
            "Lavoro",
            false,
        ),
        (
            "Allarme e cancello",
            "Codice allarme: chiedere\nTelecomando del cancello: cassetto dell'ingresso",
            "Casa",
            false,
        ),
        (
            "Polizza assicurazione casa",
            "Assicuratore fittizio\nPolizza n. CASA-000-123\nFranchigia: 150 €",
            "Pratiche",
            false,
        ),
    ],
    secure_note: "Nota sicura",
    wifi_ssid: "Rossi-5G",
    wifi_password: "lilla-cancello-27",
    ssh_title: "Chiave SSH del N100",
    ssh_folder: "Lavoro",
    ssh_user: "giulia@macbook",
    ssh_private: "-----BEGIN OPENSSH PRIVATE KEY-----\n(chiave fittizia)\n-----END OPENSSH PRIVATE KEY-----",
    ssh_fingerprint: "SHA256:fittizia…",
    duplicates: &[
        (
            "Generali",
            &["https://www.generali.it"],
            "giulia.rossi@esempio.it",
            "generali-Lilla-42",
            3,
            Some("JBSWY3DPEHPK3PXP"),
        ),
        (
            "GENERALI - Area clienti",
            &["https://www.generali.it/area-clienti"],
            "Giulia.Rossi@esempio.it",
            "generali-Lilla-42",
            400,
            None,
        ),
        (
            "generali.it",
            &[],
            "giulia.rossi@esempio.it",
            "generali-Lilla-42",
            700,
            None,
        ),
        ("Generali", &[], "", "generali-Lilla-42", 900, None),
        (
            "Google",
            &["https://accounts.google.com"],
            "giulia.rossi@esempio.it",
            "g-Tiglio-77",
            10,
            Some("GEZDGNBVGY3TQOJQ"),
        ),
        (
            "google.com",
            &["https://google.com/"],
            "giulia.rossi+news@esempio.it",
            "g-vecchia-2019",
            800,
            None,
        ),
        (
            "Gmail",
            &["https://mail.google.com"],
            "giulia.rossi@esempio.it",
            "g-Tiglio-77",
            200,
            None,
        ),
        (
            "Facebook",
            &["https://m.facebook.com"],
            "giulia.rossi@esempio.it",
            "fb-Acero-13",
            30,
            None,
        ),
        (
            "facebook.com (giulia)",
            &["http://facebook.com:443/login"],
            "giulia.rossi@esempio.it",
            "fb-Acero-13",
            600,
            None,
        ),
        (
            "Netflix",
            &["https://www.netflix.com"],
            "giulia@esempio.it",
            "condivisa-Salice-8",
            50,
            None,
        ),
        (
            "Netflix — Marco",
            &["https://netflix.com/browse"],
            "marco@esempio.it",
            "condivisa-Salice-8",
            90,
            None,
        ),
        (
            "Nextcloud",
            &["https://cloud.esempio.it"],
            "giulia",
            "nc-Betulla-1",
            20,
            None,
        ),
        (
            "Vaultwarden",
            &["https://vault.esempio.it"],
            "giulia",
            "vw-Carpino-2",
            25,
            None,
        ),
        ("Router", &[], "admin", "router-Faggio-5", 100, None),
        ("router", &[], "Admin", "router-vecchio", 1000, None),
        (
            "Slack",
            &["https://slack.com", "macapp://com.tinyspeck.slackmacgap"],
            "giulia.rossi@esempio.it",
            "slack-Olmo-3",
            40,
            None,
        ),
        (
            "Slack (app)",
            &["macapp://com.tinyspeck.slackmacgap"],
            "giulia.rossi@esempio.it",
            "slack-Olmo-3",
            300,
            None,
        ),
        (
            "Amazon",
            &["https://www.amazon.it"],
            "giulia.rossi@esempio.it",
            "amz-Pioppo-4",
            60,
            None,
        ),
        (
            "Amazon",
            &["https://amazon.it/ap/signin"],
            "",
            "amz-Frassino-6",
            500,
            None,
        ),
    ],
    duplicate_cards: ["Visa Fineco", "Carta Visa"],
    fake_key: "chiave fittizia",
};

/// Mac apps linked to a login of the mock vault.
const MAC_APPS: [(&str, &str); 3] = [
    ("Slack", "com.tinyspeck.slackmacgap"),
    ("Discord", "com.hnc.Discord"),
    ("Notion", "notion.id"),
];

/// Ids of the mock vault's organization and collection.
pub const MOCK_ORGANIZATION_ID: &str = "0f1e2d3c-4b5a-4968-8776-655443322110";
pub const MOCK_COLLECTION_ID: &str = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";

/// Name of the mock vault's organization.
pub fn organization_name(language: MockLanguage) -> &'static str {
    language.texts().organization
}

/// Name of the mock vault's collection.
pub fn collection_name(language: MockLanguage) -> &'static str {
    language.texts().collection
}

/// Mock vault of at least `count` items (the hand-crafted items first,
/// then filler for performance measurements).
pub fn vault_items(count: usize, seed: u64, language: MockLanguage) -> Vec<Item> {
    let t = language.texts();
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut builder = Builder {
        rng: &mut rng,
        next_id: 0,
        t,
    };
    let mut items = Vec::with_capacity(count.max(80));

    for (title, domain, folder, tags, favorite, totp) in t.services {
        let username = if tags.contains(&"dev") {
            t.dev_username
        } else {
            t.email
        };
        let mut item = builder.login(title, domain, username, folder, tags, *favorite, *totp);
        // A few logins linked to their Mac app (filling with ⌘\).
        if let Some((_, bundle_id)) = MAC_APPS.iter().find(|(t, _)| t == title) {
            item.urls.push(format!("macapp://{bundle_id}"));
        }
        items.push(item);
    }
    // Two accounts on the same site, for matching and search.
    let (title, username, folder, tags) = t.github_pro;
    items.push(builder.login(title, "github.com", username, folder, tags, false, true));
    // A shared account, stored in the family's shared vault.
    let (title, username, folder, tags) = t.family;
    let mut family = builder.login(
        title,
        "accounts.google.com",
        username,
        folder,
        tags,
        false,
        false,
    );
    family.shared = Some(crate::Sharing {
        organization_id: MOCK_ORGANIZATION_ID.to_owned(),
        organization: t.organization.to_owned(),
        collections: vec![(MOCK_COLLECTION_ID.to_owned(), t.collection.to_owned())],
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

/// Mock duplicates (logins and cards), for tests and the visual
/// review of the duplicates sheet. Ids `dup-N`.
///
/// The same account, arrived several times through the Apple,
/// 1Password and Proton Pass imports: addresses, titles and usernames that
/// vary. These mock passwords are only used for comparison.
pub fn duplicate_items(language: MockLanguage) -> Vec<Item> {
    let t = language.texts();
    let mut items: Vec<Item> = t
        .duplicates
        .iter()
        .enumerate()
        .map(|(n, (title, urls, username, password, age, totp))| {
            let mut fields = Vec::new();
            if !username.is_empty() {
                fields.push(Field::new(
                    "username",
                    t.labels.username,
                    FieldKind::Username,
                    *username,
                ));
            }
            fields.push(Field::new(
                "password",
                t.labels.password,
                FieldKind::Password,
                *password,
            ));
            if let Some(secret) = totp {
                fields.push(Field::new("totp", t.labels.totp, FieldKind::Totp, *secret));
            }
            Item {
                id: format!("dup-{n}"),
                kind: ItemKind::Login,
                title: (*title).to_owned(),
                subtitle: (*username).to_owned(),
                urls: urls.iter().map(|u| (*u).to_owned()).collect(),
                url_matches: Vec::new(),
                folder: None,
                tags: Vec::new(),
                favorite: false,
                created: NOW - 2000 * DAY,
                modified: NOW - age * DAY,
                fields,
                notes: None,
                reprompt: false,
                state: crate::ItemState::Active,
                shared: None,
            }
        })
        .collect();
    for (n, title) in [100, 101].into_iter().zip(t.duplicate_cards) {
        items.push(Item {
            id: format!("dup-{n}"),
            kind: ItemKind::Card,
            title: title.to_owned(),
            subtitle: "Visa •••• 4242".to_owned(),
            urls: Vec::new(),
            url_matches: Vec::new(),
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created: NOW - 900 * DAY,
            modified: NOW - (n - 90) * DAY,
            fields: vec![Field::new(
                "number",
                t.labels.number,
                FieldKind::CardNumber,
                "4242 4242 4242 4242",
            )],
            notes: None,
            reprompt: false,
            state: crate::ItemState::Active,
            shared: None,
        });
    }
    items
}

struct Builder<'a> {
    rng: &'a mut ChaCha20Rng,
    next_id: u64,
    t: &'static Texts,
}

impl Builder<'_> {
    fn id(&mut self) -> String {
        self.next_id += 1;
        // UUID shape, like Vaultwarden ids.
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
        // One login in thirteen keeps an old habit (weak,
        // reused): enough to show the audit. Without an extra draw, so that
        // the rest of the mock vault doesn't change.
        if self.next_id % 13 == 5 {
            let habits = &self.t.habits;
            return habits[(self.next_id / 13) as usize % habits.len()].to_owned();
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
        let labels = &self.t.labels;
        let (created, modified) = self.dates();
        let mut fields = vec![
            Field::new("username", labels.username, FieldKind::Username, username),
            Field::new(
                "password",
                labels.password,
                FieldKind::Password,
                self.password(),
            ),
        ];
        if totp {
            let secret = self.totp_secret();
            fields.push(Field::new("totp", labels.totp, FieldKind::Totp, secret));
        }
        Item {
            id: self.id(),
            kind: ItemKind::Login,
            title: title.to_owned(),
            subtitle: username.to_owned(),
            urls: vec![format!("https://{domain}")],
            url_matches: Vec::new(),
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
        // Public test numbers (Stripe, payment networks): never valid.
        let t = self.t;
        t.cards
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
                    url_matches: Vec::new(),
                    folder: Some(t.cards_folder.to_owned()),
                    tags: vec![t.cards_tag.to_owned()],
                    favorite: *favorite,
                    created,
                    modified,
                    fields: vec![
                        Field::new(
                            "cardholder",
                            t.labels.cardholder,
                            FieldKind::Text,
                            t.cardholder,
                        ),
                        Field::new("brand", t.labels.brand, FieldKind::Text, *brand),
                        Field::new("number", t.labels.number, FieldKind::CardNumber, *number),
                        Field::new("expiry", t.labels.expiry, FieldKind::Expiry, *expiry),
                        Field::new(
                            "code",
                            t.labels.code,
                            FieldKind::Pin,
                            generator::pin(self.rng, cvv_len),
                        ),
                    ],
                    notes: None,
                    // As often in Bitwarden: cards ask for confirmation again.
                    reprompt: true,
                    state: crate::ItemState::Active,
                    shared: None,
                }
            })
            .collect()
    }

    fn identities(&mut self) -> Vec<Item> {
        let t = self.t;
        let labels = &t.labels;
        let (created, modified) = self.dates();
        let me = Item {
            id: self.id(),
            kind: ItemKind::Identity,
            title: t.name.to_owned(),
            subtitle: t.email.to_owned(),
            urls: Vec::new(),
            url_matches: Vec::new(),
            folder: Some(t.identity_folder.to_owned()),
            tags: Vec::new(),
            favorite: true,
            created,
            modified,
            fields: vec![
                Field::new(
                    "first_name",
                    labels.first_name,
                    FieldKind::Text,
                    t.first_name,
                ),
                Field::new("last_name", labels.last_name, FieldKind::Text, t.last_name),
                Field::new("email", labels.email, FieldKind::Email, t.email),
                Field::new("phone", labels.phone, FieldKind::Phone, t.phone),
                Field::new("birthdate", labels.birthdate, FieldKind::Date, t.birthdate),
                Field::new("address", labels.address, FieldKind::Address, t.address),
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
            title: t.passport.to_owned(),
            subtitle: t.name.to_owned(),
            urls: Vec::new(),
            url_matches: Vec::new(),
            folder: Some(t.passport_folder.to_owned()),
            tags: vec![t.passport_tag.to_owned()],
            favorite: false,
            created,
            modified,
            fields: vec![
                Field::new(
                    "number",
                    labels.number,
                    FieldKind::Concealed,
                    t.passport_number,
                ),
                Field::new("issued", labels.issued, FieldKind::Date, t.passport_issued),
                Field::new(
                    "expires",
                    labels.expires,
                    FieldKind::Date,
                    t.passport_expires,
                ),
                Field::new(
                    "authority",
                    labels.authority,
                    FieldKind::Text,
                    t.passport_authority,
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
        let t = self.t;
        let mut notes = t
            .notes
            .iter()
            .map(|(title, body, folder, favorite)| {
                let (created, modified) = self.dates();
                Item {
                    id: self.id(),
                    kind: ItemKind::SecureNote,
                    title: (*title).to_owned(),
                    // Never an excerpt of the content: the note is secret, and the
                    // subtitle is displayed and indexed in clear.
                    subtitle: t.secure_note.to_owned(),
                    urls: Vec::new(),
                    url_matches: Vec::new(),
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
        // The Wi-Fi follows Verrou's template: predefined fields and QR code.
        if let Some(wifi) = notes.first_mut() {
            use crate::template::{MARKER, Template, WIFI_PASSWORD, WIFI_SECURITY, WIFI_SSID};
            Template::Wifi.singular().clone_into(&mut wifi.subtitle);
            wifi.fields = vec![
                Field::new("custom-0", WIFI_SSID, FieldKind::Text, t.wifi_ssid),
                Field::new(
                    "custom-1",
                    WIFI_PASSWORD,
                    FieldKind::Concealed,
                    t.wifi_password,
                ),
                Field::new("custom-2", WIFI_SECURITY, FieldKind::Text, "WPA2"),
                Field::new(MARKER, MARKER, FieldKind::Text, Template::Wifi.key()),
            ];
        }
        notes
    }

    fn ssh_key(&mut self) -> Item {
        let t = self.t;
        let (created, modified) = self.dates();
        let key: [u8; 32] = self.rng.r#gen();
        let public = format!(
            "ssh-ed25519 {} {}",
            data_encoding::BASE64
                .encode(&[&[0, 0, 0, 11][..], b"ssh-ed25519", &[0, 0, 0, 32], &key].concat()),
            t.ssh_user
        );
        Item {
            id: self.id(),
            kind: ItemKind::SshKey,
            title: t.ssh_title.to_owned(),
            subtitle: t.ssh_fingerprint.to_owned(),
            urls: Vec::new(),
            url_matches: Vec::new(),
            folder: Some(t.ssh_folder.to_owned()),
            tags: vec!["infra".to_owned()],
            favorite: false,
            created,
            modified,
            fields: vec![
                Field::new(
                    "public_key",
                    t.labels.public_key,
                    FieldKind::Multiline,
                    public,
                ),
                Field::new(
                    "private_key",
                    t.labels.private_key,
                    FieldKind::Concealed,
                    t.ssh_private,
                ),
            ],
            notes: None,
            reprompt: false,
            state: crate::ItemState::Active,
            shared: None,
        }
    }

    fn filler(&mut self) -> Item {
        let t = self.t;
        let (title, domain, _, _, _, _) = t.services[self.rng.gen_range(0..t.services.len())];
        let first = t.first_names[self.rng.gen_range(0..t.first_names.len())];
        let last = t.last_names[self.rng.gen_range(0..t.last_names.len())];
        let folder = t.folders[self.rng.gen_range(0..t.folders.len())];
        let tag = t.tags[self.rng.gen_range(0..t.tags.len())];
        let username = format!(
            "{first}.{last}{}@{}",
            self.rng.gen_range(1..999),
            t.mail_domain
        );
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

/// Mock passkeys ("Passkeys" filter, screenshots): on a few
/// logins of the mock vault, by title. Their key is not a real
/// key: they are not used for signing.
pub fn passkeys(items: &[Item], language: MockLanguage) -> Vec<crate::Passkey> {
    let t = language.texts();
    let sites: [(&str, &str, &str); 3] = [
        ("GitHub", "github.com", t.dev_username),
        ("Google", "accounts.google.com", t.email),
        ("Apple ID", "apple.com", t.email),
    ];
    sites
        .iter()
        .enumerate()
        .filter_map(|(n, (title, rp_id, user))| {
            let item = items.iter().find(|i| i.title == *title)?;
            Some(crate::Passkey {
                item: item.id.clone(),
                credential_id: format!("00000000-0000-4000-8000-00000000000{n}"),
                rp_id: (*rp_id).to_owned(),
                rp_name: Some((*title).to_owned()),
                user_handle: None,
                user_name: Some((*user).to_owned()),
                user_display_name: Some(t.name.to_owned()),
                counter: 0,
                discoverable: true,
                created: NOW - 40 * DAY,
                key: SecretString::new(t.fake_key),
            })
        })
        .collect()
}

/// Excerpt of the passkeys directory (passkeys.2fa.directory, format
/// `v1/supported.json`) for the mock vault's sites: the "Passkey
/// possible" audit of the demo and screenshots, without network.
pub const PASSKEY_DIRECTORY: &str = r#"{
  "github.com": {"mfa": "allowed", "passwordless": "allowed",
    "documentation": "https://docs.github.com/en/authentication/authenticating-with-a-passkey/about-passkeys"},
  "mail.google.com": {"mfa": "allowed", "passwordless": "allowed",
    "documentation": "https://safety.google/authentication/passkey/"},
  "appleid.apple.com": {"mfa": "allowed", "passwordless": "allowed",
    "documentation": "https://support.apple.com/en-us/HT204915",
    "notes": "Passwordless authentication only works on Apple devices."},
  "amazon.com": {"passwordless": "allowed",
    "documentation": "https://www.amazon.com/gp/help/customer/display.html?nodeId=TPphmhSWBgcI9Ak87p"},
  "amazon.fr": {"passwordless": "allowed",
    "documentation": "https://www.amazon.com/gp/help/customer/display.html?nodeId=TPphmhSWBgcI9Ak87p",
    "notes": "Passkeys must be activated individually on different regional Amazon sites, such as UK and DE."},
  "amazon.de": {"passwordless": "allowed",
    "documentation": "https://www.amazon.com/gp/help/customer/display.html?nodeId=TPphmhSWBgcI9Ak87p"},
  "amazon.es": {"passwordless": "allowed",
    "documentation": "https://www.amazon.com/gp/help/customer/display.html?nodeId=TPphmhSWBgcI9Ak87p"},
  "amazon.it": {"passwordless": "allowed",
    "documentation": "https://www.amazon.com/gp/help/customer/display.html?nodeId=TPphmhSWBgcI9Ak87p"},
  "booking.com": {"passwordless": "allowed"},
  "notion.so": {"passwordless": "allowed", "documentation": "https://www.notion.com/help/passkeys"},
  "discord.com": {"passwordless": "allowed",
    "documentation": "https://support.discord.com/hc/articles/25966860846231"},
  "npmjs.com": {"mfa": "allowed",
    "documentation": "https://docs.npmjs.com/configuring-two-factor-authentication"},
  "vercel.com": {"passwordless": "allowed"},
  "uber.com": {"passwordless": "allowed"},
  "facebook.com": {"passwordless": "allowed", "mfa": "allowed",
    "documentation": "https://www.facebook.com/help/1181045243159511"}
}"#;

#[cfg(test)]
mod tests {
    use super::*;

    const LANGUAGES: [MockLanguage; 5] = [
        MockLanguage::En,
        MockLanguage::Fr,
        MockLanguage::De,
        MockLanguage::Es,
        MockLanguage::It,
    ];

    #[test]
    fn generation_is_deterministic() {
        for language in LANGUAGES {
            let a = vault_items(200, 42, language);
            let b = vault_items(200, 42, language);
            assert_eq!(a, b);
            assert_eq!(a.len(), 200);
        }
    }

    #[test]
    fn every_kind_is_represented() {
        for language in LANGUAGES {
            let items = vault_items(0, 1, language);
            for kind in ItemKind::ALL {
                assert!(items.iter().any(|i| i.kind == kind), "{kind:?} missing");
            }
        }
    }

    #[test]
    fn ids_are_unique() {
        let items = vault_items(5_000, 3, MockLanguage::En);
        let mut ids: Vec<_> = items.iter().map(|i| i.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), items.len());
    }

    /// Only the words change: same items, kinds, ids, secrets, dates,
    /// favorites and 2FA, item by item, in every language.
    #[test]
    fn all_languages_have_the_same_shape() {
        let en = vault_items(300, 42, MockLanguage::En);
        let en_passkeys = passkeys(&en, MockLanguage::En).len();
        for language in LANGUAGES {
            let t = language.texts();
            assert_eq!(EN.services.len(), t.services.len(), "{language:?}");
            for (a, b) in EN.services.iter().zip(t.services) {
                assert_eq!((a.4, a.5), (b.4, b.5), "{} / {}", a.0, b.0);
                assert_eq!(a.3.len(), b.3.len(), "{} / {}", a.0, b.0);
                assert_eq!(a.3.contains(&"dev"), b.3.contains(&"dev"), "{}", b.0);
                // Same folder pattern: the folder at the same position.
                let folder = |texts: &Texts, f: &str| texts.folders.iter().position(|x| *x == f);
                assert!(folder(t, b.2).is_some(), "{language:?}: folder {}", b.2);
                assert_eq!(folder(&EN, a.2), folder(t, b.2), "{} / {}", a.0, b.0);
            }
            assert_eq!(EN.first_names.len(), t.first_names.len());
            assert_eq!(EN.last_names.len(), t.last_names.len());
            assert_eq!(EN.folders.len(), t.folders.len());
            assert_eq!(EN.tags.len(), t.tags.len());
            assert_eq!(EN.duplicates.len(), t.duplicates.len());
            for (a, b) in EN.duplicates.iter().zip(t.duplicates) {
                assert_eq!(
                    (a.1.len(), a.2.is_empty(), a.4, a.5.is_some()),
                    (b.1.len(), b.2.is_empty(), b.4, b.5.is_some()),
                    "{} / {}",
                    a.0,
                    b.0
                );
            }
            for note in &t.notes {
                assert!(t.folders.contains(&note.2), "{language:?}: {}", note.2);
            }
            let other = vault_items(300, 42, language);
            assert_eq!(en.len(), other.len());
            for (a, b) in en.iter().zip(&other) {
                assert_eq!(a.id, b.id);
                assert_eq!(a.kind, b.kind);
                assert_eq!((a.favorite, a.reprompt), (b.favorite, b.reprompt));
                assert_eq!((a.created, a.modified), (b.created, b.modified));
                assert_eq!(a.shared.is_some(), b.shared.is_some());
                let ids = |i: &Item| i.fields.iter().map(|f| f.id.clone()).collect::<Vec<_>>();
                assert_eq!(ids(a), ids(b), "{} / {}", a.title, b.title);
                if let Some(totp) = a.field("totp") {
                    assert_eq!(totp.value, b.field("totp").unwrap().value);
                }
            }
            assert_eq!(
                en_passkeys,
                passkeys(&other, language).len(),
                "{language:?}"
            );
        }
    }

    #[test]
    fn english_vault_uses_the_core_labels() {
        let items = vault_items(0, 42, MockLanguage::En);
        let github = items.iter().find(|i| i.title == "GitHub").unwrap();
        assert_eq!(github.field("username").unwrap().label, "Username");
        assert_eq!(github.field("password").unwrap().label, "Password");
        assert_eq!(github.folder.as_deref(), Some("Work"));
        let wifi = items.iter().find(|i| i.title == "Home Wi-Fi").unwrap();
        assert_eq!(wifi.subtitle, "Wi-Fi Network");
        assert!(
            items.iter().all(
                |i| !i.title.contains("Mot de passe") && i.folder.as_deref() != Some("Travail")
            )
        );
    }

    #[test]
    fn language_codes() {
        assert_eq!(MockLanguage::from_code("fr-FR"), MockLanguage::Fr);
        assert_eq!(MockLanguage::from_code("FR"), MockLanguage::Fr);
        assert_eq!(MockLanguage::from_code("de-AT"), MockLanguage::De);
        assert_eq!(MockLanguage::from_code("de"), MockLanguage::De);
        assert_eq!(MockLanguage::from_code("es-419"), MockLanguage::Es);
        assert_eq!(MockLanguage::from_code("it-CH"), MockLanguage::It);
        assert_eq!(MockLanguage::from_code("pt-BR"), MockLanguage::En);
        assert_eq!(MockLanguage::from_code("en-GB"), MockLanguage::En);
        assert_eq!(MockLanguage::from_code(""), MockLanguage::En);
    }
}
