//! Mock vault, deterministic, for development, tests, screenshots
//! and performance measurements.
//!
//! Two languages, the app's: an English-speaking user's vault (the default)
//! and a French-speaking user's. Both have the same items, in the same order,
//! of the same kinds, with the same ids and secrets for a given seed: only
//! the words change.
//!
//! No real data: addresses are `example.com` / `@exemple.fr`,
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
}

impl MockLanguage {
    /// From a language code (`fr`, `fr-FR`, `en-US`…): French for `fr…`,
    /// English otherwise.
    pub fn from_code(code: &str) -> Self {
        if code.trim().to_ascii_lowercase().starts_with("fr") {
            Self::Fr
        } else {
            Self::En
        }
    }

    fn texts(self) -> &'static Texts {
        match self {
            Self::En => &EN,
            Self::Fr => &FR,
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
        username: "Identifiant",
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

    const LANGUAGES: [MockLanguage; 2] = [MockLanguage::En, MockLanguage::Fr];

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
    /// favorites and 2FA, item by item.
    #[test]
    fn both_languages_have_the_same_shape() {
        for (en, fr) in EN.services.iter().zip(FR.services) {
            assert_eq!((en.4, en.5), (fr.4, fr.5), "{} / {}", en.0, fr.0);
            assert_eq!(en.3.len(), fr.3.len(), "{} / {}", en.0, fr.0);
        }
        assert_eq!(EN.services.len(), FR.services.len());
        assert_eq!(EN.first_names.len(), FR.first_names.len());
        assert_eq!(EN.last_names.len(), FR.last_names.len());
        assert_eq!(EN.folders.len(), FR.folders.len());
        assert_eq!(EN.tags.len(), FR.tags.len());
        assert_eq!(EN.duplicates.len(), FR.duplicates.len());
        let en = vault_items(300, 42, MockLanguage::En);
        let fr = vault_items(300, 42, MockLanguage::Fr);
        assert_eq!(en.len(), fr.len());
        for (a, b) in en.iter().zip(&fr) {
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
            passkeys(&en, MockLanguage::En).len(),
            passkeys(&fr, MockLanguage::Fr).len()
        );
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
        assert_eq!(MockLanguage::from_code("en-GB"), MockLanguage::En);
        assert_eq!(MockLanguage::from_code(""), MockLanguage::En);
    }
}
