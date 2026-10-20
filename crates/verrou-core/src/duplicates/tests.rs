use super::*;
use crate::mock;
use crate::model::{Field, FieldKind};

fn login(id: &str, url: &str, username: &str, password: &str, modified: i64) -> Item {
    Item {
        id: id.to_owned(),
        kind: ItemKind::Login,
        title: id.to_owned(),
        subtitle: username.to_owned(),
        urls: if url.is_empty() {
            Vec::new()
        } else {
            vec![url.to_owned()]
        },
        folder: None,
        tags: Vec::new(),
        favorite: false,
        created: 0,
        modified,
        fields: vec![
            Field::new("username", "Identifiant", FieldKind::Username, username),
            Field::new("password", "Mot de passe", FieldKind::Password, password),
        ],
        notes: None,
        reprompt: false,
        state: ItemState::Active,
        shared: None,
    }
}

fn titled(mut item: Item, title: &str) -> Item {
    title.clone_into(&mut item.title);
    item
}

fn imported(url: &str, username: &str, password: &str) -> ImportedItem {
    ImportedItem {
        kind: ImportKind::Login,
        title: "importé".to_owned(),
        username: (!username.is_empty()).then(|| username.to_owned()),
        password: Some(SecretString::new(password)),
        urls: if url.is_empty() {
            Vec::new()
        } else {
            vec![url.to_owned()]
        },
        totp: None,
        notes: None,
        folder: None,
        favorite: false,
        card: None,
        identity: None,
        template: None,
        fields: Vec::new(),
        modified: None,
        attachments: Vec::new(),
    }
}

/// (gardé, [(élément, degré)]) de chaque groupe, pour des assertions lisibles.
type Shape<'a> = Vec<(Confidence, Vec<(&'a str, Option<Confidence>)>)>;

fn summary(groups: &[DuplicateGroup]) -> Shape<'_> {
    groups
        .iter()
        .map(|g| {
            (
                g.confidence,
                g.members
                    .iter()
                    .map(|m| (m.id.as_str(), m.confidence))
                    .collect(),
            )
        })
        .collect()
}

fn group_with<'g>(groups: &'g [DuplicateGroup], id: &str) -> &'g DuplicateGroup {
    groups
        .iter()
        .find(|g| g.members.iter().any(|m| m.id == id))
        .unwrap_or_else(|| panic!("{id} dans aucun groupe"))
}

fn ids(group: &DuplicateGroup) -> Vec<&str> {
    group.members.iter().map(|m| m.id.as_str()).collect()
}

fn level(group: &DuplicateGroup, id: &str) -> Option<Confidence> {
    group
        .members
        .iter()
        .find(|m| m.id == id)
        .unwrap()
        .confidence
}

// MARK: Import

#[test]
fn imported_logins_are_classified() {
    let vault = vec![
        login("gh", "https://github.com", "Camille", "un", 100),
        login(
            "bank",
            "https://www.banque.fr/espace",
            "camille",
            "deux",
            100,
        ),
    ];
    let mut with_totp = imported("https://github.com/login", "camille", "un");
    with_totp.totp = Some(SecretString::new("JBSWY3DPEHPK3PXP"));
    let mut old = imported("https://banque.fr", "camille", "ancien");
    old.modified = Some(50);
    let items = vec![
        imported("https://login.github.com", " CAMILLE ", "un"),
        imported("https://banque.fr", "camille", "trois"),
        with_totp,
        old,
        imported("https://forum.fr", "cam", "x"),
        imported("https://forum.fr", "cam", "x"),
        imported("https://www.forum.fr", "cam", "y"),
        imported("https://github.io", "camille", "un"),
    ];
    let result = classify(&items, &vault);
    let statuses: Vec<&Status> = result.iter().map(|c| &c.status).collect();
    assert_eq!(statuses[0], &Status::Exact(Existing::Vault("gh".into())));
    assert_eq!(
        result[0].reason.as_deref(),
        Some("même site (github.com), même identifiant, même mot de passe")
    );
    assert_eq!(
        (&result[1].status, result[1].decision),
        (
            &Status::NewPassword(Existing::Vault("bank".into())),
            Decision::Update
        )
    );
    assert_eq!(statuses[2], &Status::AddsTotp("gh".into()));
    assert_eq!(
        result[3].decision,
        Decision::Skip,
        "plus ancien que le coffre"
    );
    assert_eq!(statuses[4], &Status::New);
    assert_eq!(result[4].reason, None);
    assert_eq!(statuses[5], &Status::Exact(Existing::Import(4)));
    assert_eq!(statuses[6], &Status::NewPassword(Existing::Import(4)));
    assert_eq!(result[6].decision, Decision::Create);
    assert_eq!(statuses[7], &Status::New, "github.io n'est pas github.com");
}

#[test]
fn import_uses_the_same_signals_but_only_skips_certain_duplicates() {
    let vault = vec![titled(
        login(
            "maif",
            "https://www.maif.fr",
            "camille@exemple.fr",
            "lilas",
            100,
        ),
        "Maif",
    )];
    let mut no_site = imported("", "", "lilas");
    no_site.title = "Maif".to_owned();
    let mut no_site_other_password = imported("", "", "autre");
    no_site_other_password.title = "MAIF".to_owned();
    let items = vec![
        // Autre sous-domaine de connexion, casse et étiquette `+` : certain.
        imported(
            "http://connect.maif.fr:8080/espace-perso",
            "Camille+import@Exemple.fr",
            "lilas",
        ),
        // Même compte, nouveau mot de passe : complète le coffre.
        imported("https://maif.fr", "camille@exemple.fr", "nouveau"),
        // Titre seul, sans identifiant, même mot de passe : probable.
        no_site,
        // Titre seul, sans identifiant, autre mot de passe : à vérifier, créé.
        no_site_other_password,
        // Autre sous-domaine, même identifiant et mot de passe, le titre du
        // coffre nomme le domaine : probable, à compléter.
        imported("https://assurance.maif.fr", "camille@exemple.fr", "lilas"),
    ];
    let result = classify(&items, &vault);
    let maif = || Existing::Vault("maif".into());
    assert_eq!(result[0].status, Status::Exact(maif()));
    assert_eq!(result[0].decision, Decision::Skip);
    assert_eq!(result[1].status, Status::NewPassword(maif()));
    assert_eq!(result[1].decision, Decision::Update);
    assert_eq!(result[2].status, Status::Similar(maif()));
    assert_eq!(result[2].decision, Decision::Update);
    assert_eq!(
        result[2].reason.as_deref(),
        Some("titre « Maif » ↔ maif.fr, un identifiant manquant, même mot de passe")
    );
    assert_eq!(result[3].status, Status::New);
    assert_eq!(result[3].decision, Decision::Create);
    assert_eq!(result[4].status, Status::Similar(maif()));

    // Deux services d'un même domaine, même identifiant et mot de passe :
    // à vérifier, donc créé.
    let vault = vec![titled(
        login("nc", "https://cloud.example.net", "camille", "ldap", 1),
        "Nextcloud",
    )];
    let mut other = imported("https://vault.example.net", "camille", "ldap");
    other.title = "Vaultwarden".to_owned();
    assert_eq!(classify(&[other], &vault)[0].status, Status::New);
}

#[test]
fn logins_without_site_compare_titles() {
    let vault = vec![titled(login("routeur", "", "admin", "a", 0), "Routeur")];
    let mut item = imported("", "admin", "a");
    item.title = "routeur (maison)".to_owned();
    assert_eq!(
        classify(&[item], &vault)[0].status,
        Status::Exact(Existing::Vault("routeur".into()))
    );
}

// MARK: Coffre

#[test]
fn sites_keep_services_apart() {
    let mut trashed = login("Nextcloud", "https://cloud.example.net", "camille", "a", 0);
    trashed.state = ItemState::Trashed;
    let items = vec![
        login("Nextcloud", "https://cloud.example.net", "camille", "a", 1),
        login(
            "Vaultwarden",
            "https://vault.example.net",
            "camille",
            "b",
            2,
        ),
        trashed,
    ];
    assert_eq!(
        find_duplicates(&items),
        Vec::new(),
        "deux services, la corbeille ne compte pas"
    );
    let mut import = imported("https://cloud.example.net", "camille", "a");
    import.title = "Nextcloud".to_owned();
    assert_eq!(classify(&[import], &items[2..])[0].status, Status::New);

    // Même mot de passe sur deux sous-domaines : au plus « à vérifier ».
    let shared = vec![
        login(
            "Nextcloud",
            "https://cloud.example.net",
            "camille",
            "même",
            1,
        ),
        login(
            "Vaultwarden",
            "https://vault.example.net",
            "camille",
            "même",
            2,
        ),
    ];
    let groups = find_duplicates(&shared);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].confidence, Confidence::Review);
    assert!(!groups[0].members.iter().any(|m| m.preselected));
    assert_eq!(
        groups[0].reason,
        "même domaine (example.net), autre sous-domaine, même identifiant, même mot de passe"
    );
}

#[test]
fn duplicates_in_the_vault_suggest_the_best_item() {
    let mut with_totp = login("ancien", "https://github.com", "camille", "a", 10);
    with_totp.fields.push(Field::new(
        "totp",
        "Code",
        FieldKind::Totp,
        "JBSWY3DPEHPK3PXP",
    ));
    let items = vec![
        login("récent", "https://accounts.github.com", "Camille", "b", 20),
        with_totp,
        login("autre", "https://github.com", "dominique", "a", 30),
        login("b1", "https://banque.fr", "camille", "same", 1),
        login("b2", "https://www.banque.fr", "camille", "same", 2),
    ];
    let groups = find_duplicates(&items);
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].label, "banque.fr");
    assert_eq!(ids(&groups[0]), vec!["b2", "b1"], "le plus récent");
    assert_eq!(groups[0].confidence, Confidence::Certain);
    assert!(groups[0].same_password);
    assert!(groups[0].members[1].preselected);
    assert_eq!(groups[1].label, "github.com");
    assert_eq!(
        ids(&groups[1]),
        vec!["ancien", "récent", "autre"],
        "le code TOTP d'abord ; l'autre compte, rattaché, en dernier"
    );
    assert_eq!(groups[1].confidence, Confidence::Probable);
    assert_eq!(level(&groups[1], "récent"), Some(Confidence::Probable));
    assert_eq!(level(&groups[1], "autre"), Some(Confidence::Review));
    assert_eq!(
        groups[1].members[2].reason,
        "même site (github.com), autre identifiant, même mot de passe"
    );
    assert!(!groups[1].members.iter().any(|m| m.preselected));
    assert!(!groups[1].same_password);
}

#[test]
fn shared_copies_are_not_duplicates_of_personal_ones() {
    let shared = |id: &str, org: &str, read_only: bool| {
        let mut item = login(id, "https://banque.fr", "camille", "same", 1);
        item.shared = Some(crate::Sharing {
            organization_id: org.to_owned(),
            organization: "Famille".to_owned(),
            collections: Vec::new(),
            read_only,
            hide_passwords: false,
        });
        item
    };
    let personal = login("perso", "https://banque.fr", "camille", "same", 2);
    assert_eq!(
        find_duplicates(&[personal.clone(), shared("org-1", "org", false)]).len(),
        0
    );
    assert_eq!(
        find_duplicates(&[shared("org-1", "org", false), shared("org-2", "org", true)]).len(),
        0,
        "lecture seule : impossible à mettre à la corbeille"
    );
    assert_eq!(
        find_duplicates(&[shared("a", "org", false), shared("b", "autre", false)]).len(),
        0,
        "deux organisations"
    );
    let groups = find_duplicates(&[
        personal,
        shared("org-1", "org", false),
        shared("org-2", "org", false),
    ]);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].members.len(), 2);
}

#[test]
fn imported_variants_of_the_same_accounts_are_grouped() {
    let items = mock::duplicate_items();
    let groups = find_duplicates(&items);
    let (c, p, r) = (
        Some(Confidence::Certain),
        Some(Confidence::Probable),
        Some(Confidence::Review),
    );
    let expected: Shape = vec![
        // Certains d'abord, par site.
        (Confidence::Certain, vec![("dup-7", None), ("dup-8", c)]),
        (
            Confidence::Certain,
            vec![("dup-0", None), ("dup-1", c), ("dup-2", c), ("dup-3", p)],
        ),
        (Confidence::Certain, vec![("dup-15", None), ("dup-16", c)]),
        (Confidence::Certain, vec![("dup-100", None), ("dup-101", c)]),
        (
            Confidence::Probable,
            vec![("dup-4", None), ("dup-6", p), ("dup-5", p)],
        ),
        (Confidence::Probable, vec![("dup-13", None), ("dup-14", p)]),
        (Confidence::Review, vec![("dup-17", None), ("dup-18", r)]),
        (Confidence::Review, vec![("dup-9", None), ("dup-10", r)]),
    ];
    assert_eq!(summary(&groups), expected);
    let maif = group_with(&groups, "dup-0");
    assert_eq!(maif.label, "maif.fr");
    assert_eq!(maif.username, "camille.martin@exemple.fr");
    assert_eq!(
        maif.members[1].reason,
        "même site (maif.fr), même identifiant, même mot de passe"
    );
    assert_eq!(
        maif.members[3].reason,
        "titre « Maif » ↔ maif.fr, un identifiant manquant, même mot de passe"
    );
    // Certain : les copies cochées ; probable : suggéré seulement.
    let preselected: Vec<bool> = maif.members.iter().map(|m| m.preselected).collect();
    assert_eq!(preselected, [false, true, true, false]);
    assert!(maif.same_password && maif.mergeable);

    let google = group_with(&groups, "dup-4");
    assert_eq!(
        google.members[2].reason,
        "même site (google.com), même identifiant, autre mot de passe"
    );
    assert!(
        google.members[1]
            .reason
            .starts_with("même domaine (google.com)")
    );
    let slack = group_with(&groups, "dup-15");
    assert_eq!(
        slack.members[1].reason,
        "même app (com.tinyspeck.slackmacgap), même identifiant, même mot de passe"
    );
    let cards = group_with(&groups, "dup-100");
    assert_eq!(cards.members[1].reason, "même numéro de carte");
    assert!(!cards.mergeable);
    let netflix = group_with(&groups, "dup-9");
    assert_eq!(
        netflix.reason,
        "même site (netflix.com), autre identifiant, même mot de passe"
    );
    // Nextcloud et Vaultwarden : deux services, jamais regroupés.
    assert!(
        groups
            .iter()
            .all(|g| !g.ids().contains(&"dup-11".to_owned()))
    );
}

#[test]
fn kinds_never_mix() {
    let mut card = login("carte", "", "", "", 0);
    card.kind = ItemKind::Card;
    card.fields = vec![Field::new(
        "number",
        "Numéro",
        FieldKind::CardNumber,
        "4242",
    )];
    let items = vec![titled(login("a", "", "x", "4242", 0), "carte"), card];
    assert_eq!(find_duplicates(&items), Vec::new());
}

#[test]
fn passkeys_and_attachments_decide_what_is_kept() {
    let items = vec![
        login("récent", "https://github.com", "camille", "a", 20),
        login("passkey", "", "camille", "a", 10),
        login("pièce", "https://github.com/login", "camille", "a", 5),
    ];
    let mut extras = HashMap::new();
    extras.insert(
        "passkey".to_owned(),
        ItemExtras {
            passkey_sites: vec!["github.com".to_owned()],
            attachments: 0,
        },
    );
    extras.insert(
        "pièce".to_owned(),
        ItemExtras {
            passkey_sites: Vec::new(),
            attachments: 1,
        },
    );
    // Sans les passkeys, l'élément sans adresse ni titre parlant reste seul.
    assert_eq!(ids(&find_duplicates(&items)[0]), vec!["récent", "pièce"]);
    // Le site de la passkey le rapproche, et ce qui ne se fusionne pas
    // décide de l'élément gardé.
    let groups = find_duplicates_with(&items, &extras);
    assert_eq!(ids(&groups[0]), vec!["passkey", "pièce", "récent"]);
    assert_eq!(groups[0].confidence, Confidence::Certain);
}

#[test]
fn group_keys_ignore_order() {
    let a = group_key(&["x".to_owned(), "y".to_owned()]);
    assert_eq!(a, group_key(&["y".to_owned(), "x".to_owned()]));
    assert_ne!(a, group_key(&["x".to_owned(), "z".to_owned()]));
    assert_eq!(a.len(), 24);
}

#[test]
fn large_buckets_still_find_every_kind_of_duplicate() {
    // Un domaine partagé par des centaines de comptes : le paquet se
    // subdivise sans rien perdre.
    let mut items: Vec<Item> = (0..300)
        .map(|n| {
            login(
                &format!("u{n}"),
                "https://exemple.fr",
                &format!("user{n}"),
                &format!("pw{n}"),
                n,
            )
        })
        .collect();
    items.push(login(
        "same-user",
        "https://exemple.fr",
        "user7",
        "autre",
        1,
    ));
    items.push(login("same-pw", "https://exemple.fr", "quelquun", "pw9", 1));
    items.push(login("anonyme", "https://exemple.fr", "", "pw11", 1));
    let groups = find_duplicates(&items);
    assert_eq!(groups.len(), 3);
    assert_eq!(
        group_with(&groups, "same-user").confidence,
        Confidence::Probable
    );
    assert!(
        group_with(&groups, "same-pw")
            .ids()
            .contains(&"u9".to_owned())
    );
    assert_eq!(
        group_with(&groups, "anonyme").confidence,
        Confidence::Probable,
        "sans identifiant, même mot de passe"
    );
}

#[test]
fn an_item_without_username_joins_only_an_unambiguous_account() {
    let alone = || login("sans", "https://amazon.fr", "", "x", 1);
    let one = vec![
        login("camille", "https://amazon.fr", "camille", "a", 2),
        alone(),
    ];
    let groups = find_duplicates(&one);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].confidence, Confidence::Review);
    assert_eq!(
        groups[0].members[1].reason,
        "même site (amazon.fr), un identifiant manquant, autre mot de passe"
    );
    // Deux comptes sur le site : lequel ? Aucun groupe.
    let two = vec![
        login("camille", "https://amazon.fr", "camille", "a", 2),
        login("dominique", "https://amazon.fr", "dominique", "b", 3),
        alone(),
    ];
    assert_eq!(find_duplicates(&two), Vec::new());
}
