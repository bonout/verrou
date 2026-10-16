//! Ce qui est nouveau pour le compte depuis la dernière fois : de quoi
//! poster une notification locale (jamais un service de notification à
//! distance), sans secret.
//!
//! Sources, et ce qu'elles demandent :
//! - **la réponse de synchronisation** (cache du coffre), sans clé : les
//!   organisations confirmées et leur nom (le serveur les envoie en clair),
//!   les adhésions acceptées en attente de confirmation
//!   (`profile.organizationsNew`), les identifiants des éléments et leur
//!   organisation. Rien n'y est déchiffré ;
//! - **le serveur**, coffre ouvert (jeton d'accès) : les membres qui
//!   attendent la confirmation d'un administrateur, les demandes et
//!   accords d'accès d'urgence.
//!
//! Ce que Vaultwarden 1.37 ne montre pas : une invitation pas encore
//! acceptée (état « Invité »). La synchronisation de l'invité ne la liste
//! nulle part (`organizations` : confirmées ; `organizationsNew` :
//! acceptées et confirmées), et aucune route ne la rend à l'invité. Seul le
//! courriel la porte.
//!
//! Pour ne rien répéter, un ensemble de « déjà vus » par compte
//! (`activity.json`, identifiants seulement, jamais de nom ni de secret)
//! survit aux relances ; il est effacé à la déconnexion. La première
//! observation d'un compte ne signale rien : elle sert de point de départ
//! (les bandeaux de l'app montrent déjà l'état du moment).

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::hash::BuildHasher;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::emergency::{EmergencyOverview, EmergencyStatus};
use crate::{Error, Store};

const ACTIVITY_FILE: &str = "activity.json";
const ACTIVITY_VERSION: u32 = 1;

/// Lecture-modification-écriture du fichier : une à la fois dans le
/// processus (synchronisation au premier plan et tâche d'arrière-plan).
static FILE_LOCK: Mutex<()> = Mutex::new(());

/// Ce qui mérite une notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NoticeKind {
    /// Invitation acceptée : un administrateur doit encore confirmer le
    /// compte (sur un serveur sans courriel, c'est l'invitation elle-même).
    MembershipPending,
    /// Le compte a été confirmé : les éléments de l'organisation sont lisibles.
    MembershipConfirmed,
    /// Des membres attendent la confirmation de ce compte (administrateur).
    MembersToConfirm,
    /// De nouveaux éléments dans une organisation (pas créés par cet appareil).
    ItemsShared,
    /// Un contact d'urgence demande l'accès au coffre de ce compte.
    EmergencyRequested,
    /// Un proche a accordé l'accès à son coffre (demande approuvée, ou
    /// délai écoulé).
    EmergencyApproved,
}

/// Une notification à poster : des noms d'organisation, une adresse, des
/// nombres. Jamais un secret, un identifiant de connexion ni un titre
/// d'élément (ils sont chiffrés de toute façon).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    /// Clé stable (identifiant de la notification : une nouvelle du même
    /// sujet remplace l'ancienne).
    pub key: String,
    pub kind: NoticeKind,
    pub organization_id: Option<String>,
    pub organization: Option<String>,
    /// Éléments nouveaux, ou membres à confirmer (au total).
    pub count: u32,
    /// L'autre personne, pour l'accès d'urgence.
    pub email: Option<String>,
}

/// Une organisation vue dans la synchronisation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrganizationRef {
    pub id: String,
    pub name: String,
    /// Propriétaire : il l'a sans doute créée lui-même.
    pub owner: bool,
}

/// Ce que dit une réponse de synchronisation, sans clé.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub user_id: String,
    /// Organisations confirmées (clé reçue).
    pub confirmed: Vec<OrganizationRef>,
    /// Invitations acceptées, en attente de confirmation.
    pub pending: Vec<OrganizationRef>,
    /// Éléments : identifiant, organisation, dans la corbeille.
    pub items: Vec<(String, Option<String>, bool)>,
}

impl Snapshot {
    /// Lit la réponse brute de `/api/sync`. Les champs chiffrés ne sont pas
    /// lus ; un document illisible donne `None`.
    pub fn from_sync(json: &str) -> Option<Self> {
        #[derive(Deserialize)]
        struct Sync {
            profile: Option<Profile>,
            #[serde(default)]
            ciphers: Vec<CipherRef>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Profile {
            id: Option<String>,
            #[serde(default)]
            organizations: Vec<Membership>,
            #[serde(default)]
            organizations_new: Vec<Membership>,
        }
        #[derive(Deserialize)]
        struct Membership {
            id: Option<String>,
            name: Option<String>,
            status: Option<i64>,
            #[serde(rename = "type")]
            role: Option<i64>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct CipherRef {
            id: Option<String>,
            organization_id: Option<String>,
            deleted_date: Option<String>,
        }
        let sync: Sync = serde_json::from_str(json).ok()?;
        let profile = sync.profile?;
        let organization = |m: Membership| {
            Some(OrganizationRef {
                id: m.id?,
                name: m.name.unwrap_or_else(|| "Organisation".to_owned()),
                owner: m.role == Some(0),
            })
        };
        let confirmed: Vec<OrganizationRef> = profile
            .organizations
            .into_iter()
            .filter(|m| m.status.is_none_or(|s| s == 2))
            .filter_map(organization)
            .collect();
        let pending = profile
            .organizations_new
            .into_iter()
            .filter(|m| m.status == Some(1))
            .filter_map(organization)
            .collect();
        Some(Self {
            user_id: profile.id?,
            confirmed,
            pending,
            items: sync
                .ciphers
                .into_iter()
                .filter_map(|c| Some((c.id?, c.organization_id, c.deleted_date.is_some())))
                .collect(),
        })
    }
}

/// Ce que seul le serveur sait (coffre ouvert). `None` : pas demandé, ou
/// pas joignable ; ce qui avait déjà été vu de cette catégorie est gardé.
#[derive(Clone, Debug, Default)]
pub struct Remote {
    /// Membres à confirmer : (organisation, nom, identifiant d'adhésion).
    pub to_confirm: Option<Vec<(String, String, String)>>,
    /// Accès d'urgence (les deux côtés).
    pub emergency: Option<EmergencyOverview>,
}

/// Le fichier des déjà-vus.
#[derive(Serialize, Deserialize)]
struct SeenFile {
    version: u32,
    user_id: String,
    seen: BTreeSet<String>,
}

const ORG: &str = "org:";
const PENDING: &str = "pending:";
const ITEM: &str = "item:";
const CONFIRM: &str = "confirm:";
const EMERGENCY_REQUEST: &str = "ea-request:";
const EMERGENCY_APPROVED: &str = "ea-approved:";

/// Compare l'état observé aux déjà-vus du compte, enregistre le nouvel
/// état, et rend ce qui est nouveau. `own` : éléments créés par cet
/// appareil (pas une nouvelle pour lui). `notify` faux : tout est marqué vu
/// sans rien signaler (juste après une écriture locale, par exemple).
///
/// Ne fait rien pour une session invitée (extension de remplissage) : seul
/// l'app tient ce fichier.
pub fn observe<S: BuildHasher>(
    store: &Store,
    snapshot: &Snapshot,
    remote: &Remote,
    own: &HashSet<String, S>,
    notify: bool,
) -> Result<Vec<Notice>, Error> {
    if store.is_guest() {
        return Ok(Vec::new());
    }
    let _guard = FILE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let previous = load(store)?.filter(|f| f.user_id == snapshot.user_id);
    let first = previous.is_none();
    let seen = previous.map(|f| f.seen).unwrap_or_default();
    let (notices, current) = diff(&seen, snapshot, remote, own);
    save(
        store,
        &SeenFile {
            version: ACTIVITY_VERSION,
            user_id: snapshot.user_id.clone(),
            seen: current,
        },
    )?;
    Ok(if notify && !first {
        notices
    } else {
        Vec::new()
    })
}

/// Le cœur de `observe`, sans fichier : les nouvelles, et le nouvel
/// ensemble des déjà-vus.
fn diff<S: BuildHasher>(
    seen: &BTreeSet<String>,
    snapshot: &Snapshot,
    remote: &Remote,
    own: &HashSet<String, S>,
) -> (Vec<Notice>, BTreeSet<String>) {
    let mut diff = Diff {
        seen,
        current: BTreeSet::new(),
        notices: Vec::new(),
    };
    let just_confirmed = diff.memberships(snapshot);
    diff.items(snapshot, own, &just_confirmed);
    match &remote.to_confirm {
        Some(members) => diff.confirmations(members),
        None => diff.carry(CONFIRM),
    }
    if let Some(overview) = &remote.emergency {
        diff.emergency(overview);
    } else {
        diff.carry(EMERGENCY_REQUEST);
        diff.carry(EMERGENCY_APPROVED);
    }
    (diff.notices, diff.current)
}

struct Diff<'a> {
    seen: &'a BTreeSet<String>,
    current: BTreeSet<String>,
    notices: Vec<Notice>,
}

impl Diff<'_> {
    /// Retient la clé ; rend vrai si elle n'avait jamais été vue.
    fn note(&mut self, key: String) -> bool {
        let new = !self.seen.contains(&key);
        self.current.insert(key);
        new
    }

    fn push(&mut self, key: String, kind: NoticeKind, organization: Option<&OrganizationRef>) {
        self.notices.push(Notice {
            key,
            kind,
            organization_id: organization.map(|o| o.id.clone()),
            organization: organization.map(|o| o.name.clone()),
            count: 0,
            email: None,
        });
    }

    /// Garde les déjà-vus d'une catégorie qui n'a pas été observée cette fois.
    fn carry(&mut self, prefix: &str) {
        self.current
            .extend(self.seen.iter().filter(|k| k.starts_with(prefix)).cloned());
    }

    /// Adhésions confirmées et en attente ; rend les organisations tout
    /// juste confirmées (leurs éléments ne font pas une seconde nouvelle).
    fn memberships(&mut self, snapshot: &Snapshot) -> HashSet<String> {
        let mut just_confirmed = HashSet::new();
        for org in &snapshot.confirmed {
            // Une organisation dont le compte est propriétaire : il l'a créée.
            if self.note(format!("{ORG}{}", org.id)) && !org.owner {
                just_confirmed.insert(org.id.clone());
                let key = format!("confirmed-{}", org.id);
                self.push(key, NoticeKind::MembershipConfirmed, Some(org));
            }
        }
        for org in &snapshot.pending {
            if self.note(format!("{PENDING}{}", org.id)) {
                let key = format!("pending-{}", org.id);
                self.push(key, NoticeKind::MembershipPending, Some(org));
            }
        }
        just_confirmed
    }

    /// Nouveaux éléments des organisations, comptés par organisation.
    fn items<S: BuildHasher>(
        &mut self,
        snapshot: &Snapshot,
        own: &HashSet<String, S>,
        just_confirmed: &HashSet<String>,
    ) {
        let organizations: BTreeMap<&str, &OrganizationRef> = snapshot
            .confirmed
            .iter()
            .map(|o| (o.id.as_str(), o))
            .collect();
        let mut shared: BTreeMap<&str, u32> = BTreeMap::new();
        for (id, organization, trashed) in &snapshot.items {
            if self.note(format!("{ITEM}{id}"))
                && !own.contains(id)
                && !trashed
                && let Some(org) = organization.as_deref()
                && organizations.contains_key(org)
                && !just_confirmed.contains(org)
            {
                *shared.entry(org).or_default() += 1;
            }
        }
        for (org, count) in shared {
            self.push(
                format!("items-{org}"),
                NoticeKind::ItemsShared,
                organizations.get(org).copied(),
            );
            if let Some(notice) = self.notices.last_mut() {
                notice.count = count;
            }
        }
    }

    /// Membres à confirmer : une nouvelle par organisation où il en arrive,
    /// avec le total qui attend.
    fn confirmations(&mut self, members: &[(String, String, String)]) {
        let mut fresh: BTreeMap<&str, &str> = BTreeMap::new();
        let mut totals: BTreeMap<&str, u32> = BTreeMap::new();
        for (org, name, member) in members {
            *totals.entry(org).or_default() += 1;
            if self.note(format!("{CONFIRM}{org}:{member}")) {
                fresh.entry(org).or_insert(name);
            }
        }
        for (org, name) in fresh {
            let organization = OrganizationRef {
                id: org.to_owned(),
                name: name.to_owned(),
                owner: false,
            };
            self.push(
                format!("confirm-{org}"),
                NoticeKind::MembersToConfirm,
                Some(&organization),
            );
            if let Some(notice) = self.notices.last_mut() {
                notice.count = totals.get(org).copied().unwrap_or(1);
            }
        }
    }

    /// Demandes d'accès d'urgence (je suis le concédant) et accès accordés
    /// (je suis le contact).
    fn emergency(&mut self, overview: &EmergencyOverview) {
        let wanted = [
            (
                &overview.trusted,
                EmergencyStatus::RecoveryInitiated,
                EMERGENCY_REQUEST,
                NoticeKind::EmergencyRequested,
                "emergency-request-",
            ),
            (
                &overview.granted,
                EmergencyStatus::RecoveryApproved,
                EMERGENCY_APPROVED,
                NoticeKind::EmergencyApproved,
                "emergency-approved-",
            ),
        ];
        for (list, status, prefix, kind, key) in wanted {
            for access in list.iter().filter(|a| a.status == status) {
                if self.note(format!("{prefix}{}", access.id)) {
                    self.push(format!("{key}{}", access.id), kind, None);
                    if let Some(notice) = self.notices.last_mut() {
                        notice.email.clone_from(&access.email);
                    }
                }
            }
        }
    }
}

fn load(store: &Store) -> Result<Option<SeenFile>, Error> {
    let path = store.dir().join(ACTIVITY_FILE);
    let data = match std::fs::read(&path) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::storage(e)),
    };
    // Un fichier illisible ou d'un autre format repart de zéro.
    Ok(serde_json::from_slice::<SeenFile>(&data)
        .ok()
        .filter(|f| f.version == ACTIVITY_VERSION))
}

fn save(store: &Store, file: &SeenFile) -> Result<(), Error> {
    let data = serde_json::to_vec(file).map_err(Error::storage)?;
    store.write_private(ACTIVITY_FILE, &data)
}

/// Marque comme vus des éléments que cet appareil vient de créer dans une
/// organisation : ils ne seront pas annoncés comme partagés par un autre.
pub fn acknowledge_items(store: &Store, user_id: &str, ids: &[String]) -> Result<(), Error> {
    if store.is_guest() || ids.is_empty() {
        return Ok(());
    }
    let _guard = FILE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Pas encore de point de départ : la première observation les absorbera.
    let Some(mut file) = load(store)?.filter(|f| f.user_id == user_id) else {
        return Ok(());
    };
    file.seen.extend(ids.iter().map(|id| format!("{ITEM}{id}")));
    save(store, &file)
}

/// Efface les déjà-vus (déconnexion).
pub fn forget(store: &Store) -> Result<(), Error> {
    if store.is_guest() {
        return Ok(());
    }
    match std::fs::remove_file(store.dir().join(ACTIVITY_FILE)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::storage(e)),
    }
}

/// Coffre verrouillé : ce que le cache seul permet de dire, sans clé ni
/// réseau (le jeton de renouvellement est chiffré par la clé de
/// l'utilisateur). Utile quand le cache a été rafraîchi sans que l'app
/// l'examine (extension de remplissage, app interrompue).
pub fn observe_cache(store: &Store) -> Result<Vec<Notice>, Error> {
    let Some(account) = store.load_account()? else {
        return Ok(Vec::new());
    };
    let Some(snapshot) = account.sync.as_deref().and_then(Snapshot::from_sync) else {
        return Ok(Vec::new());
    };
    observe(store, &snapshot, &Remote::default(), &HashSet::new(), true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emergency::{EmergencyAccess, EmergencyKind};

    fn sync(orgs: &str, new: &str, ciphers: &str) -> Snapshot {
        Snapshot::from_sync(&format!(
            r#"{{"profile":{{"id":"moi","organizations":[{orgs}],"organizationsNew":[{new}]}},
                "ciphers":[{ciphers}]}}"#
        ))
        .unwrap()
    }

    fn kinds(notices: &[Notice]) -> Vec<NoticeKind> {
        notices.iter().map(|n| n.kind).collect()
    }

    #[test]
    fn the_sync_is_read_without_any_key() {
        let snapshot = sync(
            r#"{"id":"o1","name":"Famille","status":2,"type":2,"key":"4.chiffré"}"#,
            r#"{"id":"o2","name":"Club","status":1,"type":2}"#,
            r#"{"id":"c1","organizationId":"o1","name":"2.chiffré"},{"id":"c2","organizationId":null,"deletedDate":"2026-01-01"}"#,
        );
        assert_eq!(snapshot.user_id, "moi");
        assert_eq!(snapshot.confirmed[0].name, "Famille");
        assert!(!snapshot.confirmed[0].owner);
        assert_eq!(snapshot.pending[0].id, "o2");
        assert_eq!(
            snapshot.items,
            [
                ("c1".to_owned(), Some("o1".to_owned()), false),
                ("c2".to_owned(), None, true)
            ]
        );
        assert!(Snapshot::from_sync("pas du json").is_none());
    }

    #[test]
    fn invitation_then_confirmation_then_new_items() {
        let empty = BTreeSet::new();
        let own = HashSet::new();
        let remote = Remote::default();
        // Invitation acceptée.
        let pending = sync(
            "",
            r#"{"id":"o1","name":"Famille","status":1,"type":2}"#,
            "",
        );
        let (notices, seen) = diff(&empty, &pending, &remote, &own);
        assert_eq!(kinds(&notices), [NoticeKind::MembershipPending]);
        assert_eq!(notices[0].organization.as_deref(), Some("Famille"));
        // Rien de neuf : rien à dire.
        let (again, seen) = diff(&seen, &pending, &remote, &own);
        assert_eq!(again, [] as [Notice; 0]);
        // Confirmée, avec deux éléments : une seule nouvelle.
        let confirmed = sync(
            r#"{"id":"o1","name":"Famille","status":2,"type":2}"#,
            r#"{"id":"o1","name":"Famille","status":2,"type":2}"#,
            r#"{"id":"c1","organizationId":"o1"},{"id":"c2","organizationId":"o1"}"#,
        );
        let (notices, seen) = diff(&seen, &confirmed, &remote, &own);
        assert_eq!(kinds(&notices), [NoticeKind::MembershipConfirmed]);
        // Deux nouveaux éléments, dont un créé ici, et un dans la corbeille.
        let more = sync(
            r#"{"id":"o1","name":"Famille","status":2,"type":2}"#,
            "",
            r#"{"id":"c1","organizationId":"o1"},{"id":"c2","organizationId":"o1"},
               {"id":"c3","organizationId":"o1"},{"id":"c4","organizationId":"o1"},
               {"id":"c5","organizationId":"o1"},{"id":"c6","organizationId":"o1","deletedDate":"x"},
               {"id":"c7","organizationId":null}"#,
        );
        let own: HashSet<String> = ["c5".to_owned()].into();
        let (notices, _) = diff(&seen, &more, &remote, &own);
        assert_eq!(kinds(&notices), [NoticeKind::ItemsShared]);
        assert_eq!(notices[0].count, 2, "c3 et c4");
    }

    #[test]
    fn an_organization_created_here_is_not_news() {
        let owned = sync(r#"{"id":"o1","name":"À moi","status":2,"type":0}"#, "", "");
        let (notices, _) = diff(
            &BTreeSet::new(),
            &owned,
            &Remote::default(),
            &HashSet::new(),
        );
        assert_eq!(notices, [] as [Notice; 0]);
    }

    #[test]
    fn members_to_confirm_count_and_carry_over() {
        let snapshot = sync(
            r#"{"id":"o1","name":"Famille","status":2,"type":0}"#,
            "",
            "",
        );
        let one = Remote {
            to_confirm: Some(vec![("o1".into(), "Famille".into(), "m1".into())]),
            emergency: None,
        };
        let (notices, seen) = diff(&BTreeSet::new(), &snapshot, &one, &HashSet::new());
        assert_eq!(kinds(&notices), [NoticeKind::MembersToConfirm]);
        assert_eq!(notices[0].count, 1);
        // Hors ligne : le déjà-vu reste, rien n'est répété au retour.
        let (_, seen) = diff(&seen, &snapshot, &Remote::default(), &HashSet::new());
        let (notices, seen) = diff(&seen, &snapshot, &one, &HashSet::new());
        assert_eq!(notices, [] as [Notice; 0]);
        // Un second membre : la nouvelle dit le total.
        let two = Remote {
            to_confirm: Some(vec![
                ("o1".into(), "Famille".into(), "m1".into()),
                ("o1".into(), "Famille".into(), "m2".into()),
            ]),
            emergency: None,
        };
        let (notices, _) = diff(&seen, &snapshot, &two, &HashSet::new());
        assert_eq!(notices[0].count, 2);
    }

    #[test]
    fn emergency_requests_and_approvals() {
        let access = |id: &str, status| EmergencyAccess {
            id: id.to_owned(),
            user_id: None,
            name: None,
            email: Some("lea@exemple.fr".to_owned()),
            kind: EmergencyKind::View,
            status,
            wait_time_days: 7,
        };
        let remote = Remote {
            to_confirm: None,
            emergency: Some(EmergencyOverview {
                trusted: vec![
                    access("e1", EmergencyStatus::RecoveryInitiated),
                    access("e2", EmergencyStatus::Confirmed),
                ],
                granted: vec![access("e3", EmergencyStatus::RecoveryApproved)],
            }),
        };
        let (notices, seen) = diff(
            &BTreeSet::new(),
            &Snapshot::default(),
            &remote,
            &HashSet::new(),
        );
        assert_eq!(
            kinds(&notices),
            [
                NoticeKind::EmergencyRequested,
                NoticeKind::EmergencyApproved
            ]
        );
        assert_eq!(notices[0].email.as_deref(), Some("lea@exemple.fr"));
        let (notices, _) = diff(&seen, &Snapshot::default(), &remote, &HashSet::new());
        assert_eq!(notices, [] as [Notice; 0]);
    }

    #[test]
    fn the_first_observation_is_silent_and_survives_relaunches() {
        let dir = std::env::temp_dir().join(format!("verrou-activity-{}", uuid::Uuid::new_v4()));
        let store = Store::new(&dir);
        let pending = sync(
            "",
            r#"{"id":"o1","name":"Famille","status":1,"type":2}"#,
            "",
        );
        let none = HashSet::new();
        assert_eq!(
            observe(
                &store,
                &Snapshot {
                    pending: vec![],
                    ..pending.clone()
                },
                &Remote::default(),
                &none,
                true
            )
            .unwrap(),
            [] as [Notice; 0]
        );
        let notices =
            observe(&Store::new(&dir), &pending, &Remote::default(), &none, true).unwrap();
        assert_eq!(kinds(&notices), [NoticeKind::MembershipPending]);
        assert_eq!(
            observe(&Store::new(&dir), &pending, &Remote::default(), &none, true).unwrap(),
            [] as [Notice; 0]
        );
        // Le fichier ne contient que des identifiants.
        let text = std::fs::read_to_string(dir.join(ACTIVITY_FILE)).unwrap();
        assert!(!text.contains("Famille"));
        // L'extension (invitée) n'y touche pas.
        assert_eq!(
            observe(
                &Store::new(&dir).guest(),
                &sync("", "", ""),
                &Remote::default(),
                &none,
                true
            )
            .unwrap(),
            [] as [Notice; 0]
        );
        assert!(
            std::fs::read_to_string(dir.join(ACTIVITY_FILE))
                .unwrap()
                .contains("pending:o1")
        );
        forget(&store).unwrap();
        assert!(!dir.join(ACTIVITY_FILE).exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
