//! Membres d'une organisation : inviter, confirmer, gérer les rôles et les
//! accès aux collections, sans jeton d'administration du serveur.
//!
//! Le parcours d'un nouveau membre, sur Vaultwarden 1.37 :
//! 1. un propriétaire ou un administrateur l'**invite** par son adresse
//!    (`POST /api/organizations/{org}/users/invite`) ; si le serveur envoie
//!    des courriels, le lien d'invitation porte un jeton signé par le
//!    serveur, sinon le serveur garde une invitation à son nom ;
//! 2. la personne crée son compte (voir `register`) ou se connecte, puis
//!    **accepte** (`…/users/{membre}/accept`, avec le jeton) ;
//! 3. un propriétaire ou un administrateur la **confirme** : la clé de
//!    l'organisation est chiffrée pour sa clé publique (RSA-OAEP-SHA1, par
//!    le SDK) et confiée au serveur, qui ne peut pas la lire.
//!
//! Comme pour l'accès d'urgence, la clé publique vient du serveur : avant de
//! confirmer, l'utilisateur compare son **empreinte** (phrase de 5 mots) avec
//! celle que le membre lit dans son compte ; à l'envoi, la clé est relue et
//! refusée si son empreinte a changé.
//!
//! Les droits sont ceux de Vaultwarden, vérifiés ici avant tout envoi pour
//! un message clair (le serveur les vérifie de toute façon) : voir la liste
//! (propriétaire, administrateur, gestionnaire avec accès à toutes les
//! collections) ; gérer (propriétaire, administrateur) ; inviter, confirmer,
//! retirer un gestionnaire, un administrateur ou un propriétaire, ou donner
//! ces rôles (propriétaire seulement).

use bitwarden_core::OrganizationId;
use bitwarden_core::key_management::SymmetricKeySlotId;
use bitwarden_crypto::{PublicKey, SpkiPublicKeyBytes, UnsignedSharedKey};
use reqwest::Method;
use serde_json::{Value, json};

use crate::emergency::key_fingerprint;
use crate::{Connection, Error, Organization};

/// Nombre d'adresses par invitation (limite du coffre web).
pub const MAX_INVITES: usize = 20;

/// Rôle d'un membre dans l'organisation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MemberRole {
    Owner,
    Admin,
    User,
    /// Gestionnaire (le rôle « personnalisé » des apps Bitwarden, que
    /// Vaultwarden traite comme un gestionnaire).
    Manager,
}

impl MemberRole {
    /// Numéro du rôle dans l'API (`type`).
    pub fn code(self) -> u8 {
        match self {
            Self::Owner => 0,
            Self::Admin => 1,
            Self::User => 2,
            Self::Manager => 3,
        }
    }

    /// `4` (personnalisé) est le gestionnaire de Vaultwarden.
    pub fn from_code(code: i64) -> Option<Self> {
        match code {
            0 => Some(Self::Owner),
            1 => Some(Self::Admin),
            2 => Some(Self::User),
            3 | 4 => Some(Self::Manager),
            _ => None,
        }
    }

    /// Propriétaires et administrateurs voient toutes les collections : le
    /// serveur ignore alors la liste envoyée.
    pub fn sees_all_collections(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    /// Rôles au-dessus de « utilisateur » : seul un propriétaire les donne,
    /// les retire, invite ou confirme ceux qui les ont.
    fn is_privileged(self) -> bool {
        self != Self::User
    }
}

/// État d'un membre.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberStatus {
    /// Accès retiré (restaurable).
    Revoked,
    /// Invitation envoyée, pas encore acceptée.
    Invited,
    /// Invitation acceptée : à confirmer (empreinte).
    Accepted,
    /// Confirmé : il a la clé de l'organisation.
    Confirmed,
}

impl MemberStatus {
    fn from_code(code: i64) -> Option<Self> {
        match code {
            // Vaultwarden décale l'état d'un membre révoqué ; l'API rend -1.
            i64::MIN..=-1 => Some(Self::Revoked),
            0 => Some(Self::Invited),
            1 => Some(Self::Accepted),
            2 => Some(Self::Confirmed),
            _ => None,
        }
    }
}

/// Accès d'un membre à une collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionAccess {
    pub id: String,
    /// Voir sans modifier.
    pub read_only: bool,
    /// Remplir sans voir les mots de passe.
    pub hide_passwords: bool,
    /// Gérer la collection (membres, droits).
    pub manage: bool,
}

impl CollectionAccess {
    fn json(&self) -> Value {
        json!({
            "id": self.id,
            "readOnly": self.read_only,
            "hidePasswords": self.hide_passwords,
            "manage": self.manage,
        })
    }
}

/// Un membre de l'organisation, tel que le serveur le décrit à un
/// administrateur.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// Identifiant de l'adhésion (pas du compte).
    pub id: String,
    /// Compte du membre.
    pub user_id: String,
    /// Nom choisi par le membre (une fois l'invitation acceptée).
    pub name: Option<String>,
    pub email: String,
    pub role: MemberRole,
    pub status: MemberStatus,
    /// Toutes les collections (propriétaire, administrateur, ou
    /// gestionnaire avec accès complet).
    pub access_all: bool,
    /// Accès donnés collection par collection (vide si `access_all`).
    pub collections: Vec<CollectionAccess>,
    /// Groupes (gardés tels quels quand on modifie le membre).
    pub groups: Vec<String>,
    /// Double authentification activée sur son compte.
    pub two_factor_enabled: bool,
    /// Le compte existe déjà (mot de passe principal choisi) ; sinon
    /// l'invité doit d'abord créer son compte.
    pub has_account: bool,
}

impl Member {
    fn parse(value: &Value) -> Option<Self> {
        let text = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        let flag = |key: &str| value.get(key).and_then(Value::as_bool).unwrap_or(false);
        let role = MemberRole::from_code(value.get("type")?.as_i64()?)?;
        let access_all = role.sees_all_collections()
            || value
                .pointer("/permissions/editAnyCollection")
                .and_then(Value::as_bool)
                .unwrap_or(false);
        let collections = value
            .get("collections")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|c| {
                let flag = |key: &str| c.get(key).and_then(Value::as_bool).unwrap_or(false);
                Some(CollectionAccess {
                    id: c.get("id")?.as_str()?.to_owned(),
                    read_only: flag("readOnly"),
                    hide_passwords: flag("hidePasswords"),
                    manage: flag("manage"),
                })
            })
            .collect();
        let groups = value
            .get("groups")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|g| g.as_str().map(str::to_owned))
            .collect();
        Some(Self {
            id: text("id")?,
            user_id: text("userId")?,
            name: text("name"),
            email: text("email")?,
            role,
            status: MemberStatus::from_code(value.get("status")?.as_i64()?)?,
            access_all,
            collections,
            groups,
            two_factor_enabled: flag("twoFactorEnabled"),
            // Absent des anciennes versions : on suppose le compte créé.
            has_account: value
                .get("hasMasterPassword")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        })
    }

    /// Nom à afficher : son nom, sinon son adresse.
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.email)
    }
}

fn parse_members(body: &Value) -> Vec<Member> {
    let mut members: Vec<Member> = body
        .get("data")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Member::parse)
        .collect();
    members.sort_by_key(|m| m.display_name().to_lowercase());
    members
}

/// Ce que le compte peut faire des membres d'une organisation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemberRights {
    /// Voir la liste des membres.
    pub view: bool,
    /// Inviter, confirmer, modifier, révoquer, retirer.
    pub manage: bool,
    /// Propriétaire : les rôles au-dessus d'« utilisateur » aussi.
    pub owner: bool,
}

impl Organization {
    /// Les droits du compte sur les membres de cette organisation.
    pub fn member_rights(&self) -> MemberRights {
        let manage = matches!(self.role, Some(MemberRole::Owner | MemberRole::Admin));
        MemberRights {
            // Gestionnaire : seulement avec l'accès à toutes les collections
            // (sinon le serveur répond 404).
            view: self.admin,
            manage,
            owner: self.role == Some(MemberRole::Owner),
        }
    }
}

/// Ce qu'on veut faire d'un membre, pour vérifier les droits avant l'envoi.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberAction {
    Invite(MemberRole),
    /// Nouveau rôle ; le rôle actuel est celui du membre.
    Edit(MemberRole),
    Reinvite,
    Confirm,
    Revoke,
    Restore,
    Remove,
}

/// Les règles de Vaultwarden, avec un message qui dit quoi faire.
pub fn check_rights(
    rights: MemberRights,
    action: MemberAction,
    member: Option<&Member>,
) -> Result<(), Error> {
    let refuse = |message: &str| Err(Error::Invalid(message.to_owned()));
    if !rights.manage {
        return refuse(
            "seuls les propriétaires et les administrateurs de l'organisation gèrent ses membres",
        );
    }
    if rights.owner {
        return Ok(());
    }
    let current = member.map(|m| m.role);
    match action {
        MemberAction::Invite(role) if role.is_privileged() => refuse(
            "seul un propriétaire peut inviter un gestionnaire, un administrateur ou un propriétaire",
        ),
        MemberAction::Edit(_) if current == Some(MemberRole::Owner) => {
            refuse("seul un propriétaire peut modifier un propriétaire")
        }
        MemberAction::Edit(role)
            if Some(role) != current
                && (role.sees_all_collections()
                    || current.is_some_and(MemberRole::sees_all_collections)) =>
        {
            refuse("seul un propriétaire peut donner ou retirer le rôle d'administrateur")
        }
        MemberAction::Confirm if current.is_some_and(MemberRole::is_privileged) => refuse(
            "seul un propriétaire peut confirmer un gestionnaire, un administrateur ou un propriétaire",
        ),
        MemberAction::Remove if current.is_some_and(MemberRole::is_privileged) => refuse(
            "seul un propriétaire peut retirer un gestionnaire, un administrateur ou un propriétaire",
        ),
        MemberAction::Revoke | MemberAction::Restore if current == Some(MemberRole::Owner) => {
            refuse("seul un propriétaire peut révoquer ou restaurer un propriétaire")
        }
        _ => Ok(()),
    }
}

/// Les adresses saisies (séparées par des virgules, points-virgules,
/// espaces ou retours à la ligne), sans doublon, en minuscules.
pub fn parse_emails(text: &str) -> Result<Vec<String>, Error> {
    let mut emails: Vec<String> = Vec::new();
    for raw in text.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
        let email = raw
            .trim()
            .trim_matches(|c| c == '<' || c == '>')
            .to_lowercase();
        if email.is_empty() {
            continue;
        }
        let valid = email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        }) && email.matches('@').count() == 1;
        if !valid {
            return Err(Error::Invalid(format!("adresse e-mail invalide : {email}")));
        }
        if !emails.contains(&email) {
            emails.push(email);
        }
    }
    if emails.is_empty() {
        return Err(Error::Invalid(
            "saisissez au moins une adresse e-mail".to_owned(),
        ));
    }
    if emails.len() > MAX_INVITES {
        return Err(Error::Invalid(format!(
            "{MAX_INVITES} adresses au plus par invitation"
        )));
    }
    Ok(emails)
}

/// Le corps de `POST /api/organizations/{org}/users/invite`.
pub fn invite_body(emails: &[String], role: MemberRole, collections: &[CollectionAccess]) -> Value {
    json!({
        "emails": emails,
        "type": role.code(),
        "collections": access_list(role, collections),
        "groups": [],
        "accessAll": role.sees_all_collections(),
        "permissions": {},
    })
}

/// Le corps de `PUT /api/organizations/{org}/users/{membre}` : le rôle et
/// les collections remplacent les précédents ; les groupes sont gardés.
pub fn edit_body(role: MemberRole, collections: &[CollectionAccess], groups: &[String]) -> Value {
    json!({
        "type": role.code(),
        "collections": access_list(role, collections),
        "groups": groups,
        "accessAll": role.sees_all_collections(),
        "permissions": {},
    })
}

fn access_list(role: MemberRole, collections: &[CollectionAccess]) -> Vec<Value> {
    if role.sees_all_collections() {
        Vec::new()
    } else {
        collections.iter().map(CollectionAccess::json).collect()
    }
}

impl Connection {
    /// L'organisation, d'après le cache (le compte doit en être membre confirmé).
    pub(crate) fn organization(&self, organization_id: &str) -> Result<Organization, Error> {
        let json = self.account.sync.as_deref().ok_or(Error::NotFound)?;
        let sync = serde_json::from_str(json)
            .map_err(|e| Error::Storage(format!("cache illisible ({e})")))?;
        self.decrypt_directory(&sync)
            .organizations
            .into_iter()
            .find(|o| o.id == organization_id)
            .ok_or_else(|| Error::Invalid("organisation inconnue".to_owned()))
    }

    /// Vérifie les droits du compte pour cette action, d'après le cache.
    fn require_rights(
        &self,
        organization_id: &str,
        action: MemberAction,
        member: Option<&Member>,
    ) -> Result<(), Error> {
        let rights = self.organization(organization_id)?.member_rights();
        check_rights(rights, action, member)
    }

    /// Les membres de l'organisation, triés par nom.
    pub async fn organization_members(
        &mut self,
        organization_id: &str,
    ) -> Result<Vec<Member>, Error> {
        if !self.organization(organization_id)?.member_rights().view {
            return Err(Error::Invalid(
                "votre rôle ne permet pas de voir les membres de cette organisation".to_owned(),
            ));
        }
        let access = self.access_token().await?;
        let body = self
            .api
            .call(
                Method::GET,
                &access,
                &format!(
                    "organizations/{organization_id}/users?includeCollections=true&includeGroups=true"
                ),
                None,
            )
            .await?;
        Ok(parse_members(&body))
    }

    /// Un membre, relu sur le serveur (son état et son compte font foi, pas
    /// ce que l'interface affiche).
    async fn member(&mut self, organization_id: &str, member_id: &str) -> Result<Member, Error> {
        let access = self.access_token().await?;
        let body = self
            .api
            .call(
                Method::GET,
                &access,
                &format!(
                    "organizations/{organization_id}/users/{member_id}?includeCollections=true&includeGroups=true"
                ),
                None,
            )
            .await?;
        Member::parse(&body).ok_or_else(|| Error::Server("membre illisible".to_owned()))
    }

    /// Invite une ou plusieurs adresses. Le serveur envoie le lien
    /// d'invitation par courriel (sans courriel, il garde une invitation au
    /// nom de l'adresse, et un compte existant l'accepte d'office).
    pub async fn invite_members(
        &mut self,
        organization_id: &str,
        emails: &str,
        role: MemberRole,
        collections: &[CollectionAccess],
    ) -> Result<Vec<String>, Error> {
        let emails = parse_emails(emails)?;
        if emails.contains(&self.account.email.to_lowercase()) {
            return Err(Error::Invalid(
                "vous êtes déjà membre de cette organisation".to_owned(),
            ));
        }
        self.require_rights(organization_id, MemberAction::Invite(role), None)?;
        let body = invite_body(&emails, role, collections);
        self.org_call(
            Method::POST,
            &format!("organizations/{organization_id}/users/invite"),
            Some(&body),
        )
        .await?;
        Ok(emails)
    }

    /// Renvoie l'invitation (courriel) d'un membre qui ne l'a pas acceptée.
    pub async fn reinvite_member(
        &mut self,
        organization_id: &str,
        member_id: &str,
    ) -> Result<(), Error> {
        let member = self.member(organization_id, member_id).await?;
        self.require_rights(organization_id, MemberAction::Reinvite, Some(&member))?;
        if member.status != MemberStatus::Invited {
            return Err(Error::Invalid(
                "ce membre a déjà accepté l'invitation".to_owned(),
            ));
        }
        self.org_call(
            Method::POST,
            &format!("organizations/{organization_id}/users/{member_id}/reinvite"),
            None,
        )
        .await
    }

    /// Change le rôle et les accès aux collections d'un membre.
    pub async fn edit_member(
        &mut self,
        organization_id: &str,
        member_id: &str,
        role: MemberRole,
        collections: &[CollectionAccess],
    ) -> Result<(), Error> {
        let member = self.member(organization_id, member_id).await?;
        self.require_rights(organization_id, MemberAction::Edit(role), Some(&member))?;
        let body = edit_body(role, collections, &member.groups);
        self.org_call(
            Method::PUT,
            &format!("organizations/{organization_id}/users/{member_id}"),
            Some(&body),
        )
        .await
    }

    /// Retire l'accès d'un membre sans le supprimer (restaurable).
    pub async fn revoke_member(
        &mut self,
        organization_id: &str,
        member_id: &str,
    ) -> Result<(), Error> {
        let member = self.member(organization_id, member_id).await?;
        self.require_rights(organization_id, MemberAction::Revoke, Some(&member))?;
        if member.user_id == self.account.user_id {
            return Err(Error::Invalid(
                "vous ne pouvez pas révoquer votre propre accès".to_owned(),
            ));
        }
        self.org_call(
            Method::PUT,
            &format!("organizations/{organization_id}/users/{member_id}/revoke"),
            None,
        )
        .await
    }

    /// Rend son accès à un membre révoqué (dans l'état d'avant).
    pub async fn restore_member(
        &mut self,
        organization_id: &str,
        member_id: &str,
    ) -> Result<(), Error> {
        let member = self.member(organization_id, member_id).await?;
        self.require_rights(organization_id, MemberAction::Restore, Some(&member))?;
        self.org_call(
            Method::PUT,
            &format!("organizations/{organization_id}/users/{member_id}/restore"),
            None,
        )
        .await
    }

    /// Retire un membre de l'organisation (son compte reste sur le serveur).
    pub async fn remove_member(
        &mut self,
        organization_id: &str,
        member_id: &str,
    ) -> Result<(), Error> {
        let member = self.member(organization_id, member_id).await?;
        self.require_rights(organization_id, MemberAction::Remove, Some(&member))?;
        if member.user_id == self.account.user_id {
            return Err(Error::Invalid(
                "pour quitter l'organisation, passez par le coffre web".to_owned(),
            ));
        }
        self.org_call(
            Method::DELETE,
            &format!("organizations/{organization_id}/users/{member_id}"),
            None,
        )
        .await
    }

    /// Empreinte de la clé publique d'un membre qui a accepté l'invitation,
    /// à comparer avec la sienne avant de le confirmer.
    pub async fn member_fingerprint(
        &mut self,
        organization_id: &str,
        member_id: &str,
    ) -> Result<String, Error> {
        let member = self.member(organization_id, member_id).await?;
        self.require_rights(organization_id, MemberAction::Confirm, Some(&member))?;
        if member.status != MemberStatus::Accepted {
            return Err(Error::Invalid(
                "seul un membre qui a accepté l'invitation peut être confirmé".to_owned(),
            ));
        }
        let der = self.public_key(&member.user_id).await?;
        key_fingerprint(&member.user_id, &der)
    }

    /// Confirme un membre : la clé de l'organisation est chiffrée pour sa
    /// clé publique (RSA-OAEP-SHA1, par le SDK). `fingerprint` est
    /// l'empreinte que l'utilisateur a vérifiée : si la clé du serveur ne
    /// lui correspond plus, rien n'est envoyé.
    pub async fn confirm_member(
        &mut self,
        organization_id: &str,
        member_id: &str,
        fingerprint: &str,
    ) -> Result<(), Error> {
        let member = self.member(organization_id, member_id).await?;
        self.require_rights(organization_id, MemberAction::Confirm, Some(&member))?;
        if member.status != MemberStatus::Accepted {
            return Err(Error::Invalid(
                "seul un membre qui a accepté l'invitation peut être confirmé".to_owned(),
            ));
        }
        let der = self.public_key(&member.user_id).await?;
        if key_fingerprint(&member.user_id, &der)? != fingerprint {
            return Err(Error::Crypto(
                "la clé du membre a changé depuis la vérification : rien n'a été envoyé".to_owned(),
            ));
        }
        let public_key =
            PublicKey::from_der(&SpkiPublicKeyBytes::from(der)).map_err(Error::crypto)?;
        let organization: OrganizationId = organization_id.parse().map_err(Error::crypto)?;
        let key_store = self.sdk.internal.get_key_store();
        let wrapped = UnsignedSharedKey::encapsulate(
            SymmetricKeySlotId::Organization(organization),
            &public_key,
            &key_store.context(),
        )
        .map_err(|_| Error::Crypto("clé de l'organisation indisponible".to_owned()))?;
        let body = json!({ "key": wrapped.to_string() });
        self.org_call(
            Method::POST,
            &format!("organizations/{organization_id}/users/{member_id}/confirm"),
            Some(&body),
        )
        .await
    }

    /// L'empreinte de ma propre clé publique (« Phrase d'empreinte » du
    /// coffre web), que je lis à celui qui me confirme.
    pub fn own_fingerprint(&self) -> Result<String, Error> {
        self.sdk
            .platform()
            .user_fingerprint(self.account.user_id.clone())
            .map_err(Error::crypto)
    }

    async fn org_call(
        &mut self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(), Error> {
        let access = self.access_token().await?;
        self.api.call(method, &access, path, body).await.map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(role: MemberRole) -> Member {
        Member {
            id: "m".into(),
            user_id: "u".into(),
            name: None,
            email: "a@exemple.fr".into(),
            role,
            status: MemberStatus::Accepted,
            access_all: false,
            collections: Vec::new(),
            groups: Vec::new(),
            two_factor_enabled: false,
            has_account: true,
        }
    }

    #[test]
    fn members_are_parsed_like_vaultwarden_sends_them() {
        let body = json!({ "data": [
            { "id": "m1", "userId": "u1", "name": "Zoé", "email": "zoe@exemple.fr", "status": 2,
              "type": 0, "twoFactorEnabled": true, "hasMasterPassword": true,
              "collections": [], "groups": [], "permissions": null },
            { "id": "m2", "userId": "u2", "name": null, "email": "invite@exemple.fr", "status": 0,
              "type": 2, "twoFactorEnabled": false, "hasMasterPassword": false,
              "collections": [{ "id": "c1", "readOnly": true, "hidePasswords": true, "manage": false }],
              "groups": ["g1"] },
            { "id": "m3", "userId": "u3", "name": "Bob", "email": "bob@exemple.fr", "status": -1,
              "type": 4, "permissions": { "editAnyCollection": true }, "collections": [] },
            { "id": "m4", "userId": "u4", "email": "x@exemple.fr", "status": 1, "type": 9 },
        ]});
        let members = parse_members(&body);
        assert_eq!(members.len(), 3, "rôle inconnu ignoré");
        // Triés par nom affiché.
        assert_eq!(members[0].display_name(), "Bob");
        assert_eq!(members[1].display_name(), "invite@exemple.fr");
        assert_eq!(members[2].display_name(), "Zoé");
        let bob = &members[0];
        assert_eq!(bob.role, MemberRole::Manager, "personnalisé = gestionnaire");
        assert_eq!(bob.status, MemberStatus::Revoked);
        assert!(bob.access_all);
        let invited = &members[1];
        assert_eq!(invited.status, MemberStatus::Invited);
        assert!(!invited.has_account);
        assert_eq!(invited.groups, ["g1"]);
        assert_eq!(
            invited.collections,
            [CollectionAccess {
                id: "c1".into(),
                read_only: true,
                hide_passwords: true,
                manage: false
            }]
        );
        let owner = &members[2];
        assert!(owner.access_all && owner.two_factor_enabled);
        assert_eq!(owner.status, MemberStatus::Confirmed);
    }

    #[test]
    fn invite_body_matches_vaultwarden() {
        let collections = [CollectionAccess {
            id: "c1".into(),
            read_only: false,
            hide_passwords: true,
            manage: false,
        }];
        let emails = vec!["lea@exemple.fr".to_owned()];
        assert_eq!(
            invite_body(&emails, MemberRole::User, &collections),
            json!({
                "emails": ["lea@exemple.fr"], "type": 2,
                "collections": [{ "id": "c1", "readOnly": false, "hidePasswords": true, "manage": false }],
                "groups": [], "accessAll": false, "permissions": {},
            })
        );
        // Un administrateur voit tout : pas de liste.
        let admin = invite_body(&emails, MemberRole::Admin, &collections);
        assert_eq!(admin["type"], 1);
        assert_eq!(admin["accessAll"], true);
        assert_eq!(admin["collections"], json!([]));
        assert_eq!(
            invite_body(&emails, MemberRole::Manager, &collections)["type"],
            3
        );
    }

    #[test]
    fn edit_body_keeps_groups() {
        let body = edit_body(MemberRole::Manager, &[], &["g1".to_owned()]);
        assert_eq!(
            body,
            json!({ "type": 3, "collections": [], "groups": ["g1"], "accessAll": false, "permissions": {} })
        );
    }

    #[test]
    fn emails_are_split_checked_and_deduplicated() {
        assert_eq!(
            parse_emails(" Lea@Exemple.fr, <tom@exemple.fr>;\nlea@exemple.fr ").unwrap(),
            ["lea@exemple.fr", "tom@exemple.fr"]
        );
        assert!(parse_emails("").is_err());
        assert!(parse_emails("lea@exemple").is_err());
        assert!(parse_emails("a@@exemple.fr").is_err());
        let many: Vec<String> = (0..=MAX_INVITES)
            .map(|i| format!("p{i}@exemple.fr"))
            .collect();
        assert!(parse_emails(&many.join(",")).is_err());
    }

    #[test]
    fn rights_follow_vaultwarden() {
        let owner = MemberRights {
            view: true,
            manage: true,
            owner: true,
        };
        let admin = MemberRights {
            owner: false,
            ..owner
        };
        let manager = MemberRights {
            view: true,
            manage: false,
            owner: false,
        };
        let user = member(MemberRole::User);
        let other_admin = member(MemberRole::Admin);
        let other_owner = member(MemberRole::Owner);
        let other_manager = member(MemberRole::Manager);

        // Gestionnaire : lecture seule.
        assert!(check_rights(manager, MemberAction::Invite(MemberRole::User), None).is_err());
        // Propriétaire : tout.
        for action in [
            MemberAction::Invite(MemberRole::Owner),
            MemberAction::Edit(MemberRole::Admin),
            MemberAction::Confirm,
            MemberAction::Remove,
            MemberAction::Revoke,
        ] {
            assert!(check_rights(owner, action, Some(&other_owner)).is_ok());
        }
        // Administrateur : les utilisateurs, et les gestionnaires sans les promouvoir.
        assert!(check_rights(admin, MemberAction::Invite(MemberRole::User), None).is_ok());
        assert!(check_rights(admin, MemberAction::Invite(MemberRole::Manager), None).is_err());
        assert!(check_rights(admin, MemberAction::Invite(MemberRole::Admin), None).is_err());
        assert!(check_rights(admin, MemberAction::Confirm, Some(&user)).is_ok());
        assert!(check_rights(admin, MemberAction::Confirm, Some(&other_manager)).is_err());
        assert!(check_rights(admin, MemberAction::Edit(MemberRole::User), Some(&user)).is_ok());
        assert!(check_rights(admin, MemberAction::Edit(MemberRole::Manager), Some(&user)).is_ok());
        assert!(check_rights(admin, MemberAction::Edit(MemberRole::Admin), Some(&user)).is_err());
        assert!(
            check_rights(
                admin,
                MemberAction::Edit(MemberRole::User),
                Some(&other_admin)
            )
            .is_err()
        );
        assert!(
            check_rights(
                admin,
                MemberAction::Edit(MemberRole::Owner),
                Some(&other_owner)
            )
            .is_err()
        );
        assert!(check_rights(admin, MemberAction::Remove, Some(&user)).is_ok());
        assert!(check_rights(admin, MemberAction::Remove, Some(&other_admin)).is_err());
        assert!(check_rights(admin, MemberAction::Revoke, Some(&other_admin)).is_ok());
        assert!(check_rights(admin, MemberAction::Revoke, Some(&other_owner)).is_err());
        assert!(check_rights(admin, MemberAction::Reinvite, Some(&other_owner)).is_ok());
    }

    #[test]
    fn roles_round_trip() {
        for role in [
            MemberRole::Owner,
            MemberRole::Admin,
            MemberRole::User,
            MemberRole::Manager,
        ] {
            assert_eq!(MemberRole::from_code(i64::from(role.code())), Some(role));
        }
        assert_eq!(MemberRole::from_code(4), Some(MemberRole::Manager));
        assert_eq!(MemberStatus::from_code(-129), Some(MemberStatus::Revoked));
    }
}
