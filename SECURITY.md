# Sécurité

Verrou garde des mots de passe : chaque choix ci-dessous est délibéré, et toute
PR qui touche à l'un de ces points le dit dans sa description.

## Principes

1. **Pas de cryptographie maison.** Le chiffrement des coffres vient des crates
   du SDK Rust de Bitwarden (le code des apps officielles, épinglé sur un
   commit) ; les primitives restantes, de CryptoKit et du Secure Enclave.
2. **Les secrets restent dans Rust tant que possible.** `SecretString` est mis à
   zéro à la libération et ne s'affiche jamais dans un `Debug`. Swift ne reçoit
   une valeur secrète que sur demande explicite (`reveal`), au moment de
   l'afficher ou de la copier. Limite connue : une `String` Swift ne peut pas
   être mise à zéro ; on réduit donc sa durée de vie (oubliée dès qu'on change
   d'élément ou qu'on verrouille).
3. **Rien de secret n'est indexé.** La recherche porte sur le titre,
   l'identifiant affiché, les sites, le dossier et les étiquettes. Le sous-titre
   d'une note n'est jamais tiré de son contenu (un test le vérifie).
4. **Presse-papiers** : types `org.nspasteboard.ConcealedType` et
   `TransientType`, effacement après 90 s, et seulement si le contenu est
   toujours le nôtre.
5. **Verrouillage** : inactivité (10 min), veille, écran verrouillé, fin de
   session. Verrouiller libère le coffre.
6. **Écritures prudentes** : chiffrées par le SDK, envoyées avec la date de
   révision connue (le serveur refuse d'écraser une version plus récente),
   en ne touchant qu'aux champs que l'écran d'édition montre.
7. **App sandboxée**, runtime renforcé ; en entrée, seulement le pont vers l'extension et le terminal, sur `127.0.0.1`.

## Connexion à Vaultwarden

- **Ce que fait le SDK** : dérivation du mot de passe principal (PBKDF2 ou
  Argon2id, selon le compte), déchiffrement de la clé de l'utilisateur, de sa
  clé privée, des clés d'organisation, des dossiers et des éléments. Verrou
  ne fait que le transport HTTP et la conversion vers son modèle.
- **Ce qui est envoyé** : l'empreinte d'authentification dérivée par le SDK,
  jamais le mot de passe. HTTPS obligatoire (HTTP seulement pour `localhost`,
  les tests).
- **Ce qui est sur le disque** (`account.json`, dans le conteneur de l'app,
  mode 600) : la clé de l'utilisateur chiffrée par sa clé principale, sa clé
  privée chiffrée, la réponse de synchronisation telle que le serveur
  l'envoie (chiffrée), et le jeton de renouvellement **chiffré par Verrou avec
  la clé de l'utilisateur** : sans le mot de passe principal (ou Touch ID),
  le fichier ne permet ni de lire le coffre ni de parler au serveur. Un test
  vérifie qu'aucun secret n'y figure en clair.
- **Second facteur par clé de sécurité** (YubiKey en FIDO2) : Verrou parle à
  la clé **directement en USB** (protocole CTAP2, par `authenticator-rs`, la
  bibliothèque de Firefox ; droit `com.apple.security.device.usb`, qui ne
  demande aucune équipe de développeur). Comme un navigateur, il écrit
  `clientDataJSON` avec l'origine du serveur et le défi reçu ; la clé signe
  l'empreinte du domaine et celle de `clientDataJSON` après un contact :
  la signature ne vaut que pour ce serveur, et c'est lui qui la vérifie.
  Aucun code PIN (le serveur demande `discouraged`) ; si la clé en exige un,
  Verrou renvoie vers le repli. Un test d'intégration enregistre une clé
  logicielle sur un vrai Vaultwarden et vérifie qu'il accepte la réponse de
  Verrou et refuse une signature altérée.
- **Repli par le navigateur** : la page que Vaultwarden publie pour les apps
  mobiles (`webauthn-mobile-connector.html`), dans une session Safari
  éphémère (`ASWebAuthenticationSession`). « Se souvenir de cet appareil »
  n'est pas utilisé : une reconnexion redemande le second facteur.
- **Icônes des sites** : demandées au serveur du compte
  (`/icons/<site>/icon.png`, comme les apps Bitwarden), qui ne reçoit que le
  nom du site, sans authentification. Session réseau éphémère et cache en
  mémoire, vidé au verrouillage : la liste des sites ne reste pas en clair sur
  le disque. Désactivables dans les réglages.
- **Écriture** : l'élément part du cache, déchiffré par le SDK ; Verrou y
  reporte les champs modifiés, le SDK le rechiffre (avec la clé de l'élément
  ou de son organisation), puis `POST`/`PUT /api/ciphers` et une
  synchronisation. Un mot de passe remplacé rejoint l'historique de l'élément
  (5 entrées, comme Bitwarden). Les éléments qu'un compte ne peut pas
  modifier (partage en lecture) sont refusés avant tout envoi. Pour éditer,
  Swift reçoit les secrets de l'élément (`edit_draft`) : seulement quand
  l'utilisateur ouvre l'écran de modification. La corbeille est celle du
  serveur (`PUT /api/ciphers/{id}/delete`), restaurable.
- **Import** (Apple, 1Password, Proton Pass) : le fichier d'export est **en
  clair**, il contient tous les mots de passe. Verrou ne le lit que sur
  demande, une fois, par le panneau d'ouverture de macOS (droit
  `com.apple.security.files.user-selected.read-only` : lecture seule, de ce
  seul fichier) ; il ne le copie pas, ne le garde pas et n'y écrit rien. Le
  cœur Rust le lit et le compare au coffre ; les secrets restent dans des
  `SecretString` jusqu'à l'import, l'abandon ou le verrouillage, et la revue
  ne montre à Swift que titres, identifiants et sites, avec le verdict de la
  comparaison des mots de passe. Limite connue : les lecteurs CSV et JSON
  gardent des copies intermédiaires qui ne sont pas mises à zéro. Les
  éléments sont chiffrés par le SDK comme une création, puis envoyés en une
  requête (`POST /api/ciphers/import`, comme le coffre web) ; les noms de
  dossiers partent chiffrés. Un mot de passe remplacé rejoint l'historique
  de l'élément. Verrou recommande de supprimer le fichier d'export après
  l'import (et de vider la corbeille du Finder). Les exports chiffrés (PGP de
  Proton Pass) sont refusés : il faut exporter sans chiffrement.
- **Doublons** : comparés dans Rust (même site, même identifiant) ; Swift ne
  reçoit que les groupes et le verdict « mot de passe identique ou non ». La
  corbeille en masse (`PUT /api/ciphers/delete`) est celle du serveur,
  restaurable, et rien n'est envoyé si un élément n'est pas modifiable. Les
  éléments protégés (« redemander le mot de passe principal ») sont comparés
  comme les autres, à l'import comme ici : seul le verdict en sort, aucun
  secret.
- **Limites connues** : la demande de mot de passe principal par élément
  (« reprompt ») n'est pas appliquée ; les pièces jointes et les passkeys ne
  sont pas affichées.

## Extension de navigateur

```
extension ──Native Messaging──▶ verrou-native-host ──TCP 127.0.0.1──▶ Verrou
```

- **Pourquoi TCP** : le sandbox de macOS refuse à l'app (signée localement,
  sans équipe de développeur) tout socket Unix hors de son conteneur, en
  écoute comme en connexion ; il permet l'écoute sur `127.0.0.1`
  (`com.apple.security.network.server`). Ce port est joignable par tout
  programme de la machine : rien n'y circule en clair, et rien n'y est servi
  sans appairage.
- **Appairage** : l'extension crée une clé ECDH P-256 (WebCrypto, non
  exportable) ; Verrou répond avec une clé éphémère ; HKDF-SHA256 en tire la
  clé du canal. Les deux côtés affichent un code à 6 chiffres dérivé de cette
  clé : l'utilisateur l'accepte dans Verrou s'il est identique (« Refuser »
  est le bouton par défaut). Une demande à la fois, trois secondes au moins
  entre deux, deux minutes pour répondre.
- **Canal** : AES-256-GCM, nonce aléatoire, données associées = client et sens
  du message ; chaque requête porte un horodatage (± 2 min) contre le rejeu.
  L'hôte Native Messaging relaie des octets chiffrés sans les lire.
- **Ce que l'extension obtient** (`verrou-bridge/src/access.rs`) : la liste des
  identifiants (titre, identifiant) qui correspondent au site de la page, et
  les secrets d'un identifiant seulement s'il correspond à ce site — même
  domaine enregistrable, comme Bitwarden — et si la page est en HTTPS (HTTP
  seulement vers `localhost`). L'adresse vient du navigateur (`sender.url`),
  jamais de la page. Coffre verrouillé : rien, sinon la demande de
  déverrouillage. Une extension appairée ne peut donc pas vider le coffre.
- **Ce que l'extension écrit** : après l'envoi d'un formulaire, l'identifiant
  et le mot de passe saisis attendent la réponse de l'utilisateur deux minutes
  au plus, dans `chrome.storage.session` (en mémoire, hors de portée des
  pages). Rien n'est écrit sans un clic réel sur le bandeau. Verrou vérifie
  de nouveau chaque écriture : un nouvel élément pour le site de la page, ou
  le nouveau mot de passe (ou code de vérification) d'un identifiant qui
  correspond à ce site, en HTTPS. L'ancien mot de passe rejoint l'historique
  de l'élément. Une page piégée peut au pire proposer d'enregistrer ce
  qu'elle veut pour son propre site, et l'utilisateur doit l'accepter.
- **Générateur** : dans l'extension (`generator.js`), même règles que celui de
  Verrou, hasard de `crypto.getRandomValues` sans biais. Il ne demande rien
  à Verrou et fonctionne coffre verrouillé.
- **QR code de double authentification** : sur un clic dans la fenêtre de
  l'extension, une image de l'onglet visible (droit `activeTab`, valable
  seulement après ce clic) est lue par le lecteur de codes-barres de Brave,
  dans l'extension ; l'image n'est ni gardée ni envoyée. Seule l'URI
  `otpauth://` part vers Verrou, pour l'identifiant choisi.
- **Cartes et identités** : le menu d'un formulaire de paiement ou
  d'adresse ne reçoit que des titres et des sous-titres masqués (« Visa ••••
  4242 ») ; les champs ne sortent qu'au choix d'un élément, vers une page en
  HTTPS, et un élément protégé attend la confirmation dans Verrou. Une carte
  n'étant liée à aucun site, toute page sûre peut la proposer : c'est
  l'utilisateur qui choisit de la remplir.
- **Relier un site à un identifiant** : seulement depuis la fenêtre de
  l'extension, jamais depuis une page. La recherche n'y montre que titres et
  identifiants ; choisir un élément lui ajoute l'origine de l'onglet (après un
  avertissement sur l'hameçonnage), et le remplissage suit la règle habituelle
  du même site.
- **Dans la page** : le menu et le bandeau vivent dans un shadow DOM fermé et
  n'obéissent qu'aux événements réels (`isTrusted`) ; la page ne peut ni les
  lire ni les déclencher. Les secrets n'arrivent qu'au remplissage, pour
  l'élément choisi ; le bandeau d'enregistrement ne reçoit pas le mot de passe.
- **Ce qui est sur le disque** : côté Verrou, `bridge-clients.json` (conteneur
  de l'app, mode 600) garde la clé de chaque extension appairée ; côté Brave,
  la clé AES non exportable dans IndexedDB. Ces clés ne donnent que ce que
  donne l'extension. Réglages → *Délier* révoque un client.
- **Déclaration au navigateur** : `NativeMessagingHosts/app.verrou.bridge.json`
  n'autorise que l'identifiant de l'extension de Verrou (fixé par la clé de
  son manifeste ; un test vérifie la concordance). Droits du sandbox limités
  aux dossiers `NativeMessagingHosts` de Brave et de Chrome.
- **Limites connues** : un programme qui lit le profil de Brave peut en tirer
  la clé du canal (comme les cookies) ; l'extension se charge en mode
  développeur (pas de Chrome Web Store).

## Éléments protégés et audit

- **« Redemander le mot de passe principal »** (réglage Bitwarden d'un
  élément) : le cœur Rust refuse ses secrets (`reveal`, codes, brouillon de
  modification, remplissage dans Brave) tant que l'utilisateur n'a pas
  confirmé, par Touch ID ou par le mot de passe principal (vérifié hors ligne
  sur le cache). Une confirmation vaut 5 minutes pour cet élément et
  s'efface au verrouillage. Depuis Brave, Verrou demande la confirmation et
  l'extension réessaie : elle ne reçoit rien avant.
- **Audit** : mots de passe réutilisés, faibles (entropie estimée sous
  60 bits), sites en HTTP, calculés localement ; seuls des résumés sortent du
  cœur Rust.
- **Fuites connues** (sur demande) : API « Pwned Passwords » de Have I Been
  Pwned par k-anonymat. Seuls les 5 premiers caractères hexadécimaux du SHA-1
  de chaque mot de passe partent, avec du remplissage dans les réponses ; la
  comparaison se fait sur le Mac.
- **Nouveaux mots de passe** (réglage *Vérifier les nouveaux mots de passe
  dans les fuites connues*, actif par défaut) : après une écriture faite
  depuis Verrou (éditeur, extension, import), le cœur Rust compare le coffre
  avant et après, et seuls les identifiants dont le mot de passe est nouveau
  sont vérifiés, par la même API et le même k-anonymat. Les mots de passe
  arrivés par synchronisation ne partent pas. Réglage désactivé : rien n'est
  envoyé, la file d'attente (des identifiants d'éléments, jamais des secrets)
  est vidée ; elle l'est aussi au verrouillage.
- **Double authentification disponible** : la liste complète de
  [2fa.directory](https://2fa.directory) (`api.2fa.directory/v3/tfa.json`,
  environ 400 Ko) est téléchargée à l'ouverture de l'audit, au plus une fois
  par semaine, et gardée dans le dossier du compte (`2fa-directory.json`) ;
  aucune requête ne dépend du coffre, la comparaison avec les sites des
  identifiants se fait sur le Mac. Hors ligne, la dernière copie sert. Seuls
  les liens d'aide en HTTPS sont proposés.
- **Cartes et mots de passe anciens** : calculés localement (échéance des
  cartes, date de modification des éléments).

## Remplissage dans les apps (⌘\)

- **Ce qui est tapé** : l'identifiant, Tab, le mot de passe (Retour en
  option, désactivé par défaut), par des événements clavier `CGEvent` dont le
  texte passe en Unicode (`keyboardSetUnicodeString`), sans code de touche ni
  modificateur. Le cœur Rust ne rend ces frappes (`autofill_keystrokes`)
  qu'au moment où l'utilisateur choisit un identifiant, et refuse un élément
  protégé tant qu'il n'a pas été confirmé (Touch ID ou mot de passe
  principal) ; coffre verrouillé, il ne rend rien.
- **Où** : dans l'app qui était au premier plan au moment du raccourci,
  retenue par son PID. Verrou lui rend le premier plan et ne tape qu'après
  avoir vérifié qu'elle l'a ; sinon, rien n'est tapé. Il ne lit ni ne
  contrôle les fenêtres des autres apps (aucune lecture d'interface par
  l'API d'accessibilité) : c'est l'utilisateur qui place le curseur dans le
  champ.
- **Saisie sécurisée** : si une autre app que la cible a activé la saisie
  sécurisée (`IsSecureEventInputEnabled`, propriétaire lu dans
  `CGSessionCopyCurrentDictionary`), Verrou prévient dans l'accès rapide et
  ne tape rien. Celle de l'app visée (un champ de mot de passe) est normale.
- **Autorisation** : taper pour une autre app demande l'accès
  « Accessibilité » (`AXIsProcessTrustedWithOptions`,
  `CGRequestPostEventAccess` pour une app sandboxée). Signé ad hoc, Verrou
  peut perdre cette autorisation à chaque recompilation (macOS l'attache à la
  signature) : il faut alors le retirer de la liste et l'autoriser à nouveau.
- **Association** : une app se relie à un identifiant par une adresse
  `macapp://<identifiant de paquet>` ajoutée à ses sites, chiffrée et
  synchronisée comme eux, avec la règle de correspondance « jamais » pour
  que les extensions Bitwarden ne la proposent sur aucune page. Le cœur ne la
  traite jamais comme un site (ni suggestion web, ni icône, ni doublon).
- **Limites connues** : une app qui lit les codes de touches plutôt que les
  caractères (jeux, bureaux à distance) reçoit des frappes incorrectes ; une
  app malveillante au premier plan reçoit ce qu'on lui tape, comme avec un
  copier-coller. Le code à usage unique est copié (presse-papiers dissimulé,
  effacé après 90 s), pas tapé.

## Terminal et agent SSH

```
verrou (CLI) ─────────TCP 127.0.0.1──▶ Verrou
ssh ──socket Unix──▶ verrou ssh-agent ──TCP 127.0.0.1──▶ Verrou
```

- **Appairage** : le même que l'extension (ECDH P-256, code à 6 chiffres à
  comparer, canal AES-256-GCM), par `verrou link`. Le client se déclare
  « terminal » ; la fenêtre d'accord de Verrou le dit (« Relier le terminal
  (verrou) ») et dit ce qu'il pourra faire. Un client enregistré sans nature
  (avant cette version) est une extension.
- **Commandes par nature de client** (`access::allowed`, vérifié par le pont
  pour chaque requête, avec des tests) : l'extension n'a que ses commandes
  (suggérer, remplir, enregistrer) ; le terminal n'a que les siennes
  (chercher, lire un élément, révéler, code, clés SSH, signer). Ni l'un ni
  l'autre ne peut emprunter celles de l'autre.
- **Ce que le terminal obtient sans demander** : les résultats de recherche
  et les éléments **sans aucun secret** (titre, identifiant, sites, dossier,
  étiquettes, valeur des champs non masqués) ; les champs masqués, les notes
  et les graines TOTP n'y figurent pas (un test le vérifie). Coffre
  verrouillé : rien, sinon la demande de déverrouillage (Touch ID dans
  Verrou).
- **Ce qui demande un accord** : chaque secret (champ masqué, notes, code à
  usage unique) et chaque signature SSH. Verrou demande Touch ID (ou le mot
  de passe de la session, `.deviceOwnerAuthentication`) : « autoriser le
  terminal à lire « titre » », « autoriser ssh à utiliser la clé « titre » ».
  L'accord vaut **5 minutes pour ce client et cet élément** seulement ; il est
  oublié au verrouillage du coffre et à la révocation du client. Sans réponse
  en 90 s : refus. Un élément protégé (« redemander le mot de passe
  principal ») exige la confirmation de l'app (Touch ID ou mot de passe
  principal), que le cœur Rust vérifie avant de livrer quoi que ce soit.
- **Clés SSH** : la clé privée (OpenSSH, telle que Vaultwarden la garde) ne
  quitte jamais l'app. Verrou signe (crate `ssh-key` de RustCrypto) et ne
  rend que la signature ; l'agent ne voit que les clés publiques. Les clés
  protégées par une phrase de passe sont ignorées.
- **Ce qui est sur le disque** : `~/.config/verrou/cli.json` (mode 600,
  dossier 700) garde l'identifiant du client et la clé du canal. Un
  programme qui le lit peut se faire passer pour le terminal : chercher sans
  secret, et demander des secrets — que l'utilisateur doit encore accepter
  par Touch ID. Réglages → *Délier*, ou `verrou unlink`, révoque le lien.
- **Socket de l'agent** : `~/.verrou/agent.sock`, dossier 700, socket 600.
  Comme pour `ssh-agent`, **tout programme lancé par l'utilisateur** peut lui
  demander les clés publiques et des signatures ; chaque signature d'une clé
  passe toutefois par Touch ID, puis l'accord dure 5 minutes pour cette clé
  (pendant ce temps, un tel programme peut signer sans nouvelle demande).
  L'agent ne sait ni ajouter, ni retirer, ni exporter de clé ; les autres
  messages reçoivent `SSH_AGENT_FAILURE`.
- **Limites connues** : l'accord est donné par élément, sans montrer quelle
  commande le demande ; un programme qui tourne sous le compte de
  l'utilisateur peut lire ce que la CLI affiche.

## Touch ID

La clé de l'utilisateur est scellée par une clé d'accord P-256 **créée dans le
Secure Enclave**, utilisable seulement après Touch ID
(`.biometryCurrentSet`) : ajouter ou retirer une empreinte la rend
inutilisable, et il faut repasser par le mot de passe. Le scellement (ECDH avec
une clé éphémère, HKDF-SHA256, AES-GCM) n'exige pas d'authentification ;
l'ouverture, si. Le fichier `touchid.json` ne contient qu'une référence
chiffrée à la clé du Secure Enclave, inutilisable sur un autre Mac. Pas de
trousseau, donc pas de droit à demander : l'app peut être signée localement.

La clé de l'utilisateur ne traverse la frontière Rust/Swift que pour
l'enrôlement (`user_key`) et le déverrouillage ; une `String` Swift ne pouvant
être mise à zéro, elle n'est gardée dans aucune propriété.

Le SDK de Bitwarden accepte n'importe quelle clé bien formée (le coffre se
déchiffre alors en zéro élément) : Verrou vérifie la clé rendue en déchiffrant
avec elle le jeton de renouvellement, et la refuse sinon.

## Clé de sécurité (YubiKey, `hmac-secret`)

Une YubiKey (ou toute clé FIDO2 avec l'extension `hmac-secret` et un code
PIN) peut déverrouiller le coffre, en plus de Touch ID et du mot de passe.

- **Principe** : à l'enrôlement (coffre ouvert, Réglages), Verrou crée sur la
  clé une accréditation non résidente pour l'identifiant `verrou:` — pas un
  nom de domaine, comme le `ssh:` d'OpenSSH : aucune page web ne peut la
  faire utiliser par un navigateur. Il tire un sel de 32 octets ; la clé
  rend, après code PIN et contact, `HMAC-SHA-256` d'un secret qu'elle ne
  livre jamais (le sel passe d'abord par la transformation de l'extension
  WebAuthn PRF). HKDF-SHA256 (sel `verrou.security-key.v1`, info =
  identifiant de l'accréditation) en tire une clé AES-256-GCM qui scelle la
  clé de l'utilisateur ; données associées : version, identifiant de
  l'accréditation et sel. Tout cela se fait dans Rust (`unlock_keys.rs`,
  primitives RustCrypto) : la clé de l'utilisateur ne passe pas par Swift.
- **Ce qui est sur le disque** (`security-keys.json`, conteneur de l'app,
  mode 600, écriture atomique), par clé : identifiant de l'accréditation,
  sel, clé de l'utilisateur scellée (nonce aléatoire), nom et date. Rien
  d'utile sans la clé physique.
- **Code PIN exigé** (vérification de l'utilisateur `required`) : il faut la
  clé **et** son code PIN ; la clé se bloque après 8 codes faux. Une clé
  sans code PIN est refusée, avec le message qui dit d'en définir un. C'est
  aussi une contrainte d'`authenticator-rs` 0.5 : sans vérification de
  l'utilisateur, il n'établit pas le secret partagé et n'envoie pas
  l'extension `hmac-secret`. Le code PIN traverse la frontière Swift/Rust
  une fois, va à la clé chiffré par le protocole PIN de CTAP2, et n'est
  gardé (effacé ensuite) que le temps d'un enrôlement, pour éviter de le
  taper deux fois. Limite : la bibliothèque le copie dans une `String` non
  effacée.
- **Plusieurs clés** (principale et secours) : chacune a son accréditation,
  son sel et sa copie scellée. Au déverrouillage, toutes les accréditations
  sont proposées (PRF `evalByCredential`) : la clé branchée ne répond que
  pour la sienne, avec le sel qui va avec. Les mêmes accréditations ne
  peuvent pas être enrôlées deux fois (liste d'exclusion).
- **Avec le fichier mais sans la clé**, un attaquant n'a que des données
  chiffrées : le secret ne sort pas de la clé, et 32 octets aléatoires ne se
  devinent pas. **Avec la clé mais sans le code PIN**, 8 essais au plus
  avant blocage. **Avec la clé, le code PIN et le fichier**, il ouvre le
  coffre, comme avec le mot de passe principal : retirer la clé dans les
  Réglages (ou se déconnecter) rend sa copie scellée inutile.
- **Invalidation**, comme Touch ID : une reconnexion ou une déconnexion
  efface `security-keys.json` ; une clé descellée que le coffre refuse (clé
  du coffre changée) efface toutes les clés enrôlées. Retirer une clé
  n'efface pas son accréditation sur la YubiKey (sans valeur sans le
  fichier ; une YubiKey ne liste pas les accréditations non résidentes).

## Distribution

`scripts/install-macos.sh` construit une version Release **signée ad hoc**
(aucun compte de développeur), sandboxée (réseau sortant et USB), runtime
renforcé, sans
`get-task-allow` (aucun débogueur ne peut s'y attacher) ; le script refuse
d'installer un build qui l'aurait.

## Signaler un problème

Ouvrir une issue privée sur ce dépôt.
