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

## Distribution

`scripts/install-macos.sh` construit une version Release **signée ad hoc**
(aucun compte de développeur), sandboxée (réseau sortant et USB), runtime
renforcé, sans
`get-task-allow` (aucun débogueur ne peut s'y attacher) ; le script refuse
d'installer un build qui l'aurait.

## Signaler un problème

Ouvrir une issue privée sur ce dépôt.
