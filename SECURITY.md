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
7. **App sandboxée**, runtime renforcé ; en entrée, seulement le pont vers l'extension, sur `127.0.0.1`.

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
- **Dans la page** : le menu vit dans un shadow DOM fermé et n'obéit qu'aux
  événements réels (`isTrusted`) ; la page ne peut ni le lire ni le
  déclencher. Les secrets n'arrivent qu'au remplissage, pour l'élément choisi.
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
