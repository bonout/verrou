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
   en ne touchant qu'aux champs que l'écran d'édition montre. Elles passent
   par une file chiffrée, envoyée en arrière-plan ou au retour du réseau
   (voir « Modifications hors ligne »).
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
  l'utilisateur ouvre l'écran de modification (champs personnalisés
  masqués compris). Les champs réservés à Verrou (`verrou:type`, qui
  désigne un modèle comme « Réseau Wi-Fi ») ne lui sont jamais proposés et
  repartent tels quels. La corbeille est celle du serveur
  (`PUT /api/ciphers/{id}/delete`), restaurable.
- **QR code d'un Wi-Fi** : le contenu (`WIFI:T:WPA;S:…;P:…;;`, mot de passe
  compris) ne sort de Rust (`wifi_qr_code`) que quand l'utilisateur demande
  le QR code, après la confirmation d'un élément protégé ; Swift n'en garde
  que l'image, le temps du popover.
- **Import** (Apple, 1Password, Proton Pass) : le fichier d'export est **en
  clair**, il contient tous les mots de passe. Verrou ne le lit que sur
  demande, une fois, par le panneau d'ouverture de macOS (droit
  `com.apple.security.files.user-selected.read-write`, qu'exige
  « Enregistrer sous… » des pièces jointes ; limité au fichier choisi) ; il
  ne le copie pas, ne le garde pas et n'y écrit rien. Les fichiers d'une
  archive (1Password, Proton Pass) deviennent des pièces jointes : lus en
  mémoire (100 Mo par fichier, 512 Mo par archive), chiffrés comme un ajout,
  l'élément créé seul puis ses fichiers. Le
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
- **Doublons** : comparés dans Rust (sites et domaines, titre et marque,
  identifiant ; mots de passe et graines TOTP en temps constant, regroupés
  le temps du calcul par une empreinte en mémoire, jamais écrite) ; Swift ne
  reçoit que les groupes, leur degré (certain, probable, à vérifier), la
  raison en clair et le verdict « mot de passe identique ou non ». La fusion
  (`merge.rs`) se fait dans Rust sur l'élément déchiffré, par le chemin
  d'écriture d'une modification (date de révision, file hors ligne) ; les
  pièces jointes et les passkeys ne sont jamais déplacées (fusion refusée).
  Les groupes ignorés sont retenus dans les préférences de l'app par une
  empreinte SHA-256 tronquée des identifiants des éléments, sans titre ni
  site. La corbeille en masse (`PUT /api/ciphers/delete`) est celle du serveur,
  restaurable, et rien n'est envoyé si un élément n'est pas modifiable. Les
  éléments protégés (« redemander le mot de passe principal ») sont comparés
  comme les autres, à l'import comme ici : seul le verdict en sort, aucun
  secret.
- **Actions groupées** (plusieurs éléments sélectionnés, `bulk.rs`) : même
  chemin d'écriture qu'un seul élément. Corbeille, restauration, archives et
  dossiers par les routes groupées de Vaultwarden (`PUT /api/ciphers/delete`,
  `…/restore`, `…/archive`, `…/unarchive`, `…/move`), par lots de 500 ; un
  lot refusé est repris élément par élément pour savoir lequel. Les favoris,
  sans route groupée, partent un par un comme une modification (chiffrés
  par le SDK, date de révision connue : un élément changé ailleurs est
  refusé, jamais écrasé). Les éléments en lecture seule (et ceux de la
  corbeille, sauf pour restaurer) sont écartés avant tout envoi, et comptés.
  Hors ligne, chaque élément rejoint la file comme une action seule. Mettre
  plusieurs éléments à la corbeille demande confirmation. La sélection
  elle-même ne contient que des identifiants : aucun secret.
- **Pièces jointes** (format Bitwarden) : chaque fichier a sa propre clé
  (64 octets, tirée par le SDK), chiffrée par la clé de l'élément (ou de
  l'utilisateur, ou de l'organisation) ; le nom du fichier est chiffré comme
  un champ ; le contenu est un `EncArrayBuffer` de type 2 (AES-256-CBC,
  HMAC-SHA256 vérifié avant tout déchiffrement). Le SDK fait toute cette
  cryptographie ; un test relit un fichier chiffré par Bitwarden, un autre
  vérifie qu'un octet altéré fait tout refuser. Envoi en deux temps
  (`POST …/attachment/v2`, puis le contenu chiffré vers l'adresse rendue,
  qui doit être sur le serveur du compte ; la réservation est supprimée si
  l'envoi échoue), lecture par l'adresse signée que donne le serveur, en
  HTTPS (HTTP seulement vers `localhost`). 100 Mo par fichier.
  **Rien n'est gardé hors ligne** : le cache ne contient que les
  métadonnées chiffrées de la synchronisation ; un fichier se télécharge à
  chaque ouverture. Déchiffré dans Rust (tampon effacé à la libération), il
  passe à Swift : pour Quick Look, dans un fichier temporaire du conteneur
  de l'app (`tmp/pieces-jointes`, mode 600), effacé à la fermeture de
  l'aperçu, au changement d'élément, au verrouillage et au lancement
  suivant ; « Enregistrer sous… » écrit une copie **en clair**, là où
  l'utilisateur le choisit (droit
  `com.apple.security.files.user-selected.read-write`, limité aux fichiers
  choisis dans les panneaux de macOS ou déposés sur la fenêtre). Un élément
  protégé ne livre ses fichiers qu'après confirmation. Limites : la copie
  passée à Swift (`Data`) n'est pas mise à zéro, et Quick Look peut garder
  sa propre vignette en cache.
- **Coffres partagés (organisations)** : la clé de chaque organisation
  arrive dans le profil, chiffrée avec la clé publique du compte (RSA-OAEP) ;
  le SDK la déchiffre avec la clé privée et l'utilise pour les noms des
  collections et les éléments de l'organisation. Elle reste dans le SDK,
  jamais dans Swift ni sur le disque en clair (le cache garde la version
  chiffrée du serveur). Créer dans une collection
  (`POST /api/ciphers/create`), partager un élément personnel
  (`PUT /api/ciphers/{id}/share`) ou changer ses collections
  (`PUT /api/ciphers/{id}/collections_v2`) : le SDK chiffre avec la clé de
  l'organisation, clés de l'élément et de ses pièces jointes comprises (le
  contenu des pièces jointes n'est pas retéléchargé) ; des pièces jointes
  d'un ancien format, sans clé propre, font refuser le partage. Les droits
  annoncés par le serveur sont appliqués avant tout envoi : une collection en
  lecture seule n'est ni modifiée ni proposée comme destination (le serveur
  le vérifie de toute façon) ; « masquer les mots de passe » est appliqué
  dans le cœur Rust : mot de passe, graine TOTP, champs masqués et anciens
  mots de passe ne sortent ni vers Swift (`reveal`), ni vers le terminal, ni
  dans un brouillon de modification ; seul le remplissage par l'extension
  reste permis, comme dans les apps Bitwarden. Les doublons ne comparent que
  des éléments d'un même coffre, et jamais un élément en lecture seule. Les
  membres se gèrent dans Verrou (voir « Membres des organisations ») ; la
  création des collections et les règles de l'organisation, dans le coffre
  web.
- **Modifications hors ligne, et écritures sans attente** (`outbox.rs`) :
  en ligne comme hors ligne, une création, une modification, un favori, un
  changement de dossier, la corbeille, la restauration, les archives (seules
  ou groupées) et les identifiants enregistrés depuis le navigateur
  s'appliquent au coffre affiché et attendent dans une file, `outbox.json`
  (dossier du compte, mode 600) ; l'envoi suit aussitôt, en arrière-plan, et
  l'extension reçoit sa réponse dès l'écriture locale. En ligne, une
  passkey créée depuis le navigateur et son compteur vont au serveur avant
  la réponse au site ; les pièces jointes, le partage et l'import ne passent
  pas par la file. L'élément y
  est **déjà chiffré par le SDK**, exactement comme il serait parti (même
  clé, même date de révision connue) ; la file entière est en plus chiffrée
  par la clé de l'utilisateur (comme le jeton de renouvellement). En clair
  dans le fichier : l'identifiant du compte et le nombre de modifications en
  attente (pour prévenir avant une déconnexion, coffre verrouillé). Un test
  vérifie qu'aucun titre ni secret n'y figure. Verrouiller garde la file ;
  se déconnecter l'efface (la confirmation dit combien de modifications
  seraient perdues) ; une file d'un autre compte est ignorée et supprimée.
  La file part avant la lecture du coffre : créations et modifications
  d'abord, dans l'ordre, puis corbeille, archives et dossiers (par lots).
  L'envoi ne garde pas la connexion verrouillée pendant le réseau : une
  écriture faite pendant ce temps se place derrière celle en cours d'envoi
  (jamais fusionnée avec elle) et repart de la date de révision que le
  serveur rend, sans rien écraser d'autre. Une déconnexion pendant un envoi
  arrête toute écriture de la file sur le disque ; un verrouillage l'arrête
  après la requête en cours (la clé de l'utilisateur reste en mémoire le
  temps de cette requête, 30 s au plus, comme pour toute requête déjà
  partie), le reste attend le déverrouillage suivant. Si
  l'élément a changé (ou disparu) sur le serveur entre-temps, le serveur
  refuse la modification ; Verrou ne l'écrase pas : la version locale
  devient une copie, « titre (conflit hors ligne) », au même endroit, sans
  ses pièces jointes, et la version du serveur revient. Une modification
  refusée pour une autre raison (et dont la copie est refusée aussi) est
  retirée de la file, le coffre affiché revient à la version du serveur, et
  le refus est signalé avec sa raison : jamais perdue en silence. Restent
  impossibles hors ligne, avec un message clair : pièces jointes, partage
  vers une organisation (et création dans une collection), envois, accès
  d'urgence, import. Les éléments en lecture seule le restent. Les
  identifiants enregistrés depuis le navigateur suivent le même chemin. Limite
  connue : une écriture dont la réponse se perd (coupure pendant l'envoi)
  peut repartir au retour du réseau ; une création peut alors être en
  double, une modification devient une copie de conflit (rien n'est perdu).
- **Limites connues** : la demande de mot de passe principal par élément
  (« reprompt ») n'est pas appliquée.

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
  `otpauth://` part vers Verrou, pour l'identifiant choisi. Firefox n'a pas
  de lecteur de codes-barres : la clé s'y saisit à la main.
- **Cartes et identités** : la pastille d'un formulaire de paiement ou
  d'adresse ne reçoit que des titres et des sous-titres masqués (« Visa ••••
  4242 ») ; les champs ne sortent qu'au choix d'un élément, vers une page en
  HTTPS, et un élément protégé attend la confirmation dans Verrou. Une carte
  n'étant liée à aucun site, toute page sûre peut la proposer : c'est
  l'utilisateur qui choisit de la remplir.
- **Relier un site à un identifiant** : seulement depuis la fenêtre de
  l'extension, jamais depuis une page. « Remplir avec un autre
  identifiant… » de la pastille (vrai clic) ne fait que l'ouvrir sur ce choix,
  pour l'onglet et le cadre d'où vient le clic (adresse donnée par le
  navigateur, `sender.url`) ; Firefox n'ouvrant pas la fenêtre de
  l'extension hors d'un clic sur son icône, c'est alors une petite fenêtre de
  l'extension. La recherche n'y montre que titres et identifiants ; choisir un
  élément lui ajoute l'origine du cadre (après un avertissement sur
  l'hameçonnage), et le remplissage suit la règle habituelle du même site.
- **Remplissage demandé par la fenêtre de l'extension** : les identifiants
  partent vers le cadre visé avec l'origine pour laquelle Verrou les a
  donnés ; `content.js` ne remplit que si son cadre est toujours à cette
  origine (la page a pu changer entre-temps).
- **Dans la page** : la pastille (en haut à gauche), l'icône Verrou du champ
  actif et le bandeau d'enregistrement vivent dans des shadow DOM fermés et
  n'obéissent qu'aux événements réels (`isTrusted`) ; la page ne peut ni les
  lire ni les déclencher (un clic qu'elle envoie à l'hôte n'atteint pas les
  boutons). Leurs hôtes sont tenus en place par des styles en ligne
  `!important` (position fixe, `z-index` maximal, opacité) : une feuille de
  style de la page ne les cache ni ne les déplace ; un script de la page peut
  toujours les retirer ou dessiner une imitation, mais une imitation ne
  remplit rien. La pastille ne prend pas le focus ; elle ne montre que le
  site, les titres et les identifiants. Les secrets n'arrivent qu'au
  remplissage, pour l'élément choisi. Le bandeau d'enregistrement ne reçoit
  pas le mot de passe.
- **Envoi après le remplissage** : seulement pour une connexion
  (identifiant, mot de passe, code), après un vrai clic dans la pastille
  (`isTrusted`) ou un choix dans la fenêtre de l'extension ; jamais pour une
  carte, une adresse ou un mot de passe généré, donc jamais pour un
  formulaire de paiement. Le formulaire ne part (`requestSubmit`, avec son
  bouton) que si les valeurs remplies sont toujours là, qu'aucun autre champ
  visible ne reste vide et qu'aucun captcha n'est visible ; une étape
  suivante (mot de passe après l'identifiant) attend un nouveau clic.
  Réglage « Envoyer le formulaire après le remplissage » de la fenêtre de
  l'extension (`storage.local`, actif par défaut) ; désactivé, le curseur va
  sur le bouton d'envoi et rien ne part. Identifiants envoyés tels que Verrou
  les a remplis : pas de proposition d'enregistrement.
- **Quand l'extension interroge Verrou** : au chargement d'une page qui
  montre un formulaire de connexion (champ mot de passe, identifiant qui se
  présente comme tel, ou code de vérification), une fois par étape du
  formulaire, pour savoir s'il faut montrer la pastille ; avant, c'était au
  premier passage dans le champ. La demande ne porte que l'adresse du cadre,
  donnée par le navigateur, et ouvre Verrou en arrière-plan s'il ne tourne pas
  (comme une demande de passkey). Cartes et adresses : au premier passage
  dans un de leurs champs seulement.
- **Ce qui est sur le disque** : côté Verrou, `bridge-clients.json` (conteneur
  de l'app, mode 600) garde la clé de chaque extension appairée ; côté Brave
  ou Firefox,
  la clé AES non exportable dans IndexedDB. Ces clés ne donnent que ce que
  donne l'extension. Réglages → *Délier* révoque un client.
- **Déclaration au navigateur** : `NativeMessagingHosts/app.verrou.bridge.json`
  n'autorise que l'identifiant de l'extension de Verrou : `allowed_origins`
  pour Brave et Chrome (identifiant fixé par la clé de son manifeste),
  `allowed_extensions` pour Firefox (`verrou@verrou.app`, fixé par
  `browser_specific_settings.gecko.id`) ; un test vérifie la concordance entre
  app, hôte et manifestes. L'hôte refuse en plus d'être lancé pour une autre
  extension (`unknown_extension`), d'après ses arguments : l'origine de
  l'extension (Brave), ou le chemin du manifeste puis l'identifiant
  (Firefox). Droits du sandbox limités aux dossiers `NativeMessagingHosts`
  de Brave, de Chrome et de Firefox (`Mozilla`).
- **Firefox** : la même extension (`scripts/firefox-extension.sh` ne change
  que le manifeste) ; Firefox 128 au moins, pour le script de passkeys dans
  le monde de la page. L'accès aux sites (`host_permissions`) est accordé ou
  retiré par l'utilisateur ; sans lui, aucun script de Verrou ne tourne dans
  les pages, et la fenêtre de l'extension propose de le demander. Dans le
  monde isolé, les objets venus de la page se voient à travers des « Xray » :
  `passkeys.js` copie la requête (JSON) avant de s'en servir. Non signée,
  l'extension ne se charge que temporairement (about:debugging) : Firefox
  l'efface à la fermeture, avec sa clé de canal (il faut la relier de
  nouveau ; délier l'ancienne dans Verrou). Signée par Mozilla
  (`scripts/sign-firefox.sh`, distribution « unlisted »), Mozilla voit son
  code, pas les données : rien ne part du Mac
  (`data_collection_permissions: none`).
- **Mise à jour de l'extension** : la copie livrée dans `Verrou.app` reçoit à
  la compilation une version tirée de l'empreinte de ses fichiers
  (`scripts/stamp-extension.sh`). Le pont annonce cette version (réponse à
  `status`, lue dans le manifeste du paquet de l'app) ; l'extension la compare
  à la sienne et à celle du manifeste sur le disque, au démarrage, à chaque
  connexion à Verrou et toutes les dix minutes, et se recharge
  (`runtime.reload()`) si elles diffèrent : une fois par version au
  plus, une fois par minute au plus (`storage.local`). Firefox ne recharge
  que pour un manifeste changé sur le disque (extension temporaire) : un
  module installé (.xpi) ne changerait pas en se rechargeant, la fenêtre de
  l'extension avertit seulement. Elle ne relit
  que ses propres fichiers ; une version annoncée ne fait rien charger
  d'autre que le dossier déjà choisi par l'utilisateur.
- **Limites connues** : un programme qui lit le profil du navigateur peut en tirer
  la clé du canal (comme les cookies) ; l'extension se charge en mode
  développeur (pas de Chrome Web Store). Les onglets ouverts avant un
  rechargement gardent l'ancien script, détaché : il faut recharger la page.

## Accès d'urgence

- **Confirmer un contact** revient à lui confier la clé du coffre : elle est
  chiffrée pour sa clé publique (RSA-OAEP-SHA1, par le SDK, comme le coffre
  web) et confiée au serveur, qui ne peut pas la lire. La clé publique vient
  du serveur (`/api/users/{id}/public-key`) : un serveur malveillant pourrait
  y mettre la sienne. Verrou montre donc d'abord l'empreinte de cette clé (la
  phrase de 5 mots des apps Bitwarden), à comparer avec celle que le contact
  lit dans son compte ; à l'envoi, la clé est relue et refusée si son
  empreinte n'est plus celle qui a été vérifiée.
- **Ouvrir le coffre d'un concédant** (lecture seule, accès accordé) : la clé
  du concédant, chiffrée pour moi, s'ouvre avec ma clé privée, dans le SDK ;
  ses éléments sont déchiffrés dans Rust et gardés dans un objet à part.
  Swift n'en reçoit que les résumés, et les secrets un par un, à la
  demande. Fermer la fenêtre ou verrouiller Verrou vide cet objet (secrets
  mis à zéro) ; il se vide aussi de lui-même si la connexion qui l'a ouvert
  disparaît.
- **Prise de contrôle** (nouveau mot de passe principal du concédant) : pas
  dans Verrou, seulement dans le coffre web.

## Membres des organisations

- **Sans jeton d'administration** : Verrou n'utilise jamais le panneau
  d'administration de Vaultwarden (`/admin`, désactivé sur un serveur
  prudent). Ce jeton donne tout le serveur (comptes, réglages, suppression)
  à qui le détient ; le garder dans une app de bureau, ou le saisir à chaque
  invitation, élargirait beaucoup la surface d'attaque pour un gain nul.
  Ajouter quelqu'un passe par l'invitation d'une organisation
  (`INVITATIONS_ALLOWED=true`), avec les droits du compte connecté :
  propriétaires et administrateurs gèrent, un gestionnaire avec accès à
  toutes les collections voit la liste, les autres rien. Les règles de
  Vaultwarden (seul un propriétaire invite, confirme, retire ou promeut un
  gestionnaire, un administrateur ou un propriétaire) sont vérifiées dans
  Rust avant tout envoi ; le serveur les vérifie de toute façon. Avant
  chaque action sur un membre, son état et son compte sont relus sur le
  serveur : l'interface ne fournit que des identifiants.
- **Confirmer un membre** revient à lui confier la clé de l'organisation :
  elle est chiffrée pour sa clé publique (RSA-OAEP-SHA1, par le SDK, comme
  le coffre web) et confiée au serveur, qui ne peut pas la lire. La clé
  publique vient du serveur (`/api/users/{id}/public-key`) : un serveur
  malveillant pourrait y mettre la sienne et lire tout le coffre partagé.
  Verrou montre donc d'abord l'empreinte de cette clé (la phrase de 5 mots
  des apps Bitwarden), à comparer de vive voix avec celle que le membre lit
  dans son compte (Verrou : Réglages → Compte ; coffre web : Paramètres →
  Mon compte) ; à l'envoi, le membre et sa clé sont relus et rien ne part si
  l'empreinte n'est plus celle qui a été vérifiée. La même phrase, calculée
  à partir de ma clé privée (jamais du serveur), s'affiche dans Réglages →
  Compte pour celui qui me confirme.
- **Créer un compte** (écran de connexion) : le SDK dérive la clé principale
  du mot de passe (PBKDF2-SHA256 à 600 000 itérations, ou Argon2id 3 × 64 Mio
  × 4, les défauts des apps Bitwarden), tire la clé de l'utilisateur et la
  paire de clés RSA ; le serveur ne reçoit que l'empreinte d'authentification
  et les clés chiffrées. Mot de passe de 12 caractères au moins, robustesse
  affichée (zxcvbn, par le SDK), confirmation obligatoire ; l'indice, s'il y
  en a un, est stocké **en clair** sur le serveur (l'écran le dit, et refuse
  un indice égal au mot de passe). Inscriptions fermées, Vaultwarden 1.37.4
  n'accepte que : le jeton signé du lien d'invitation (serveur avec
  courriel ; l'adresse doit être celle de l'invitation), ou un jeton de
  vérification qu'il ne rend directement qu'aux adresses invitées d'un
  serveur sans courriel. Le lien collé est lu dans Rust ; son jeton ne sert
  qu'à l'inscription et à l'acceptation, et n'est pas gardé au-delà de la
  session. Limite connue : le mot de passe saisi passe par une `String`
  Swift (comme à la connexion).

## Envois (Bitwarden Send)

- **Cryptographie** : celle du SDK (`bitwarden-send`), comme le coffre web.
  Chaque envoi a sa clé, 16 octets tirés au hasard ; HKDF-SHA256 (sel
  `bitwarden-send`, info `send`) en dérive la clé de 64 octets qui chiffre
  le nom, les notes, le texte, le nom du fichier et son contenu. La clé de
  l'envoi est gardée sur le serveur chiffrée par la clé de l'utilisateur.
  Des tests recalculent la dérivation et le hachage du mot de passe sans le
  SDK.
- **Fichiers** : le contenu forme un seul `EncArrayBuffer` (type 2, IV,
  MAC, texte chiffré), chiffré directement par la clé de l'envoi, comme les
  apps Bitwarden ; le serveur ne voit ni le nom (le fichier envoyé porte le
  nom chiffré) ni le contenu, seulement la taille chiffrée. Envoi en deux
  temps (`POST /api/sends/file/v2`, puis le contenu à l'adresse rendue, qui
  doit être sur le serveur du compte) ; si le second temps échoue, l'envoi
  est supprimé. Repli sur l'ancien `POST /api/sends/file` pour un serveur
  sans v2. 100 Mo au plus, vérifiés avant tout chiffrement ; le quota du
  serveur (`USER_SEND_LIMIT`) s'applique en plus. Un fichier n'est lu par
  Swift qu'à la création, puis passé à Rust (copie `Data` non mise à zéro,
  comme pour les pièces jointes). Le fichier d'un envoi ne change jamais :
  une modification ne touche qu'aux réglages. Des tests vérifient
  l'aller-retour avec la seule clé du lien et qu'un octet altéré fait tout
  refuser ; un test d'intégration télécharge le fichier comme un
  destinataire anonyme (avec et sans mot de passe) et compare les octets.
- **Lien** : `<serveur>/#/send/<accès>/<clé>`. La clé suit le `#` : le
  navigateur du destinataire ne l'envoie jamais au serveur. Le lien donne
  donc le contenu : Verrou le copie comme un secret (presse-papiers masqué,
  effacé après 90 s) et ne le garde pas. Swift ne reçoit le lien et le texte
  d'un envoi que sur demande (copie, écran de modification) ; la liste n'en
  porte que le nom, les compteurs et les dates.
- **Mot de passe** : jamais envoyé ; seulement son empreinte (PBKDF2-SHA256,
  100 000 itérations, salé par la clé de l'envoi), que le serveur compare.
  Une modification sans nouveau mot de passe garde l'ancien ; le retirer est
  une action à part (`PUT /api/sends/{id}/remove-password`).
- **Depuis un élément** (« Envoyer de façon sécurisée… ») : le champ ne sort
  du cœur Rust qu'après la confirmation d'un élément protégé, et l'envoi
  prérempli (masqué chez le destinataire, un seul accès, 7 jours) attend
  la validation de l'utilisateur.
- **Depuis une pièce jointe** (même action, section « Pièces jointes ») :
  la pièce jointe est téléchargée, déchiffrée (clé de la pièce jointe, MAC
  vérifié) puis chiffrée de nouveau par la clé de l'envoi, entièrement dans
  Rust : son contenu en clair ne traverse pas la frontière vers Swift, et
  la mémoire est effacée à la libération. Un élément protégé demande sa
  confirmation pour préremplir l'envoi ; Rust la vérifie de nouveau à la
  création (refusée si elle a expiré entre-temps).
- **Limites** : le texte d'un envoi vit dans une `String` Swift tant que
  l'écran est ouvert ; le contenu d'un fichier choisi dans le Finder passe
  par une `Data` Swift non mise à zéro. Verrou ne télécharge pas d'envoi
  reçu (la réception, dans le cœur Rust, ne sert qu'aux tests).

## Passkeys dans Brave et Firefox

```
page ──postMessage──▶ passkeys.js ──▶ arrière-plan ──pont chiffré──▶ Verrou (signe)
```

- **Interception** : `passkey-page.js`, injecté dans la page (monde MAIN)
  avant ses scripts, fait passer `navigator.credentials.create` et `.get`
  (avec `publicKey`) par Verrou. Il ne détient rien : il relaie des options
  que la page pourrait donner elle-même au navigateur, et rend la réponse.
  Cadre principal seulement.
- **Remplissage automatique** (`mediation: "conditional"`) : la demande reste
  en attente dans `passkeys.js`, et la pastille de `content.js` (même monde
  isolé de l'extension : la page n'atteint ni l'un ni l'autre) propose en
  premier la passkey de Verrou pour ce site (« Se connecter avec une
  passkey »), les autres dans son onglet. Seul un vrai clic ou une vraie touche (`isTrusted`) les
  choisit ; la signature suit le même chemin qu'une demande explicite
  (Touch ID si demandé, élément protégé, compteur). La page annule
  (`AbortSignal`) ou lance une autre demande : la passkey quitte la pastille.
  Sans passkey de Verrou pour ce site, ou Verrou injoignable ou non relié, la
  demande passe aussitôt au navigateur.
- **Choix de l'utilisateur** : la fenêtre de Verrou (shadow DOM fermé, clics
  réels seulement) propose les passkeys du site, ou d'en enregistrer une
  (dans un identifiant du site, ou un nouveau). « Utiliser le navigateur »
  rend la main à l'implémentation d'origine, avec les mêmes options ; sans
  passkey pour ce site, c'est le navigateur d'emblée. Quand Verrou ne peut pas
  prendre une demande explicite (injoignable, extension non reliée ou rechargée
  depuis, type de clé non géré), elle passe au navigateur et un avis discret
  le dit : jamais de repli silencieux.
- **Origine et site** : l'adresse vient du navigateur (`sender.url`, cadre
  principal), jamais de la page. Le cœur Rust (`verrou-core/src/passkey.rs`)
  en tire l'origine écrite dans `clientDataJSON` et vérifie le `rpId` : l'hôte
  de la page ou l'un de ses domaines parents, jamais un suffixe public (Public
  Suffix List), jamais une adresse IP. Une passkey ne signe que pour son
  `rpId`. HTTPS seulement (HTTP vers `localhost`), coffre déverrouillé.
- **Clé privée** : créée dans Rust (P-256, `OsRng`), gardée chiffrée dans
  l'identifiant au format de Bitwarden (`login.fido2Credentials`, PKCS#8 en
  base64url, chaque champ chiffré par le SDK) : les apps Bitwarden et le
  coffre web la relisent, et Verrou utilise celles qu'elles ont créées. Elle
  ne traverse ni la frontière Swift (l'app ne voit que site, utilisateur et
  date), ni le pont : l'extension ne reçoit que la clé publique,
  l'attestation et les signatures. Signature ES256 (`p256` de RustCrypto) de
  `authenticatorData ‖ SHA-256(clientDataJSON)`.
- **Attestation** : `none`, ou `packed` auto-signée si le site demande
  `direct`/`enterprise` ; AAGUID nul (Verrou ne se fait passer pour aucun
  modèle). Indicateurs « sauvegardable » et « sauvegardée » : la passkey est
  synchronisée par le coffre.
- **Vérification de l'utilisateur** : si le site la demande (`required` ou
  `preferred`, le défaut), Verrou demande Touch ID (ou le mot de passe de la
  session) avant de signer ou de créer, et seulement alors pose l'indicateur
  UV ; l'accord vaut 5 minutes pour cette extension et cet élément. Sinon,
  le clic dans la fenêtre de Verrou vaut présence. Un élément protégé
  (« redemander le mot de passe principal ») attend sa confirmation, comme
  au remplissage.
- **Compteur** : augmenté à chaque signature et enregistré sur le serveur
  avant que la réponse parte ; hors ligne, la passkey ne signe pas. Seule
  exception : un élément partagé en lecture seule, dont le compteur reste
  celui du serveur.
- **Une passkey par identifiant**, comme Bitwarden : en enregistrer une dans
  un identifiant qui en a déjà une la remplace (la fenêtre le dit). Une
  passkey que le site exclut (`excludeCredentials`) et que le coffre contient
  déjà n'est pas recréée (`InvalidStateError`).
- **Limites connues** : clés ES256 seulement (un site qui n'accepte pas ES256
  passe par le navigateur) ; pas d'extensions WebAuthn (PRF, `largeBlob`) ;
  pas de passkey dans les cadres ; pendant
  une demande de Touch ID, les autres requêtes de l'extension attendent.

## Éléments protégés et audit

- **« Redemander le mot de passe principal »** (réglage Bitwarden d'un
  élément) : le cœur Rust refuse ses secrets (`reveal`, codes, brouillon de
  modification, remplissage dans le navigateur) tant que l'utilisateur n'a pas
  confirmé, par Touch ID ou par le mot de passe principal (vérifié hors ligne
  sur le cache). Une confirmation vaut 5 minutes pour cet élément et
  s'efface au verrouillage. Depuis le navigateur, Verrou demande la confirmation et
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
- **« Changer le mot de passe »** : pour une poignée de grands sites (Google,
  GitHub, Amazon, Microsoft, Apple, Facebook, X, LinkedIn, Dropbox), la page
  est connue d'avance, sans requête. Pour les autres, le cœur Rust vérifie si
  le site suit la norme du W3C « A Well-Known URL for Changing Passwords » :
  `/.well-known/change-password` doit répondre « OK » (après redirections) et
  `/.well-known/resource-that-should-not-exist-whose-status-code-should-not-be-200`
  ne doit pas répondre « OK » ; sur l'hôte de l'élément, puis son domaine
  enregistrable. Seulement au clic, pour cet élément seul, jamais en masse :
  les requêtes ne partent que vers le site que l'utilisateur s'apprête à
  ouvrir, qui n'apprend donc rien de plus. HTTPS seulement (une redirection
  vers HTTP n'est pas suivie), sans cookie ni `Referer`, délai de 5 s, corps
  des réponses non lu. À défaut, l'accueil du site s'ouvre. Aucun secret
  n'est envoyé : le nouveau mot de passe est proposé puis enregistré par
  l'extension, comme d'habitude.
- **Fuites et mots de passe changés** : le cœur Rust garde en mémoire
  l'empreinte SHA-256 du mot de passe de chaque identifiant trouvé dans des
  fuites, au moment de la vérification ; un mot de passe changé depuis
  (Verrou, extension, synchronisation) sort de la liste sans nouvelle
  requête. Ces empreintes ne sont jamais écrites sur le disque et s'effacent
  au verrouillage.

## Générateur de mots de passe et de phrases de passe

- **Hasard** : générateur du système (`OsRng`, c'est-à-dire `getrandom`) ;
  une source déterministe ne sert qu'aux données fictives et aux tests.
- **Mots de passe** : au moins un caractère de chaque classe demandée,
  caractères ambigus (`l`, `I`, `O`, `0`, `1`) exclus, de 8 à 128 caractères.
- **Phrases de passe** : 3 à 20 mots (5 par défaut) tirés dans une liste
  embarquée à la compilation, la liste française de Tango pour Tails et Tor
  (CC0, 7 775 mots distincts) ou la grande liste de l'EFF (CC BY 3.0 US,
  7 776 mots), voir `crates/verrou-core/wordlists/NOTICE`. Chaque mot est
  tiré uniformément par rejet (pas de biais de modulo), un test du χ² le
  vérifie. Options : séparateur (`-`, espace, `.`, `_`, `,` ou un chiffre au
  hasard), majuscule initiale, un chiffre ajouté à un mot tiré au hasard.
- **Entropie affichée** : exacte pour une phrase de passe, log2(taille de la
  liste) par mot, plus log2(10) + log2(nombre de mots) pour le chiffre, plus
  log2(10) par séparateur chiffre ; la majuscule n'ajoute rien. 5 mots
  donnent environ 64,6 bits, 6 mots 77,5 bits. Elle suppose que l'attaquant
  connaît la liste et les réglages. La jauge de l'éditeur n'utilise cette
  valeur que tant que le champ contient la phrase générée ; ailleurs (audit,
  phrase tapée à la main), l'estimation d'après les caractères reste, et
  surestime une phrase de passe.
- **Extension** : la suggestion de mot de passe fort dans les pages reste un
  mot de passe aléatoire (les sites refusent souvent les espaces).

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
- **Nouvelles clés SSH** : tirées dans le cœur Rust (Ed25519, ou RSA 4096 ;
  générateur du système, `getrandom`), rangées comme un élément « clé SSH »
  de Bitwarden (clé privée OpenSSH sans phrase de passe, protégée par le
  chiffrement du coffre comme le reste). La clé privée ne passe jamais par
  Swift : l'app ne reçoit que l'identifiant de l'élément créé.
- **Signatures git** : `ssh-keygen -Y sign` (que git appelle en
  `gpg.format=ssh`) fait signer à l'agent un bloc « SSHSIG » qui porte son
  espace de noms. Quand il vaut `git`, Verrou le dit (« signer un commit git
  avec la clé « titre » ») et l'accord est **distinct** de celui de `ssh` :
  accepter une connexion ne laisse pas signer de commits pendant 5 minutes,
  ni l'inverse. Le contenu signé reste choisi par le programme qui le
  demande : l'accord ne montre pas le commit. Une authentification SSH ne
  peut pas passer pour une signature git (elle commence par la longueur de
  l'identifiant de session, jamais par « SSHSIG »). `verrou git-signing`
  n'écrit la configuration de git qu'avec `--apply`, et n'y met que la clé
  publique.
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
