# Sécurité

Verrou garde des mots de passe : chaque choix ci-dessous est délibéré, et toute
PR qui touche à l'un de ces points le dit dans sa description.

## Principes

1. **Pas de cryptographie maison.** Le chiffrement des coffres viendra des crates
   du SDK Rust de Bitwarden (le code des apps officielles), les primitives
   restantes de RustCrypto et d'Apple (CryptoKit, trousseau, Secure Enclave).
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
6. **Mode lecture seule** au début : aucune écriture vers Vaultwarden tant que la
   lecture et le remplissage n'ont pas fait leurs preuves.
7. **App sandboxée**, runtime renforcé, réseau sortant uniquement.

## État de cette version

Le coffre est **fictif** : le mot de passe principal n'est pas vérifié et le
déverrouillage Touch ID ne protège encore aucune clé. Ne pas y saisir de vraies
données.

## Signaler un problème

Ouvrir une issue privée sur ce dépôt.
