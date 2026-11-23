# Découverte des services Propnight Reloaded

`discovery.json` dit aux clients (launcher, qui transmet au relay) où sont les services. Il est servi **hors du domaine du projet**, pour qu'un changement ou une perte de domaine ne casse pas les clients installés :

- `https://raw.githubusercontent.com/Propnight-Reloaded/discovery/main/discovery.json`
- `https://propnight-reloaded.github.io/discovery/discovery.json` (GitHub Pages, branche `main`, racine)
- `https://cdn.jsdelivr.net/gh/Propnight-Reloaded/discovery@main/discovery.json`

Chaque miroir sert aussi `discovery.json.minisig`. Le launcher n'accepte le fichier que si :

- la signature minisign (ed25519) est faite par une des clés de `keys.json` (embarquées dans le launcher) ;
- `serial` est supérieur ou égal au dernier serial qu'il a accepté (un ancien fichier rejoué est refusé) ;
- toutes les URL sont en `https://` (ou `""` = service désactivé).

Sinon il garde le dernier fichier valide en cache, puis ses défauts compilés. Il ne contacte jamais un hôte de `revoked_hosts` (ni ses sous-domaines), même via ses défauts compilés.

## Publier un changement

```powershell
# 1. Modifier discovery.json : serial + 1, issued_at, services, revoked_hosts
node tools/discovery.mjs check
# 2. Signer avec la clé hors ligne
node tools/discovery.mjs sign --key "$env:USERPROFILE\.pnr-keys\discovery\primary.key.json"
node tools/discovery.mjs verify
# 3. Commiter discovery.json + discovery.json.minisig ensemble, pousser sur main
```

jsDelivr peut garder l'ancienne version jusqu'à 12 h ; raw.githubusercontent.com environ 5 min.

## Changer de domaine

1. Le nouveau domaine sert déjà ShipGate, Accounts et Matches (l'ancien aussi, en parallèle).
2. `discovery.json` : nouvelles URL, serial + 1. Signer, pousser.
3. Suivre dans les logs le trafic restant sur l'ancien domaine (versions de launcher).
4. Quand il n'y a plus de clients actifs dessus : ajouter l'ancien domaine à `revoked_hosts` (serial + 1), puis seulement le laisser expirer.

## Clés

- `primary` signe au quotidien ; `backup` sert si la principale est perdue ou compromise. Les deux clés privées sont hors ligne, sauvegardées séparément (gestionnaire de mots de passe + support hors ligne), jamais dans un dépôt.
- Remplacer une clé = publier un launcher qui embarque la nouvelle liste, et attendre que les joueurs soient à jour avant de retirer l'ancienne.
- Nouvelle clé : `node tools/discovery.mjs keygen --out <dossier hors dépôt> --name <nom>`.

Tests : `node --test`.
