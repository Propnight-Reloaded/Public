# Démarrage du launcher : `bootstrap.json`

`bootstrap.json` dit aux clients (launcher, qui transmet au relay) où sont les services. Il est servi **hors du domaine du projet**, pour qu'un changement ou une perte de domaine ne casse pas les clients installés :

- `https://raw.githubusercontent.com/Propnight-Reloaded/Public/main/bootstrap/bootstrap.json`
- `https://propnight-reloaded.github.io/Public/bootstrap/bootstrap.json` (GitHub Pages, tout le dépôt)
- `https://cdn.jsdelivr.net/gh/Propnight-Reloaded/Public@main/bootstrap/bootstrap.json`

Chaque miroir sert aussi `bootstrap.json.minisig`, `validity.json` et `validity.json.minisig`. Le launcher n'accepte le fichier que si :

- la signature minisign (ed25519) est faite par une des clés de `keys.json` (embarquées dans le launcher) ;
- `serial` est supérieur ou égal au dernier serial qu'il a accepté (un ancien fichier rejoué est refusé) ;
- toutes les URL sont en `https://` (ou `""` = service désactivé).

Sinon il garde le dernier fichier valide en cache, puis ses défauts compilés. Il ne contacte jamais un hôte de `revoked_hosts` (ni ses sous-domaines), même via ses défauts compilés.

## Validité (coupure automatique si le projet est abandonné)

- `bootstrap.json` porte `valid_until`, fixé à la signature hors ligne (au plus tard l'expiration du domaine).
- `validity.json` prolonge cette date. Le workflow `renew.yml` le régénère chaque semaine, signé par la clé de renouvellement (secret `DISCOVERY_RENEWAL_KEY`), **seulement si** chaque domaine de `renewal.json` a toujours la même date d'enregistrement (RDAP) et n'est pas expiré. La validité vaut au plus 45 jours, et jamais au-delà de l'expiration du domaine.
- `validity.json` contient le SHA-256 exact de `bootstrap.json` : la clé de renouvellement ne peut que prolonger les adresses signées hors ligne, jamais en changer.
- Validité dépassée (domaine non renouvelé, CI arrêtée) : le launcher coupe tout ce qui est en ligne (ShipGate, comptes, matchs, liens du site). Le jeu reste jouable avec les fichiers déjà installés.
- Un échec du workflow (email de GitHub) veut dire : renouveler le domaine, ou mettre à jour `renewal.json` / `bootstrap.json`.
- Sans `DISCOVERY_RENEWAL_KEY` (ou à la main) : `node tools/bootstrap.mjs renew --key "$env:USERPROFILE\.pnr-keys\discovery\renewal.key.json"`.

## Arrêter le projet

But : les joueurs qui ont déjà le jeu installé continuent à jouer. Les nouveaux joueurs ne peuvent plus installer les fichiers du mod, et tout ce qui est en ligne est perdu (comptes, codes de skins, signalements, mises à jour).

**Rien n'est obligatoire.** On peut couper le VPS du jour au lendemain :

- Le launcher reprend les fichiers du jeu depuis son cache. Le relay garde la dernière liste de bans et ne fait plus attendre les parties. La progression des joueurs (pièces, skins, quêtes) est dans leur sauvegarde locale, et le launcher en garde des copies (`save-backups`).
- Au plus tard 45 jours après le dernier renouvellement réussi (domaine plus renouvelé, ou workflow arrêté), la validité expire. Le launcher ne contacte alors plus aucun service. Les parties passent par Steam et continuent.
- Les testeurs bêta repassent sur la dernière stable, qui est déjà en cache.

Pour tout couper tout de suite au lieu d'attendre l'expiration : publier un `bootstrap.json` dont tous les services valent `""` (serial + 1, signé avec la clé principale, voir « Publier un changement »).

À ne pas faire :

- Ne pas supprimer l'organisation GitHub, ni ce dépôt, avant que la validité ait expiré. Sinon les launchers retombent sur leur dernier fichier en cache, puis sur leurs adresses compilées, jusqu'à `PNR_DOMAIN_VALID_UNTIL`.
- Ne pas laisser le domaine être réenregistré par quelqu'un d'autre tant que des launchers le considèrent comme valide. La validité ne dépasse jamais la date d'expiration du domaine.

Prérequis : avant l'arrêt, les joueurs doivent avoir un launcher qui gère la découverte (PR « domain independence ») et les correctifs hors ligne (launcher `fix/offline-play`, relay `fix/offline-resilience`). Les launchers plus anciens contactent `*.zekyro.dev` pour toujours.

## Publier un changement

```powershell
# 1. Modifier bootstrap.json : serial + 1, issued_at, valid_until (≤ expiration du domaine), services, revoked_hosts
node tools/bootstrap.mjs check
# 2. Signer avec la clé hors ligne
node tools/bootstrap.mjs sign --key "$env:USERPROFILE\.pnr-keys\discovery\primary.key.json"
node tools/bootstrap.mjs verify
# 3. Commiter bootstrap.json + bootstrap.json.minisig ensemble, pousser sur main (renew.yml produit le validity.json correspondant)
```

jsDelivr peut garder l'ancienne version jusqu'à 12 h ; raw.githubusercontent.com environ 5 min.

## Changer de domaine

1. Le nouveau domaine sert déjà ShipGate, Accounts et Matches (l'ancien aussi, en parallèle).
2. `bootstrap.json` : nouvelles URL, serial + 1. `renewal.json` : ajouter le nouveau domaine (date `registration` de son RDAP). Signer, pousser.
3. Suivre dans les logs le trafic restant sur l'ancien domaine (versions de launcher).
4. Quand il n'y a plus de clients actifs dessus : ajouter l'ancien domaine à `revoked_hosts` (serial + 1), le retirer de `renewal.json`, puis seulement le laisser expirer.

## Clés

- `renewal` (`renewal_keys`) ne signe que `validity.json`. Sa clé privée est dans le secret CI `DISCOVERY_RENEWAL_KEY` (contenu de `renewal.key.json`). Volée, elle permet seulement de prolonger les adresses actuelles.
- `primary` signe au quotidien ; `backup` sert si la principale est perdue ou compromise. Les clés privées `primary` et `backup` sont hors ligne, sauvegardées séparément (gestionnaire de mots de passe + support hors ligne), jamais dans un dépôt.
- Remplacer une clé = publier un launcher qui embarque la nouvelle liste, et attendre que les joueurs soient à jour avant de retirer l'ancienne.
- Nouvelle clé : `node tools/bootstrap.mjs keygen --out <dossier hors dépôt> --name <nom>`.

Commandes et tests (`node --test`) à lancer depuis `bootstrap/`.
