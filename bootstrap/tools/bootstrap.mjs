#!/usr/bin/env node
// Fichier de démarrage signé de Propnight Reloaded (bootstrap.json, ex-discovery.json) — zéro dépendance (Node >= 20).
//
// Le launcher lit bootstrap.json + bootstrap.json.minisig depuis plusieurs miroirs hors du domaine du projet et
// n'accepte le fichier que s'il est signé par une des clés publiques qu'il embarque. Format de signature : minisign
// (ed25519, message pré-haché en BLAKE2b-512), vérifiable aussi avec `minisign -Vm bootstrap.json -P <clé>`.
//
//   node tools/bootstrap.mjs keygen --out <dossier hors dépôt> --name primary|backup
//   node tools/bootstrap.mjs sign --key <dossier>/primary.key.json [--file bootstrap.json]
//   node tools/bootstrap.mjs verify [--file bootstrap.json] [--pub <clé base64>,...]   (défaut : keys.json)
//   node tools/bootstrap.mjs check [--file bootstrap.json]
//   node tools/bootstrap.mjs renew [--key <clé>] [--now <date ISO>]   (CI : clé dans DISCOVERY_RENEWAL_KEY)
//
// Validité : bootstrap.json porte `valid_until` (fixé à la signature hors ligne). La CI prolonge chaque semaine avec
// validity.json (signé par la clé de renouvellement, lié au SHA-256 exact de bootstrap.json), seulement si le domaine
// est toujours le nôtre (RDAP : même date d'enregistrement, pas expiré). Passé la validité, les clients coupent tous
// les services en ligne : un domaine perdu puis racheté ne reçoit rien, même si plus personne ne s'occupe du projet.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const SERVICES = ['shipgate', 'accounts', 'matches', 'website'];
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
const DAY = 24 * 3600 * 1000;
const HOST_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

function prehash(data) {
  return crypto.createHash('blake2b512').update(data).digest();
}

function rawPublicKey(publicKey) {
  return Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
}

/** Paire de clés ed25519 : clé publique au format minisign (ligne base64) + clé privée PKCS#8 */
export function keygen() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const keyId = crypto.randomBytes(8);
  const pub = Buffer.concat([Buffer.from('Ed'), keyId, rawPublicKey(publicKey)]).toString('base64');
  return { keyId: keyId.toString('hex'), publicKey: pub, privatePem: privateKey.export({ format: 'pem', type: 'pkcs8' }) };
}

/** Signature minisign (texte complet du .minisig) */
export function sign(data, key, trustedComment) {
  const privateKey = crypto.createPrivateKey(key.privatePem);
  const keyId = Buffer.from(key.keyId, 'hex');
  const signature = crypto.sign(null, prehash(data), privateKey);
  const global = crypto.sign(null, Buffer.concat([signature, Buffer.from(trustedComment, 'utf8')]), privateKey);
  return [
    'untrusted comment: Propnight Reloaded bootstrap signature',
    Buffer.concat([Buffer.from('ED'), keyId, signature]).toString('base64'),
    `trusted comment: ${trustedComment}`,
    global.toString('base64'),
    '',
  ].join('\n');
}

function publicKeyObject(raw) {
  // SPKI DER ed25519 = préfixe fixe de 12 octets + 32 octets de clé
  const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]);
  return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
}

/** true si `sigText` est une signature minisign valide de `data` par une des clés `pubs` (lignes base64) */
export function verify(data, sigText, pubs) {
  const lines = sigText.replace(/\r/g, '').split('\n');
  if (lines.length < 4 || !lines[2].startsWith('trusted comment: ')) return false;
  const blob = Buffer.from(lines[1], 'base64');
  const global = Buffer.from(lines[3], 'base64');
  if (blob.length !== 74 || global.length !== 64) return false;
  const alg = blob.subarray(0, 2).toString();
  const keyId = blob.subarray(2, 10);
  const signature = blob.subarray(10);
  const comment = Buffer.from(lines[2].slice('trusted comment: '.length), 'utf8');
  return pubs.some((pub) => {
    const pk = Buffer.from(pub, 'base64');
    if (pk.length !== 42 || pk.subarray(0, 2).toString() !== 'Ed' || !pk.subarray(2, 10).equals(keyId)) return false;
    const key = publicKeyObject(pk.subarray(10));
    const message = alg === 'ED' ? prehash(data) : alg === 'Ed' ? data : null;
    return message !== null
      && crypto.verify(null, message, key, signature)
      && crypto.verify(null, Buffer.concat([signature, comment]), key, global);
  });
}

function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/** Liste des problèmes du fichier (vide = valide). `previous` : version déjà publiée, le serial doit monter. */
export function validate(doc, previous) {
  const errors = [];
  if (!Number.isSafeInteger(doc?.serial) || doc.serial < 1) errors.push('serial : entier >= 1 attendu');
  if (typeof doc?.issued_at !== 'string' || Number.isNaN(Date.parse(doc.issued_at))) errors.push('issued_at : date ISO attendue');
  if (typeof doc?.valid_until !== 'string' || !ISO_RE.test(doc.valid_until)) errors.push('valid_until : date ISO UTC attendue (ex. 2027-01-01T00:00:00Z)');
  else if (Date.parse(doc.valid_until) <= Date.parse(doc.issued_at)) errors.push('valid_until doit être après issued_at');
  const services = doc?.services ?? {};
  for (const name of SERVICES) {
    const url = services[name];
    if (url === '') continue; // service désactivé
    if (typeof url !== 'string' || !url.startsWith('https://') || !hostOf(url)) errors.push(`services.${name} : URL https ou "" attendue`);
    else if (url.endsWith('/')) errors.push(`services.${name} : pas de / final`);
  }
  for (const name of Object.keys(services)) if (!SERVICES.includes(name)) errors.push(`services.${name} : service inconnu`);
  const revoked = doc?.revoked_hosts ?? [];
  if (!Array.isArray(revoked)) errors.push('revoked_hosts : liste attendue');
  else {
    for (const host of revoked) if (typeof host !== 'string' || !HOST_RE.test(host)) errors.push(`revoked_hosts : "${host}" n'est pas un nom d'hôte en minuscules`);
    for (const name of SERVICES) {
      const host = hostOf(services[name] ?? '');
      if (host && revoked.some((r) => host === r || host.endsWith(`.${r}`))) errors.push(`services.${name} pointe vers un hôte révoqué`);
    }
  }
  if (previous && Number.isSafeInteger(previous.serial) && doc?.serial <= previous.serial) {
    errors.push(`serial ${doc?.serial} doit dépasser celui déjà publié (${previous.serial}) : les clients refusent un serial plus petit`);
  }
  return errors;
}

export function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/** Dates RDAP d'un domaine : { registered, expires, status } */
export function rdapDates(rdap) {
  const event = (action) => (rdap?.events ?? []).find((e) => e.eventAction === action)?.eventDate;
  return { registered: event('registration'), expires: event('expiration'), status: rdap?.status ?? [] };
}

const LOST_STATUS = ['pending delete', 'redemption period', 'inactive'];

/**
 * Contenu de validity.json, ou des erreurs si un domaine n'est plus sûr. `config.domains` : [{ name, registered }]
 * attendus (renewal.json), `lookups` : { name: réponse RDAP }. La validité ne dépasse jamais l'expiration d'un domaine.
 */
export function renewal(discoveryBytes, doc, config, lookups, now) {
  const errors = [];
  const checked = {};
  let until = now.getTime() + config.days * DAY;
  for (const { name, registered } of config.domains) {
    const dates = rdapDates(lookups[name]);
    if (!dates.registered || Date.parse(dates.registered) !== Date.parse(registered)) {
      errors.push(`${name} : date d'enregistrement ${dates.registered ?? 'absente'} ≠ ${registered} (domaine perdu puis réenregistré ?)`);
      continue;
    }
    if (!dates.expires || Date.parse(dates.expires) <= now.getTime() + DAY) {
      errors.push(`${name} : expire le ${dates.expires ?? '?'} (à renouveler chez le registrar)`);
      continue;
    }
    const lost = dates.status.filter((s) => LOST_STATUS.includes(String(s).toLowerCase()));
    if (lost.length) {
      errors.push(`${name} : statut ${lost.join(', ')}`);
      continue;
    }
    checked[name] = { registered: dates.registered, expires: dates.expires };
    until = Math.min(until, Date.parse(dates.expires));
  }
  if (errors.length) return { errors };
  return {
    errors,
    validity: {
      discovery_serial: doc.serial,
      discovery_sha256: sha256(discoveryBytes),
      valid_until: new Date(Math.floor(until / 3600000) * 3600000).toISOString().replace('.000Z', 'Z'),
      checked_at: now.toISOString().replace(/\.\d+Z$/, 'Z'),
      domains: checked,
    },
  };
}

async function rdapLookup(name) {
  const bootstrap = await (await fetch('https://data.iana.org/rdap/dns.json')).json();
  const tld = name.split('.').pop();
  const base = bootstrap.services.find(([tlds]) => tlds.includes(tld))?.[1]?.[0];
  if (!base) throw new Error(`pas de serveur RDAP pour .${tld}`);
  const res = await fetch(`${base.replace(/\/$/, '')}/domain/${name}`, { headers: { accept: 'application/rdap+json' } });
  if (!res.ok) throw new Error(`RDAP ${name} : HTTP ${res.status}`);
  return res.json();
}

function parseArgs(argv) {
  const opts = {};
  for (let i = 0; i < argv.length; i++) if (argv[i].startsWith('--')) opts[argv[i].slice(2)] = argv[++i];
  return opts;
}

function fail(message) {
  console.error(`❌ ${message}`);
  process.exit(1);
}

function publishedVersion(file) {
  try {
    const rel = path.relative(process.cwd(), file).replaceAll('\\', '/');
    return JSON.parse(execFileSync('git', ['show', `HEAD:${rel}`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }));
  } catch {
    return null; // premier fichier ou hors git
  }
}

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function readKeys() {
  return JSON.parse(fs.readFileSync(path.join(ROOT, 'keys.json'), 'utf8'));
}

function defaultKeys() {
  return readKeys().keys.map((k) => k.public_key);
}

/** Clés acceptées pour validity.json : renouvellement (CI) + clés hors ligne */
function validityKeys() {
  const keys = readKeys();
  return [...(keys.renewal_keys ?? []).map((k) => k.public_key), ...keys.keys.map((k) => k.public_key)];
}

function loadKey(opts) {
  if (opts.key) return JSON.parse(fs.readFileSync(opts.key, 'utf8'));
  if (process.env.DISCOVERY_RENEWAL_KEY) return JSON.parse(process.env.DISCOVERY_RENEWAL_KEY);
  return fail('--key ou DISCOVERY_RENEWAL_KEY requis');
}

/** Vérifie validity.json par rapport à bootstrap.json : null si absent, sinon { ok, message } */
function checkValidity(file) {
  const vfile = path.join(path.dirname(file), 'validity.json');
  if (!fs.existsSync(vfile)) return null;
  const data = fs.readFileSync(vfile);
  if (!verify(data, fs.readFileSync(`${vfile}.minisig`, 'utf8'), validityKeys())) return { ok: false, message: 'validity.json : signature invalide' };
  const v = JSON.parse(data.toString('utf8'));
  if (v.discovery_sha256 !== sha256(fs.readFileSync(file))) return { ok: true, message: `validity.json concerne un autre bootstrap.json (serial ${v.discovery_serial}) : la CI le renouvellera` };
  return { ok: true, message: `validity.json valide jusqu'au ${v.valid_until}` };
}

async function main([command, ...rest]) {
  const opts = parseArgs(rest);
  const file = path.resolve(opts.file || path.join(ROOT, 'bootstrap.json'));
  if (command === 'keygen') {
    if (!opts.out || !opts.name) fail('--out et --name sont requis');
    const out = path.resolve(opts.out);
    if (out.startsWith(ROOT)) fail('la clé privée ne doit jamais être écrite dans le dépôt');
    const keyFile = path.join(out, `${opts.name}.key.json`);
    if (fs.existsSync(keyFile)) fail(`${keyFile} existe déjà`);
    fs.mkdirSync(out, { recursive: true });
    const key = keygen();
    fs.writeFileSync(keyFile, JSON.stringify(key, null, 2), { mode: 0o600 });
    fs.writeFileSync(path.join(out, `${opts.name}.pub`), `untrusted comment: minisign public key ${key.keyId.toUpperCase()}\n${key.publicKey}\n`);
    console.log(`✅ Clé privée : ${keyFile} (à sauvegarder hors ligne, jamais dans un dépôt)`);
    console.log(`Clé publique (${opts.name}) : ${key.publicKey}`);
  } else if (command === 'check' || command === 'sign') {
    const data = fs.readFileSync(file);
    const errors = validate(JSON.parse(data.toString('utf8')), publishedVersion(file));
    if (errors.length) fail(errors.join('\n   '));
    if (command === 'check') return console.log('✅ bootstrap.json valide');
    if (!opts.key) fail('--key est requis');
    const key = JSON.parse(fs.readFileSync(opts.key, 'utf8'));
    const doc = JSON.parse(data.toString('utf8'));
    const sigText = sign(data, key, `timestamp:${Math.floor(Date.now() / 1000)}\tfile:bootstrap.json\tserial:${doc.serial}`);
    if (!verify(data, sigText, defaultKeys())) fail('cette clé ne fait pas partie de keys.json : les clients refuseraient la signature');
    fs.writeFileSync(`${file}.minisig`, sigText);
    console.log(`✅ ${path.basename(file)}.minisig écrit (serial ${doc.serial})`);
  } else if (command === 'verify') {
    const pubs = opts.pub ? opts.pub.split(',') : defaultKeys();
    const ok = verify(fs.readFileSync(file), fs.readFileSync(`${file}.minisig`, 'utf8'), pubs);
    if (!ok) fail('signature invalide');
    const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
    console.log(`✅ signature valide (serial ${doc.serial}, valide jusqu'au ${doc.valid_until})`);
    const validity = checkValidity(file);
    if (validity && !validity.ok) fail(validity.message);
    if (validity) console.log(`✅ ${validity.message}`);
  } else if (command === 'renew') {
    const data = fs.readFileSync(file);
    const doc = JSON.parse(data.toString('utf8'));
    if (!verify(data, fs.readFileSync(`${file}.minisig`, 'utf8'), defaultKeys())) fail('bootstrap.json mal signé : rien à renouveler');
    const config = JSON.parse(fs.readFileSync(path.join(ROOT, 'renewal.json'), 'utf8'));
    const now = opts.now ? new Date(opts.now) : new Date();
    const lookups = {};
    for (const { name } of config.domains) lookups[name] = await rdapLookup(name);
    const { errors, validity } = renewal(data, doc, config, lookups, now);
    if (errors.length) fail(`renouvellement refusé, les clients passeront hors ligne à l'échéance :\n   ${errors.join('\n   ')}`);
    const vdata = Buffer.from(`${JSON.stringify(validity, null, 2)}\n`);
    const key = loadKey(opts);
    const sigText = sign(vdata, key, `timestamp:${Math.floor(now.getTime() / 1000)}\tfile:validity.json\tserial:${doc.serial}`);
    if (!verify(vdata, sigText, validityKeys())) fail('cette clé ne fait pas partie de keys.json');
    const vfile = path.join(path.dirname(file), 'validity.json');
    fs.writeFileSync(vfile, vdata);
    fs.writeFileSync(`${vfile}.minisig`, sigText);
    console.log(`✅ validity.json renouvelé jusqu'au ${validity.valid_until} (serial ${doc.serial})`);
  } else {
    fail('commande : keygen | sign | verify | check | renew');
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main(process.argv.slice(2));
