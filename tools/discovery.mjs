#!/usr/bin/env node
// Fichier de découverte signé de Propnight Reloaded — zéro dépendance (Node >= 20).
//
// Le launcher lit discovery.json + discovery.json.minisig depuis plusieurs miroirs hors du domaine du projet et
// n'accepte le fichier que s'il est signé par une des clés publiques qu'il embarque. Format de signature : minisign
// (ed25519, message pré-haché en BLAKE2b-512), vérifiable aussi avec `minisign -Vm discovery.json -P <clé>`.
//
//   node tools/discovery.mjs keygen --out <dossier hors dépôt> --name primary|backup
//   node tools/discovery.mjs sign --key <dossier>/primary.key.json [--file discovery.json]
//   node tools/discovery.mjs verify [--file discovery.json] [--pub <clé base64>,...]   (défaut : keys.json)
//   node tools/discovery.mjs check [--file discovery.json]
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const SERVICES = ['shipgate', 'accounts', 'matches', 'website'];
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
    'untrusted comment: Propnight Reloaded discovery signature',
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

function defaultKeys() {
  return JSON.parse(fs.readFileSync(path.join(ROOT, 'keys.json'), 'utf8')).keys.map((k) => k.public_key);
}

function main([command, ...rest]) {
  const opts = parseArgs(rest);
  const file = path.resolve(opts.file || path.join(ROOT, 'discovery.json'));
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
    if (command === 'check') return console.log('✅ discovery.json valide');
    if (!opts.key) fail('--key est requis');
    const key = JSON.parse(fs.readFileSync(opts.key, 'utf8'));
    const doc = JSON.parse(data.toString('utf8'));
    const sigText = sign(data, key, `timestamp:${Math.floor(Date.now() / 1000)}\tfile:discovery.json\tserial:${doc.serial}`);
    if (!verify(data, sigText, defaultKeys())) fail('cette clé ne fait pas partie de keys.json : les clients refuseraient la signature');
    fs.writeFileSync(`${file}.minisig`, sigText);
    console.log(`✅ ${path.basename(file)}.minisig écrit (serial ${doc.serial})`);
  } else if (command === 'verify') {
    const pubs = opts.pub ? opts.pub.split(',') : defaultKeys();
    const ok = verify(fs.readFileSync(file), fs.readFileSync(`${file}.minisig`, 'utf8'), pubs);
    if (!ok) fail('signature invalide');
    console.log('✅ signature valide');
  } else {
    fail('commande : keygen | sign | verify | check');
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main(process.argv.slice(2));
