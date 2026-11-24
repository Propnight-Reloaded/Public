import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { keygen, sign, verify, validate, renewal, sha256 } from '../tools/bootstrap.mjs';

const doc = () => JSON.parse(fs.readFileSync(new URL('../bootstrap.json', import.meta.url), 'utf8'));

test('a signature verifies with its key and fails with another', () => {
  const key = keygen();
  const other = keygen();
  const data = Buffer.from('{"serial":1}');
  const sig = sign(data, key, 'timestamp:1\tfile:bootstrap.json');
  assert.equal(verify(data, sig, [key.publicKey]), true);
  assert.equal(verify(data, sig, [other.publicKey, key.publicKey]), true);
  assert.equal(verify(data, sig, [other.publicKey]), false);
});

test('any change to the file, the trusted comment or the signature is refused', () => {
  const key = keygen();
  const data = Buffer.from('{"serial":1}');
  const sig = sign(data, key, 'timestamp:1');
  assert.equal(verify(Buffer.from('{"serial":2}'), sig, [key.publicKey]), false);
  assert.equal(verify(data, sig.replace('timestamp:1', 'timestamp:2'), [key.publicKey]), false);
  const lines = sig.split('\n');
  const blob = Buffer.from(lines[1], 'base64');
  blob[20] ^= 1;
  lines[1] = blob.toString('base64');
  assert.equal(verify(data, lines.join('\n'), [key.publicKey]), false);
  assert.equal(verify(data, '', [key.publicKey]), false);
});

test('the published bootstrap.json is valid and signed by a key of keys.json', () => {
  assert.deepEqual(validate(doc()), []);
  const keys = JSON.parse(fs.readFileSync(new URL('../keys.json', import.meta.url), 'utf8')).keys.map((k) => k.public_key);
  const sig = fs.readFileSync(new URL('../bootstrap.json.minisig', import.meta.url), 'utf8');
  assert.equal(verify(fs.readFileSync(new URL('../bootstrap.json', import.meta.url)), sig, keys), true);
});

test('validate refuses http URLs, unknown services, revoked targets and a serial that does not go up', () => {
  const base = doc();
  assert.match(validate({ ...base, services: { ...base.services, shipgate: 'http://x.example' } }).join(), /shipgate/);
  assert.match(validate({ ...base, services: { ...base.services, cdn: 'https://x.example' } }).join(), /inconnu/);
  assert.match(validate({ ...base, revoked_hosts: ['zekyro.dev'] }).join(), /révoqué/);
  assert.match(validate({ ...base, revoked_hosts: ['https://zekyro.dev'] }).join(), /nom d'hôte/);
  assert.match(validate(base, { serial: base.serial }).join(), /serial/);
  assert.deepEqual(validate({ ...base, serial: base.serial + 1 }, { serial: base.serial }), []);
  assert.deepEqual(validate({ ...base, services: { ...base.services, matches: '' } }), []);
});

test('validate requires valid_until after issued_at', () => {
  const base = doc();
  assert.match(validate({ ...base, valid_until: undefined }).join(), /valid_until/);
  assert.match(validate({ ...base, valid_until: '2026-01-01T00:00:00Z' }).join(), /après issued_at/);
});

const config = { days: 45, domains: [{ name: 'zekyro.dev', registered: '2026-02-12T19:46:27.100Z' }] };
const rdap = (registered, expires, status = ['client transfer prohibited']) => ({
  status,
  events: [{ eventAction: 'registration', eventDate: registered }, { eventAction: 'expiration', eventDate: expires }],
});

test('renewal extends 45 days, never past the domain expiry, bound to the exact bootstrap.json', () => {
  const bytes = Buffer.from('{"serial":2}');
  const now = new Date('2026-11-23T18:30:00Z');
  const ok = renewal(bytes, { serial: 2 }, config, { 'zekyro.dev': rdap('2026-02-12T19:46:27.100Z', '2027-02-12T19:46:27.100Z') }, now);
  assert.deepEqual(ok.errors, []);
  assert.equal(ok.validity.valid_until, '2027-01-07T18:00:00Z');
  assert.equal(ok.validity.discovery_sha256, sha256(bytes));
  const late = renewal(bytes, { serial: 2 }, config, { 'zekyro.dev': rdap('2026-02-12T19:46:27.100Z', '2026-12-01T10:20:00Z') }, now);
  assert.equal(late.validity.valid_until, '2026-12-01T10:00:00Z');
});

test('renewal is refused when the domain expired, was re-registered by someone else or is being deleted', () => {
  const bytes = Buffer.from('{}');
  const now = new Date('2027-02-13T00:00:00Z');
  const expired = renewal(bytes, { serial: 2 }, config, { 'zekyro.dev': rdap('2026-02-12T19:46:27.100Z', '2027-02-12T19:46:27.100Z') }, now);
  assert.match(expired.errors.join(), /expire/);
  const rebought = renewal(bytes, { serial: 2 }, config, { 'zekyro.dev': rdap('2027-04-01T00:00:00Z', '2028-04-01T00:00:00Z') }, now);
  assert.match(rebought.errors.join(), /enregistrement/);
  const deleting = renewal(bytes, { serial: 2 }, config, { 'zekyro.dev': rdap('2026-02-12T19:46:27.100Z', '2028-02-12T00:00:00Z', ['pending delete']) }, now);
  assert.match(deleting.errors.join(), /pending delete/);
  assert.match(renewal(bytes, { serial: 2 }, config, {}, now).errors.join(), /absente/);
});

// Après un changement de bootstrap.json, validity.json concerne l'ancien fichier jusqu'au passage de la CI (renew.yml)
test('the published validity.json is signed by a renewal key', () => {
  const keys = JSON.parse(fs.readFileSync(new URL('../keys.json', import.meta.url), 'utf8'));
  const data = fs.readFileSync(new URL('../validity.json', import.meta.url));
  const sig = fs.readFileSync(new URL('../validity.json.minisig', import.meta.url), 'utf8');
  assert.equal(verify(data, sig, keys.renewal_keys.map((k) => k.public_key)), true);
});
