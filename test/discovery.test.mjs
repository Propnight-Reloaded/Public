import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { keygen, sign, verify, validate } from '../tools/discovery.mjs';

const doc = () => JSON.parse(fs.readFileSync(new URL('../discovery.json', import.meta.url), 'utf8'));

test('a signature verifies with its key and fails with another', () => {
  const key = keygen();
  const other = keygen();
  const data = Buffer.from('{"serial":1}');
  const sig = sign(data, key, 'timestamp:1\tfile:discovery.json');
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

test('the published discovery.json is valid and signed by a key of keys.json', () => {
  assert.deepEqual(validate(doc()), []);
  const keys = JSON.parse(fs.readFileSync(new URL('../keys.json', import.meta.url), 'utf8')).keys.map((k) => k.public_key);
  const sig = fs.readFileSync(new URL('../discovery.json.minisig', import.meta.url), 'utf8');
  assert.equal(verify(fs.readFileSync(new URL('../discovery.json', import.meta.url)), sig, keys), true);
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
