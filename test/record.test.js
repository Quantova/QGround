// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');

function freshKey() {
  return Q.generateKey();
}

function registerStation(key) {
  return Q.register({ key, stationName: 'Svalbard Station 7', location: 'Svalbard', band: 'x', operatorLabel: 'Quantova Ground' });
}

test('a registered station is a well formed signed record of the operator', () => {
  const operator = freshKey();
  const s = registerStation(operator);
  assert.strictEqual(s.format, 'qground/1');
  assert.strictEqual(s.type, 'register');
  assert.strictEqual(s.algorithm, 'ML-DSA-65');
  assert.strictEqual(s.signer.id, Q.keyId(operator));
  assert.strictEqual(s.statement.operatorKeyId, Q.keyId(operator));
  assert.match(s.statement.groundId, /^[0-9a-f]{32}$/);
  assert.strictEqual(Buffer.from(s.signer.publicKey, 'base64').length, Q.PUBLIC_KEY_BYTES);
  assert.strictEqual(Buffer.from(s.signature, 'base64').length, Q.SIGNATURE_BYTES);
});

test('the license, pass and maintenance records chain to the same station', () => {
  const operator = freshKey();
  const authority = freshKey();
  const controller = freshKey();
  const s = registerStation(operator);
  const lic = Q.license({ key: authority, register: s });
  const p = Q.pass({ key: controller, record: s, passKind: 'telemetry', target: 'Quantova Sat 1' });
  const m = Q.maintenance({ key: controller, record: p, action: 'calibration' });
  assert.strictEqual(lic.statement.groundId, s.statement.groundId);
  assert.strictEqual(lic.statement.registerRef, Q.recordRef(s));
  assert.strictEqual(p.statement.priorRef, Q.recordRef(s));
  assert.strictEqual(m.statement.priorRef, Q.recordRef(p));
  assert.strictEqual(p.statement.passKind, 'telemetry');
});

test('invalid inputs are refused before anything is signed', () => {
  const key = freshKey();
  const base = { key, stationName: 'S', location: 'L', band: 'x' };
  assert.throws(() => Q.register(Object.assign({}, base, { band: 'gamma' })), /band must be one of/);
  assert.throws(() => Q.register(Object.assign({}, base, { stationName: '' })), /stationName cannot be empty/);
  assert.throws(() => Q.register(Object.assign({}, base, { unknownField: 1 })), /is not an option of register/);
  const s = registerStation(key);
  assert.throws(() => Q.pass({ key, record: s, passKind: 'gossip', target: 'T' }), /passKind must be one of/);
  assert.throws(() => Q.maintenance({ key, record: s, action: 'polish' }), /action must be one of/);
});

test('a signing key must be a well formed 32 byte seed', () => {
  assert.throws(() => registerStation(new Uint8Array(16)), /32 byte Uint8Array seed/);
  assert.throws(() => registerStation(new Uint8Array(32)), /too few different byte values/);
});

test('a well formed record verifies and a type mismatch is invalid', async () => {
  const operator = freshKey();
  const s = registerStation(operator);
  const ok = await Q.verify(s, { type: 'register', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(ok.status, 'valid');
  assert.strictEqual(ok.type, 'register');
  assert.strictEqual(ok.groundId, s.statement.groundId);
  const wrongType = await Q.verify(s, { type: 'license', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(wrongType.status, 'invalid');
  const wrongSigner = await Q.verify(s, { type: 'register', network: 'testnet', requireAnchor: false, strict: false, signerKeyId: Q.keyId(freshKey()) });
  assert.strictEqual(wrongSigner.status, 'invalid');
});

test('a tampered statement no longer verifies', async () => {
  const operator = freshKey();
  const s = registerStation(operator);
  const forged = JSON.parse(JSON.stringify(s));
  forged.statement.band = 'ka';
  const r = await Q.verify(forged, { type: 'register', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'signature' && !c.ok));
});

test('the prior link binds a record to the record before it', async () => {
  const operator = freshKey();
  const controller = freshKey();
  const s = registerStation(operator);
  const p = Q.pass({ key: controller, record: s, passKind: 'command', target: 'Quantova Sat 1' });
  const good = await Q.verify(p, { type: 'pass', network: 'testnet', requireAnchor: false, strict: false, prior: s });
  assert.ok(good.checks.some((c) => c.name === 'prior' && c.ok));
  const otherS = registerStation(operator);
  const bad = await Q.verify(p, { type: 'pass', network: 'testnet', requireAnchor: false, strict: false, prior: otherS });
  assert.strictEqual(bad.status, 'invalid');
  assert.ok(bad.checks.some((c) => c.name === 'prior' && !c.ok));
});

test('stationRef is deterministic for the same secret and reference and differs otherwise', () => {
  const secret = new Uint8Array(32);
  globalThis.crypto.getRandomValues(secret);
  const a = Q.stationRef(secret, 'SVL 07');
  const b = Q.stationRef(secret, 'SVL 07');
  const c = Q.stationRef(secret, 'SVL 08');
  assert.strictEqual(a, b);
  assert.notStrictEqual(a, c);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test('the kind and constants are the ones pinned for the ground segment line', () => {
  assert.strictEqual(Q.KIND, 1409);
  assert.strictEqual(Q.FORMAT, 'qground/1');
  assert.deepStrictEqual([...Q.TYPES], ['register', 'license', 'pass', 'maintenance', 'decommission']);
  assert.deepStrictEqual([...Q.BANDS], ['uhf', 's', 'x', 'ku', 'ka', 'optical']);
  assert.deepStrictEqual([...Q.PASS_KINDS], ['telemetry', 'command', 'ranging', 'payload']);
});
