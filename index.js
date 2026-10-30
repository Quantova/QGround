// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const B = require('./lib/ground');
const { verify } = require('./lib/verify');
const F = require('./lib/format');

module.exports = {
  generateKey: B.generateKey,
  publicKey: B.publicKey,
  keyId: B.keyId,
  describeKey: B.describeKey,
  stationRef: B.stationRef,
  register: B.register,
  license: B.license,
  pass: B.pass,
  maintenance: B.maintenance,
  decommission: B.decommission,
  anchor: B.anchor,
  complete: B.complete,
  verify,
  anchorDigest: (envelope) => F.anchorDigest(F.parse(envelope)).toString('hex'),
  recordRef: (envelope) => F.refOf(F.parse(envelope)),
  FORMAT: F.FORMAT,
  ALGORITHM: F.ALGORITHM,
  KIND: F.KIND,
  TYPES: F.TYPES,
  BANDS: F.BANDS,
  PASS_KINDS: F.PASS_KINDS,
  ACTIONS: F.ACTIONS,
  PUBLIC_KEY_BYTES: F.PUBLIC_KEY_BYTES,
  SIGNATURE_BYTES: F.SIGNATURE_BYTES,
};
