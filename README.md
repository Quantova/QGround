# QGround

QGround is a live production post quantum ground segment and telemetry contact record tool for space ground stations on the Quantova network. It proves the registration, license, tracked pass, maintenance and decommission of a ground station, and it lets any third party confirm that history without trusting the party that created it.

QGround proves records without disclosing them. Station identities and operational details stay private on the systems of the party that holds them. Only a salted cryptographic commitment is written to the chain, and no sensitive detail is ever published.

## What it records

Each record is a signed envelope of one of five types.

1. register, an operator states the name, location and frequency band of a ground station.
2. license, a spectrum authority licenses the station.
3. pass, a controller records a tracked contact with a named spacecraft of a stated kind.
4. maintenance, an engineer records a maintenance action on the station.
5. decommission, the holder takes the station out of service and states why.

Every record is signed with ML-DSA-65 under FIPS 204 by the party whose role it names, and each later record links to the one before it so the whole life of a station forms a chain.

## Proving the time

A record on its own carries only the claim of its signer. Anchoring a record on the Quantova network through Qstamp adds a post quantum evidence anchor that fixes the latest moment the record existed, provable against the record and the signer by anyone, without claiming a regulated timestamp status that Quantova Inc does not hold.

## Install

```
npm install @quantovainc/qground
```

## Use

```js
const qground = require('@quantovainc/qground');

const operator = qground.generateKey();
const station = qground.register({
  key: operator,
  stationName: 'Svalbard Station 7',
  location: 'Svalbard',
  band: 'x',
  operatorLabel: 'Quantova Ground',
});

const anchored = await qground.anchor(station, { seed, index: 0, network: 'testnet' });
const result = await qground.verify(anchored[0], { type: 'register', network: 'testnet' });
```

## What a record does not establish

1. It does not show that the stated facts are true. It shows only that the signer stated them and that the statement existed unchanged at a point in time.
2. It does not identify a natural or legal person. The signer is a chain address, and linking an address to an operator, authority or controller is a separate attestation.
3. The labels are text written by the signer, they are not a verified identity.

## License

Apache-2.0 OR MIT
