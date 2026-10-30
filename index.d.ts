// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type Band = 'uhf' | 's' | 'x' | 'ku' | 'ka' | 'optical';
export type PassKind = 'telemetry' | 'command' | 'ranging' | 'payload';
export type Action = 'inspection' | 'repair' | 'calibration' | 'upgrade';
export type RecordType = 'register' | 'license' | 'pass' | 'maintenance' | 'decommission';

export interface KeyDescription {
  format: 'qground-key/1';
  algorithm: 'ML-DSA-65';
  id: string;
  publicKey: string;
}

export interface Signer {
  id: string;
  publicKey: string;
}

export interface Envelope<T = Record<string, unknown>> {
  format: 'qground/1';
  type: RecordType;
  algorithm: 'ML-DSA-65';
  signer: Signer;
  statement: T;
  signature: string;
  anchor?: unknown;
}

export interface RegisterOptions {
  key: Uint8Array;
  stationName: string;
  location: string;
  band: Band;
  operatorLabel?: string;
  registeredAt?: string;
  note?: string;
}

export interface LicenseOptions {
  key: Uint8Array;
  register: Envelope;
  authorityLabel?: string;
  licensedAt?: string;
  note?: string;
}

export interface PassOptions {
  key: Uint8Array;
  record: Envelope;
  passKind: PassKind;
  target: string;
  controllerLabel?: string;
  contactedAt?: string;
  note?: string;
}

export interface MaintenanceOptions {
  key: Uint8Array;
  record: Envelope;
  action: Action;
  engineerLabel?: string;
  performedAt?: string;
  note?: string;
}

export interface DecommissionOptions {
  key: Uint8Array;
  record: Envelope;
  reason: string;
  decommissionedAt?: string;
  note?: string;
}

export interface AnchorOptions {
  seed?: Uint8Array;
  index?: number;
  network?: string;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
  maxFee?: string | number | bigint;
  meter?: string | number | bigint;
  timeoutMs?: number;
  onPending?: (pending: unknown) => void;
  signal?: AbortSignal;
}

export interface VerifyOptions {
  type?: RecordType;
  prior?: Envelope;
  groundId?: string;
  signerKeyId?: string;
  signerPublicKey?: string | Uint8Array;
  network: string;
  strict?: boolean;
  requireAnchor?: boolean;
  maxAnchorDelay?: number;
  at?: string;
  deadlineMs?: number;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
}

export interface Check {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
  indeterminate: boolean;
  unproven: boolean;
}

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'unproven' | 'indeterminate' | 'invalid';
  type: RecordType | null;
  groundId?: string;
  signerId?: string;
  statement?: Record<string, unknown>;
  anchoredAt?: string | null;
  endpoints: string[];
  officialEndpoints: boolean | null;
  checks: Check[];
}

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function stationRef(secret: Uint8Array, reference: string): string;
export function register(options: RegisterOptions): Envelope;
export function license(options: LicenseOptions): Envelope;
export function pass(options: PassOptions): Envelope;
export function maintenance(options: MaintenanceOptions): Envelope;
export function decommission(options: DecommissionOptions): Envelope;
export function anchor(envelopes: Envelope | Envelope[], options: AnchorOptions): Promise<Envelope[]>;
export function complete(envelopes: Envelope | Envelope[], pending: unknown, options?: AnchorOptions): Promise<Envelope[]>;
export function verify(envelope: Envelope, options: VerifyOptions): Promise<VerifyResult>;
export function anchorDigest(envelope: Envelope): string;
export function recordRef(envelope: Envelope): string;

export const FORMAT: 'qground/1';
export const ALGORITHM: 'ML-DSA-65';
export const KIND: 1409;
export const TYPES: readonly RecordType[];
export const BANDS: readonly Band[];
export const PASS_KINDS: readonly PassKind[];
export const ACTIONS: readonly Action[];
export const PUBLIC_KEY_BYTES: 1952;
export const SIGNATURE_BYTES: 3309;
