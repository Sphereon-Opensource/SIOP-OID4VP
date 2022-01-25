// import { keyUtils as ed25519KeyUtils } from '@transmute/did-key-ed25519';
import base64url from 'base64url';
import * as bs58 from 'bs58';
import { ec as EC } from 'elliptic';
import { JWK } from 'jose/types';
import SHA from 'sha.js';

import { SIOP } from '../types';

import { base64urlEncodeBuffer } from './Encodings';

const ED25519_DID_KEY = 'did:key:z6Mk';

export function isEd25519DidKeyMethod(did?: string) {
  return did && did.includes(ED25519_DID_KEY);
}

export function isEd25519JWK(jwk: JWK): boolean {
  return jwk && !!jwk.crv && jwk.crv === SIOP.KeyCurve.ED25519;
}

export function getBase58PrivateKeyFromHexPrivateKey(hexPrivateKey: string): string {
  return bs58.encode(Buffer.from(hexPrivateKey, 'hex'));
}

export function getPublicED25519JWKFromHexPrivateKey(hexPrivateKey: string, kid?: string): JWK {
  const ec = new EC('ed25519');
  const privKey = ec.keyFromPrivate(hexPrivateKey);
  const pubPoint = privKey.getPublic();

  return toJWK(kid, SIOP.KeyCurve.ED25519, pubPoint);
}

function getPublicSECP256k1JWKFromHexPrivateKey(hexPrivateKey: string, kid: string) {
  const ec = new EC('secp256k1');
  const privKey = ec.keyFromPrivate(hexPrivateKey.replace('0x', ''), 'hex');
  const pubPoint = privKey.getPublic();
  return toJWK(kid, SIOP.KeyCurve.SECP256k1, pubPoint);
}

export function getPublicJWKFromHexPrivateKey(hexPrivateKey: string, kid?: string, did?: string): JWK {
  if (isEd25519DidKeyMethod(did)) {
    return getPublicED25519JWKFromHexPrivateKey(hexPrivateKey, kid);
  }
  return getPublicSECP256k1JWKFromHexPrivateKey(hexPrivateKey, kid);
}

function toJWK(kid: string, crv: SIOP.KeyCurve, pubPoint: EC.BN) {
  return {
    kid,
    kty: SIOP.KeyType.EC,
    crv: crv,
    x: base64url.toBase64(pubPoint.getX().toArrayLike(Buffer)),
    y: base64url.toBase64(pubPoint.getY().toArrayLike(Buffer)),
  };
}

function getThumbprintFromJwkImpl(jwk: JWK): string {
  const fields = {
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  };

  const buff = SHA('sha256').update(JSON.stringify(fields)).digest();

  return base64urlEncodeBuffer(buff);
}

// from fingerprintFromPublicKey function in @transmute/Ed25519KeyPair
function getThumbprintFromJwkDIDKeyImpl(jwk: JWK): string {
  // ed25519 cryptonyms are multicodec encoded values, specifically:
  // (multicodec ed25519-pub 0xed01 + key bytes)
  const pubkeyBytes = base64url.toBuffer(jwk.x);
  const buffer = new Uint8Array(2 + pubkeyBytes.length);
  buffer[0] = 0xed;
  buffer[1] = 0x01;
  buffer.set(pubkeyBytes, 2);

  // prefix with `z` to indicate multi-base encodingFormat

  return `z${bs58.encode(buffer)}`;
}

export function getThumbprintFromJwk(jwk: JWK, did: string): string {
  if (isEd25519DidKeyMethod(did)) {
    return getThumbprintFromJwkDIDKeyImpl(jwk);
  } else {
    return getThumbprintFromJwkImpl(jwk);
  }
}

export function getThumbprint(hexPrivateKey: string, did: string): string {
  return getThumbprintFromJwk(
    isEd25519DidKeyMethod(did) ? getPublicED25519JWKFromHexPrivateKey(hexPrivateKey) : getPublicJWKFromHexPrivateKey(hexPrivateKey),
    did
  );
}
