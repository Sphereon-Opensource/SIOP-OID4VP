// import { keyUtils as ed25519KeyUtils } from '@transmute/did-key-ed25519';
import base64url from 'base64url';
import * as bs58 from 'bs58';
import { ec as EC } from 'elliptic';
import { calculateJwkThumbprint, JWK } from 'jose';

import { KeyCurve, KeyType } from '../types';

const ED25519_DID_KEY = 'did:key:z6Mk';

export const isEd25519DidKeyMethod = (did?: string) => {
  return did && did.includes(ED25519_DID_KEY);
};

export const isEd25519JWK = (jwk: JWK): boolean => {
  return jwk && !!jwk.crv && jwk.crv === KeyCurve.ED25519;
};

export const getBase58PrivateKeyFromHexPrivateKey = (hexPrivateKey: string): string => {
  return bs58.encode(Buffer.from(hexPrivateKey, 'hex'));
};

export const getPublicED25519JWKFromHexPrivateKey = (hexPrivateKey: string, kid?: string): JWK => {
  const ec = new EC('ed25519');
  const privKey = ec.keyFromPrivate(hexPrivateKey);
  const pubPoint = privKey.getPublic();

  return toJWK(kid, KeyCurve.ED25519, pubPoint);
};

const getPublicSECP256k1JWKFromHexPrivateKey = (hexPrivateKey: string, kid: string) => {
  const ec = new EC('secp256k1');
  const privKey = ec.keyFromPrivate(hexPrivateKey.replace('0x', ''), 'hex');
  const pubPoint = privKey.getPublic();
  return toJWK(kid, KeyCurve.SECP256k1, pubPoint);
};

export const getPublicJWKFromHexPrivateKey = (hexPrivateKey: string, kid?: string, did?: string): JWK => {
  if (isEd25519DidKeyMethod(did)) {
    return getPublicED25519JWKFromHexPrivateKey(hexPrivateKey, kid);
  }
  return getPublicSECP256k1JWKFromHexPrivateKey(hexPrivateKey, kid);
};

const toJWK = (kid: string, crv: KeyCurve, pubPoint: EC.BN) => {
  return {
    kid,
    kty: KeyType.EC,
    crv: crv,
    x: base64url.toBase64(pubPoint.getX().toArrayLike(Buffer)),
    y: base64url.toBase64(pubPoint.getY().toArrayLike(Buffer)),
  };
};

// from fingerprintFromPublicKey function in @transmute/Ed25519KeyPair
const getThumbprintFromJwkDIDKeyImpl = (jwk: JWK): string => {
  // ed25519 cryptonyms are multicodec encoded values, specifically:
  // (multicodec ed25519-pub 0xed01 + key bytes)
  const pubkeyBytes = base64url.toBuffer(jwk.x);
  const buffer = new Uint8Array(2 + pubkeyBytes.length);
  buffer[0] = 0xed;
  buffer[1] = 0x01;
  buffer.set(pubkeyBytes, 2);

  // prefix with `z` to indicate multi-base encodingFormat

  return base64url.encode(`z${bs58.encode(buffer)}`);
};

export const getThumbprintFromJwk = async (jwk: JWK, did: string): Promise<string> => {
  if (isEd25519DidKeyMethod(did)) {
    return getThumbprintFromJwkDIDKeyImpl(jwk);
  } else {
    return await calculateJwkThumbprint(jwk, 'sha256');
  }
};

export const getThumbprint = async (hexPrivateKey: string, did: string): Promise<string> => {
  return await getThumbprintFromJwk(
    isEd25519DidKeyMethod(did) ? getPublicED25519JWKFromHexPrivateKey(hexPrivateKey) : getPublicJWKFromHexPrivateKey(hexPrivateKey),
    did
  );
};
