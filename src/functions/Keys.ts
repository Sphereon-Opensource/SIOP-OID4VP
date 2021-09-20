import { keyUtils as ed25519KeyUtils } from '@transmute/did-key-ed25519';
import * as bs58 from 'bs58';
import { decodeJWT } from 'did-jwt';
// import { verifyES256K } from 'did-JWT/src/VerifierAlgorithm';
import { VerificationMethod } from 'did-resolver';
import { ec as EC } from 'elliptic';
import eth_crypto from 'eth-crypto';
import jwtVerify from 'jose/jwt/verify';
import parseJwk from 'jose/jwk/parse';
import { JWK } from 'jose/types';
import Base64 from 'js-base64';
import SHA from 'sha.js';

import { SIOP } from '../types';
import SIOPErrors from '../types/Errors';
import { DIDDocument } from '../types/SSI.types';

import { base64ToBytes, base64ToHexString, base64urlEncodeBuffer, bytesToHexString, isHexString } from './Encodings';

const ED25519_DID_KEY = 'did:key:z6Mk';

export function isEd25519DidKeyMethod(did?: string) {
  return did && did.includes(ED25519_DID_KEY);
}

export function isEd25519JWK(jwk: JWK): boolean {
  return jwk && jwk.crv && jwk.crv === SIOP.KeyCurve.ED25519;
}

export function getHexPrivateKey(key: JWK): string {
  const privateKeyHex = Buffer.from(key.d, 'base64').toString('hex');
  return `0x${privateKeyHex}`;
}

export function getPublicJWKFromHexPublicHex(hexPublicKey: string, kid?: string, method?: string): JWK {
  if (isEd25519DidKeyMethod(method)) {
    return getPublicJWKFromDIDHexPublicKey(hexPublicKey);
  }
  const ec = new EC('secp256k1');
  const key = ec.keyFromPublic(hexPublicKey.replace('0x', ''), 'hex');
  const pubPoint = key.getPublic();

  return {
    kid,
    kty: SIOP.KeyType.EC,
    crv: SIOP.KeyCurve.SECP256k1,
    x: Base64.fromUint8Array(pubPoint.getX().toArrayLike(Buffer), true),
    y: Base64.fromUint8Array(pubPoint.getY().toArrayLike(Buffer), true),
  };
}

export function getPublicJWKFromDIDHexPublicKey(hexPublicKey: string): JWK {
  // Convert the key to base58 in order to get the jwk with another method from library Keys
  const publicKeyBase58 = ed25519KeyUtils.publicKeyBase58FromPublicKeyHex(hexPublicKey) as string;
  return ed25519KeyUtils.publicKeyJwkFromPublicKeyBase58(publicKeyBase58);
}

export function getBase58PrivateKeyFromHexPrivateKey(hexPrivateKey: string): string {
  return ed25519KeyUtils.privateKeyBase58FromPrivateKeyHex(hexPrivateKey);
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

function compareKidWithId(kid: string, elem: VerificationMethod): boolean {
  // kid can be "kid": "H7j7N4Phx2U1JQZ2SBjczz2omRjnMgT8c2gjDBv2Bf0="
  // or "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#keys-1
  if (kid.includes('did:') || kid.startsWith('#')) {
    return elem.id === kid;
  }
  return elem.id.split('#')[1] === kid;
}

export function getVerificationMethod(kid: string, didDoc: DIDDocument): VerificationMethod {
  if (!didDoc || !didDoc.verificationMethod || didDoc.verificationMethod.length < 1) {
    throw new Error(SIOPErrors.ERROR_RETRIEVING_VERIFICATION_METHOD);
  }

  const { verificationMethod } = didDoc;
  // Get the kid from the publicKeyJwk, if it does not exist (verifyDidAuthRequest) compare with the id
  return verificationMethod.find((elem) =>
    elem.publicKeyJwk ? elem.publicKeyJwk.kid === kid : compareKidWithId(kid, elem)
  );
}

export function verifyJWTSignatureFromVerificationMethod(
  jwt: string,
  verificationMethods: VerificationMethod
): Promise<VerificationMethod> {
  const { header } = decodeJWT(jwt);
  let verificationMethod;

  if (header.alg === SIOP.KeyAlgo.EDDSA || header.alg === SIOP.KeyAlgo.EDDSA) {
    verificationMethod = verifyEDDSA(jwt, verificationMethods);
  } else if (header.alg === SIOP.KeyAlgo.ES256K) {
    verificationMethod = verifyES256K(jwt, verificationMethods) != null;
  } else {
    console.error(`Key algorithm not supported: ${header.alg}`);
  }
  return verificationMethod;
}

function toJWK(kid: string, crv: SIOP.KeyCurve, pubPoint: EC.BN) {
  return {
    kid,
    kty: SIOP.KeyType.EC,
    crv: crv,
    x: Base64.fromUint8Array(pubPoint.getX().toArrayLike(Buffer), true),
    y: Base64.fromUint8Array(pubPoint.getY().toArrayLike(Buffer), true),
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
  const pubkeyBytes = bs58.decode(ed25519KeyUtils.publicKeyBase58FromPublicKeyJwk(jwk));
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
    isEd25519DidKeyMethod(did)
      ? getPublicED25519JWKFromHexPrivateKey(hexPrivateKey)
      : getPublicJWKFromHexPrivateKey(hexPrivateKey),
    did
  );
}

function extractPublicKeyBytes(vm: VerificationMethod): string | { x: string; y: string } {
  if (vm.publicKeyBase58) {
    return bs58.decode(vm.publicKeyBase58).toString('hex');
  }

  if (vm.publicKeyJwk) {
    return {
      x: isHexString(vm.publicKeyJwk.x) ? vm.publicKeyJwk.x : base64ToHexString(vm.publicKeyJwk.x),
      y: isHexString(vm.publicKeyJwk.x) ? vm.publicKeyJwk.y : base64ToHexString(vm.publicKeyJwk.y),
    };
  }
  throw new Error('No public key found!');
}

export interface EcdsaSignature {
  r: string;
  s: string;
  recoveryParam?: number | null;
}

// converts a JOSE signature to it's components
export function toSignatureObject(signature: string, recoverable = false): EcdsaSignature {
  const rawSig: Uint8Array = base64ToBytes(signature);
  if (rawSig.length !== (recoverable ? 65 : 64)) {
    throw new Error('wrong signature length');
  }
  const r: string = bytesToHexString(rawSig.slice(0, 32));
  const s: string = bytesToHexString(rawSig.slice(32, 64));
  const sigObj: EcdsaSignature = { r, s };
  if (recoverable) {
    sigObj.recoveryParam = rawSig[64];
  }
  return sigObj;
}

function verifyES256K(jwt: string, verificationMethod: VerificationMethod): boolean {
  const publicKey = extractPublicKeyBytes(verificationMethod);
  const secp256k1 = new EC('secp256k1');
  const { data, signature } = decodeJWT(jwt);
  const hash = SHA('sha256').update(data).digest();
  const sigObj = toSignatureObject(signature);
  return secp256k1.keyFromPublic(publicKey, 'hex').verify(hash, sigObj);
}

async function verifyEDDSA(jwt: string, verificationMethod: VerificationMethod): Promise<boolean> {
  let publicKey: JWK;
  if (verificationMethod.publicKeyBase58)
    publicKey = ed25519KeyUtils.publicKeyJwkFromPublicKeyBase58(verificationMethod.publicKeyBase58);
  if (verificationMethod.publicKeyJwk) publicKey = verificationMethod.publicKeyJwk;
  const result = await jwtVerify(jwt, await parseJwk(publicKey, SIOP.KeyAlgo.EDDSA));
  if (!result || !result.payload) throw Error(SIOPErrors.ERROR_VERIFYING_SIGNATURE);
  return true;
}

export async function encrypt(payload: { [x: string]: unknown }, publicKeyHex: string): Promise<string> {
  const encrypted = await eth_crypto.encryptWithPublicKey(publicKeyHex, JSON.stringify(payload));
  return eth_crypto.cipher.stringify(encrypted);
}

export async function decrypt(privateKey: string, encrypted: string): Promise<string> {
  const encryptedObject = eth_crypto.cipher.parse(encrypted);
  return eth_crypto.decryptWithPrivateKey(privateKey, encryptedObject);
}
