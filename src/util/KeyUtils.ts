import {keyUtils as ed25519KeyUtils} from "@transmute/did-key-ed25519";
import * as bs58 from "bs58";
import {decodeJWT} from "did-jwt";
import {verifyES256K} from "did-jwt/lib/VerifierAlgorithm";
import {VerificationMethod} from "did-resolver";
import {ec as EC} from "elliptic";
import eth_crypto from "eth-crypto";
import {JWK} from "jose/types";
import Base64 from "js-base64";
import SHA from "sha.js";

import {DidAuth} from "../types";
import {ExternalSignature, InternalSignature, NoSignature} from "../types/DidAuth-types";

import {base64urlEncodeBuffer} from "./Encodings";


const ED25519_DID_KEY = "did:key:z6Mk";

export function isEd25519DidKeyMethod(method?: string) {
    return method && method.includes(ED25519_DID_KEY);
}

export function isEd25519JWK(jwk: JWK): boolean {
    return jwk &&
        jwk.crv &&
        jwk.crv === DidAuth.KeyCurve.ED25519;
}

export function getHexPrivateKey(key: JWK): string {
    const privateKeyHex = Buffer.from(key.d, "base64").toString("hex");
    return `0x${privateKeyHex}`;
}

export function getPublicJWKFromHexPublicHex(hexPublicKey: string, kid?: string, method?: string): JWK {

    if (isEd25519DidKeyMethod(method)) {
        return getPublicJWKFromDIDHexPublicKey(hexPublicKey);
    }
    const ec = new EC("secp256k1");
    const key = ec.keyFromPublic(hexPublicKey.replace("0x", ""), "hex");
    const pubPoint = key.getPublic();

    return {
        kid,
        kty: DidAuth.KeyType.EC,
        crv: DidAuth.KeyCurve.SECP256k1,
        x: Base64.fromUint8Array(pubPoint.getX().toArrayLike(Buffer), true),
        y: Base64.fromUint8Array(pubPoint.getY().toArrayLike(Buffer), true),
    };


}

export function getPublicJWKFromDIDHexPublicKey(hexPublicKey: string): JWK {
    // Convert the key to base58 in order to get the jwk with another method from library KeyUtils
    const publicKeyBase58 = ed25519KeyUtils.publicKeyBase58FromPublicKeyHex(
        hexPublicKey
    ) as string;
    return ed25519KeyUtils.publicKeyJwkFromPublicKeyBase58(publicKeyBase58);
}

export function getPublicJWKFromDIDHexPrivateKey(hexPrivateKey: string, kid?: string): JWK {
    const ec = new EC("ed25519");
    const privKey = ec.keyFromPrivate(hexPrivateKey);
    const pubPoint = privKey.getPublic();


    return toJWK(kid, DidAuth.KeyCurve.ED25519, pubPoint);

}

export function getBase58PrivateKeyFromHexPrivateKey(hexPrivateKey: string): string {
    return ed25519KeyUtils.privateKeyBase58FromPrivateKeyHex(hexPrivateKey);
}


export function getPublicJWKFromHexPrivateKey(hexPrivateKey: string, kid?: string, method?: string): JWK {
    if (method && method.includes(ED25519_DID_KEY)) {
        return getPublicJWKFromDIDHexPrivateKey(hexPrivateKey, kid);
    }
    const ec = new EC("secp256k1");
    const privKey = ec.keyFromPrivate(hexPrivateKey.replace("0x", ""), "hex");
    const pubPoint = privKey.getPublic();
    return toJWK(kid, DidAuth.KeyCurve.SECP256k1, pubPoint);
}


export function verifyJWTSignatureFromVerificationMethods(jwt: string, verificationMethods: VerificationMethod[]): Promise<VerificationMethod> {
    const {header, signature} = decodeJWT(jwt);
    let verificationMethod;
    /*  if (header.alg === DidAuth.KeyAlgo.EDDSA || header.alg === DidAuth.KeyAlgo.EDDSA) {
          verificationMethod = verifyEd25519(jwt, signature, verificationMethods);
      } else*/
    if (header.alg === DidAuth.KeyAlgo.ES256K) {
        verificationMethod = verifyES256K(jwt, signature, verificationMethods) != null;
    } else {
        console.error(`Key algorithm not supported: ${header.alg}`);
    }
    return verificationMethod
}

function toJWK(kid: string, crv: DidAuth.KeyCurve, pubPoint: EC.BN) {
    return {
        kid,
        kty: DidAuth.KeyType.EC,
        crv: crv,
        x: Base64.fromUint8Array(pubPoint.getX().toArrayLike(Buffer), true),
        y: Base64.fromUint8Array(pubPoint.getY().toArrayLike(Buffer), true),
    }
}

function getThumbprintFromJwkImpl(jwk: JWK): string {
    const fields = {
        crv: jwk.crv,
        kty: jwk.kty,
        x: jwk.x,
        y: jwk.y,
    };

    const buff = SHA("sha256").update(JSON.stringify(fields)).digest();

    return base64urlEncodeBuffer(buff);
}

// from fingerprintFromPublicKey function in @transmute/Ed25519KeyPair
function getThumbprintFromJwkDIDKeyImpl(jwk: JWK): string {
    // ed25519 cryptonyms are multicodec encoded values, specifically:
    // (multicodec ed25519-pub 0xed01 + key bytes)
    const pubkeyBytes = bs58.decode(
        ed25519KeyUtils.publicKeyBase58FromPublicKeyJwk(jwk)
    );
    const buffer = new Uint8Array(2 + pubkeyBytes.length);
    buffer[0] = 0xed;
    buffer[1] = 0x01;
    buffer.set(pubkeyBytes, 2);

    // prefix with `z` to indicate multi-base encoding

    return `z${bs58.encode(buffer)}`;
}

export function getThumbprintFromJwk(jwk: JWK, method: string): string {
    if (isEd25519DidKeyMethod(method)) {
        return getThumbprintFromJwkDIDKeyImpl(jwk);
    } else {
        return getThumbprintFromJwkImpl(jwk);
    }
}

export function getThumbprint(hexPrivateKey: string, method: string): string {
    return getThumbprintFromJwk(isEd25519DidKeyMethod(method) ? getPublicJWKFromDIDHexPrivateKey(hexPrivateKey) : getPublicJWKFromHexPrivateKey(hexPrivateKey), method);
}


export const isInternalSignature = (
    object: InternalSignature | ExternalSignature | NoSignature
): object is InternalSignature => "hexPrivateKey" in object && "did" in object;

export const isExternalSignature = (
    object: InternalSignature | ExternalSignature | NoSignature
): object is ExternalSignature => "signatureUri" in object && "did" in object;

export const isNoSignature = (
    object: InternalSignature | ExternalSignature | NoSignature
): object is NoSignature => "hexPublicKey" in object && "did" in object;


export async function encrypt(payload: { [x: string]: unknown; }, publicKeyHex: string): Promise<string> {
    const encrypted = await eth_crypto.encryptWithPublicKey(publicKeyHex, JSON.stringify(payload));
    return eth_crypto.cipher.stringify(encrypted);
}


export async function decrypt(privateKey: string, encrypted: string): Promise<string> {
    const encryptedObject = eth_crypto.cipher.parse(encrypted);
    return eth_crypto.decryptWithPrivateKey(privateKey, encryptedObject);
}
