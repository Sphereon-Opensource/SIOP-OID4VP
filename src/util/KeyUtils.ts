import js_base64 from "js-base64";
import elliptic from "elliptic";
import eth_crypto from "eth-crypto";
import {JWK} from "jose/types";

export function getHexPrivateKey(key: JWK) : string {
    const privateKeyHex = Buffer.from(key.d, "base64").toString("hex");
    return `0x${privateKeyHex}`;
}


export function getECKeyfromHexPrivateKey(hexPrivateKey: string): { x: string; y: string; } {
    const ec = new elliptic.ec("secp256k1");
    const privKey = ec.keyFromPrivate(hexPrivateKey.replace("0x", ""), "hex");
    const pubPoint = privKey.getPublic();
    return {
        x: js_base64.Base64.fromUint8Array(pubPoint.getX().toArrayLike(Buffer), true),
        y: js_base64.Base64.fromUint8Array(pubPoint.getY().toArrayLike(Buffer), true),
    };
}

export async function encrypt(payload: { [x: string]: unknown; }, publicKeyHex: string): Promise<string> {
    const encrypted = await eth_crypto.encryptWithPublicKey(publicKeyHex, JSON.stringify(payload));
    return eth_crypto.cipher.stringify(encrypted);
}

export async function decrypt(privateKey: string, encrypted: string): Promise<string> {
    const encryptedObject = eth_crypto.cipher.parse(encrypted);
    const decrypted = await eth_crypto.decryptWithPrivateKey(privateKey, encryptedObject);
    return decrypted;
}
