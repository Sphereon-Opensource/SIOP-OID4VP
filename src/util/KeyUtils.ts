import js_base64 from "js-base64";
import elliptic from "elliptic";
import eth_crypto from "eth-crypto";

export function getHexPrivateKey(key) {
    const privateKeyHex = Buffer.from(key.d, "base64").toString("hex");
    return `0x${privateKeyHex}`;
}


export function getECKeyfromHexPrivateKey(hexPrivateKey) {
    const ec = new elliptic.ec("secp256k1");
    const privKey = ec.keyFromPrivate(hexPrivateKey.replace("0x", ""), "hex");
    const pubPoint = privKey.getPublic();
    return {
        x: js_base64.Base64.fromUint8Array(pubPoint.getX().toArrayLike(Buffer), true),
        y: js_base64.Base64.fromUint8Array(pubPoint.getY().toArrayLike(Buffer), true),
    };
}

export async function encrypt(payload, publicKeyHex) {
    const encrypted = await eth_crypto.encryptWithPublicKey(publicKeyHex, JSON.stringify(payload));
    return eth_crypto.cipher.stringify(encrypted);
}

export async function decrypt(privateKey, encrypted) {
    const encryptedObject = eth_crypto.cipher.parse(encrypted);
    const decrypted = await eth_crypto.decryptWithPrivateKey(privateKey, encryptedObject);
    return decrypted;
}
