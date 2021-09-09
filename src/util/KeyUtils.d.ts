import {JWK} from "jose/types";

export declare function getHexPrivateKey(key: JWK): string;

export declare function getECKeyfromHexPrivateKey(hexPrivateKey: string): { x: string; y: string; };

export declare function encrypt(payload: { [x: string]: unknown; }, publicKeyHex: string): Promise<string>;

export declare function decrypt(privateKey: string, encrypted: string): Promise<string>;
