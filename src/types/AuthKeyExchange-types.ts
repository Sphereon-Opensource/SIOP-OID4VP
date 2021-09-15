export interface AkeSigned {
    //JWT Header: typ:JWT

    version: 1;

    // Encrypted access token
    encrypted_access_token: string;

    // ID Token nonce
    nonce: string;
    kid?: string;
    iat: number;
    iss: string;
}

export interface AkeResponse {
    version: 1;

    // Encrypted access token
    // todo potential remove, given it is available in the signed_payload
    encrypted_access_token: string;
    signed_payload: AkeSigned;
    jws: string;
    did?: string;
}

export interface AkeDecrypted {
    version: 1;

    access_token: string;
    kid: string;
    nonce: string;
}
