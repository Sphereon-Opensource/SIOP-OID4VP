
import {DidAuthValidationResponse} from "./DIDAuth";
import {JWTPayload} from "./JWT";
import {Resolvable} from "did-resolver";
import {AkeResponse} from "./AuthKeyExchange";

export declare class RPSession {
    #private;
    resolver: Resolvable;
    expiration: {
        requestToken: number;
        accessToken: number;
    };
    did: string;
    kid: string;

    constructor(opts?: {
        privateKey?: string;
        kid?: string;
        did?: string;
        resolver?: Resolvable;
        expiration?: {
            requestToken: number;
            accessToken: number;
        };
    });

    /**
     * Creates an access token as a JWS wrapped as an AKE response
     *
     * @param validation
     * @param opts
     */
    createAccessToken(validation: DidAuthValidationResponse, opts?: { [key: string]: string | number; }): Promise<AkeResponse>;

    /**
     * Verifies the bearer access token on the RP side as received from the OP/client
     *
     * @param accessToken
     * @param issuer
     */
    verifyAccessToken(accessToken: string, issuer: string): Promise<JWTPayload>;
}

export default RPSession;
