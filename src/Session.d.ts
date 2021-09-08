
import {DidAuthValidationResponse} from "./DIDAuth";
import {AgentResponse} from "./Agent";
import {JWTPayload} from "./JWT";
import {Resolvable} from "did-resolver";

export declare class Session {
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

    createAccessToken(validation: DidAuthValidationResponse, opts?: { [key: string]: string | number; }): Promise<AgentResponse>;

    verifyAccessToken(token: string, issuer: string): Promise<JWTPayload>;
}

export default Session;
