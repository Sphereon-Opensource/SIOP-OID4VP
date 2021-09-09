import {DidAuthValidationResponse} from "./did/DidAuth";
import {Resolvable} from "did-resolver";

export declare class RPAuthService {
    #private;
    resolver: Resolvable;

    constructor(opts?: {
        resolver?: Resolvable;
    });

    /**
     * Sets the resolver to use for Relying Party Auth
     * @param resolver
     */
    setResolver(resolver: Resolvable);


    /**
     * Verifies a DidAuth ID Response Token
     *
     * @param idToken authentication response token to be validated
     * @param audience expected audience
     */
    verifyAuthResponse(idToken: string, audience: string): Promise<DidAuthValidationResponse>;

}
