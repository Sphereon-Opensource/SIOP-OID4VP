import {DidAuthRequest, DidAuthResponse, DidAuthValidationResponse, Resolvable, UriResponse} from "./DIDAuth";

export declare class SIOPAuth {
    /**
     * Sets the resolver to use for SIOP Auth
     * @param resolver
     */
    static setResolver(resolver: Resolvable);

    /**
     *
     * @param didAuthRequest
     */
    static createAuthRequest(didAuthRequest: DidAuthRequest): Promise<{ uri: string; }>;

    /**
     * Creates a DidAuth Request Object
     *
     * @param didAuthRequest Request input data to build a signed DidAuth Request Token
     */
    static createDidAuthRequest(didAuthRequest: DidAuthRequest): Promise<{
        jwt: string;
        nonce: string;
    }>;

    /**
     * Verifies a DidAuth ID Request Token
     * @param didAuthJwt signed DidAuth Request Token
     * @param resolver The DID resolver
     */
    static verifyIDRequestToken(didAuthJwt: string): Promise<DidAuthRequest>;

    /**
     * Creates a DidAuth Response Object
     * @param didAuthResponse
     */
    static createDidAuthResponse(didAuthResponse: DidAuthResponse): Promise<UriResponse>;

    /**
     * Verifies a DidAuth ID Response Token
     * @param idToken authentication response token to be validated
     * @param resolver DID Registry
     * @param audience expected audience
     */
    static verifyAuthenticationResponse(idToken: string, audience: string): Promise<DidAuthValidationResponse>;


}

export default SIOPAuth;
