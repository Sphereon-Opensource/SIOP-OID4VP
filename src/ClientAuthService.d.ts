import {DidAuthRequest, DidAuthRequestCall, DidAuthResponseCall, UriResponse} from "./did/DidAuth";
import {Resolvable} from "did-resolver";



export declare class ClientAuthService {
    #private;
    resolver: Resolvable;

    constructor(opts?: {
        resolver?: Resolvable;
    });

    /**
     * Sets the resolver to use for SIOP Auth
     * @param resolver
     */
    setResolver(resolver: Resolvable);


    /**
     *
     * @param didAuthRequestCall
     */
    createAuthRequest(didAuthRequestCall: DidAuthRequestCall): Promise<{
        uri: string;
    }>;

    /**
     * Creates a DidAuth Request Object
     * @param didAuthRequestCall Request input data to build a signed DidAuth Request Token
     */
    createDidAuthRequest(didAuthRequestCall: DidAuthRequestCall): Promise<{
        jwt: string;
        nonce: string;
    }>;

    /**
     * Verifies a DidAuth ID Request Token
     * @param didAuthJwt signed DidAuth Request Token
     * @param didRegistry url of the did-api, or object resolver for DIDs
     */
    verifyAuthRequest(didAuthJwt: string): Promise<DidAuthRequest>;

    /**
     * Creates a DidAuth Response Object
     *
     * @param didAuthResponse
     */
    createAuthResponse(didAuthResponse: DidAuthResponseCall): Promise<UriResponse>;

}
