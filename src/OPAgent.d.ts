import {Resolvable} from "did-resolver";
import {AkeDecrypted, AkeResponse} from "./AuthKeyExchange";

export declare class OPAgent {
    #private;
    resolver: Resolvable;

    /**
     * Creates the client application agent (the OP)
     *
     * @param   {String}        privateKey    The private key associated with a DID
     * @param   {Resolvable}    resolver      The DID resolver to use
     * @param   {}              options       Optional options
     */
    constructor(
        privateKey: string,
        resolver: Resolvable,
        options?: {}
    );

    /**
     * Verifies the Authenticated Key Exchange Response which contains the Access Token, Returns the decrypted access token
     *
     * @param {AkeResponse}     response  The AKE response, containing the encrypted access token
     * @param {String}          nonce     The nonce used
     */
    verifyAuthResponse(response: AkeResponse, nonce: string): Promise<AkeDecrypted>;
}
export default OPAgent;
