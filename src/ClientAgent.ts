import {keyUtils} from "./util";
import {didJwt} from "./did";
import {Resolvable} from "did-resolver";


export default class ClientAgent {
    private readonly privateKeys: WeakMap<String, string>;
    private readonly did: string;
    private resolver: Resolvable;
    private readonly audience: string;

    /**
     * Creates the client application agent (the OP)
     *
     * @param   {String}        privateKey    The private key associated with a DID
     * @param   {Resolvable}    resolver      The DID resolver to use
     * @param   {}              options       Optional options
     */
    constructor(opts?: {
        resolver: Resolvable;
        privateKey: string;
        did: string;
        audience?: string;
    }) {
        this.did = opts?.did;
        this.audience = opts?.audience;
        this.setResolver(opts.resolver);
        this.privateKeys.set(this.did, opts.privateKey);
    }

    /**
     * Sets the resolver to use for Relying Party Auth
     * @param resolver
     */
    setResolver(resolver: Resolvable) {
        this.resolver = resolver;
    }


    /**
     * Verifies the Authenticated Key Exchange Response which contains the Access Token, Returns the decrypted access token
     *
     * @param {AkeResponse}     response  The AKE response, containing the encrypted access token
     * @param {String}          nonce     The nonce used
     */
    async verifyAuthResponse(response, nonce) {
        const {AKeSigned: signed_payload} = response;
        const decryptedPayload = JSON.parse(await keyUtils.decrypt(this.privateKeys.get(this.did), signed_payload));

        if (typeof decryptedPayload.did !== "string" ||
            typeof decryptedPayload.access_token !== "string") {
            throw new Error("did or access_token invalid type");
        } else if (nonce !== decryptedPayload.nonce) {
            throw new Error(`Expected nonce ${nonce}. Received ${decryptedPayload.nonce}`);
        }

        const jwt = await didJwt.verifyDidJWT(decryptedPayload.access_token, this.resolver, {audience: this.audience,});
        console.log(jwt);
        return decryptedPayload.access_token;
    }
}
