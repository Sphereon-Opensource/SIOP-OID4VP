import {decrypt} from "./util/KeyUtils";
import {verifyDidJWT} from "./did/DidJWT";
import {Resolvable} from "did-resolver";


export default class ClientAgent {
    private readonly privateKeys: WeakMap<String, string>;
    private did: string;
    private resolver: Resolvable;
    private audience: string;

    constructor(opts) {
        this.did = opts.did;
        this.audience = opts.audience;
        this.resolver = opts.resolver;
        this.privateKeys.set(this.did, opts.privateKey);
    }

    async verifyAuthResponse(response, nonce) {
        const {AKeSigned: signed_payload} = response;
        const decryptedPayload = JSON.parse(await decrypt(this.privateKeys.get(this.did), signed_payload));

        if (typeof decryptedPayload.did !== "string" ||
            typeof decryptedPayload.access_token !== "string") {
            throw new Error("did or access_token invalid type");
        } else if (nonce !== decryptedPayload.nonce) {
            throw new Error(`Expected nonce ${nonce}. Received ${decryptedPayload.nonce}`);
        }

        const jwt = await verifyDidJWT(decryptedPayload.access_token, this.resolver, {audience: this.audience,});
        console.log(jwt);
        return decryptedPayload.access_token;
    }
}
