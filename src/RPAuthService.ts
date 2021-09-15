import {Resolvable} from "did-resolver";
import {verifyDidJWT} from "./did/DidJWT";
import {decodeJWT} from "did-jwt";
import {didAuth} from "./types";
import {DidAuthValidationResponse} from "./types/DidAuth-types";

export class RPAuthService {
    private resolver: Resolvable;

    constructor(opts: {
        resolver?: Resolvable;
    }) {
        this.setResolver(opts.resolver);
    }

    /**
     * Sets the resolver to use for Relying Party Auth
     * @param resolver
     */
    setResolver(resolver: Resolvable) {
        this.resolver = resolver;
    }

    /**
     * Verifies a DidAuth ID Response Token
     *
     * @param idToken ID token to be validated
     * @param audience expected audience
     */
    async verifyAuthResponse(idToken: string, audience: string): Promise<DidAuthValidationResponse> {

        const {payload} = decodeJWT(idToken);
        if (payload.iss !== didAuth.ResponseIss.SELF_ISSUE) {
            throw new Error("NO_SELFISSUED_ISS");
        }

        const verifiedJWT = await verifyDidJWT(idToken, this.resolver, {
            audience,
        });

        if (!verifiedJWT || !verifiedJWT.payload) {
            throw Error("ERROR_VERIFYING_SIGNATURE");
        }
        if (!verifiedJWT.payload.nonce) {
            throw Error("NO_NONCE");
        }

        return {
            signatureValidation: true,
            signer: verifiedJWT.signer,
            payload: {
                did: verifiedJWT.didResolutionResult.didDocument,
                ...verifiedJWT.payload,
            },
        };
    }

}
