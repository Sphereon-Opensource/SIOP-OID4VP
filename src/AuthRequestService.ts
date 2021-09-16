import {decodeJWT} from "did-jwt";
import {Resolvable} from "did-resolver";

// import querystring from "querystring";
import {didJwt} from "./did";
import {signDidJwtPayload} from "./did/DidJWT";
import {DidAuth, jwt} from "./types";
import {
    AuthRequestResponse,
    DidAuthRequest,
    DidAuthResponse,
    PassBy,
    RequestOpts,
    ResponseOpts
} from "./types/DidAuth-types";
import {fetchDidDocument} from "./util/HttpUtils";
import {
    getPublicJWKFromHexPrivateKey,
    getThumbprint,
    getThumbprintFromJwk,
    isExternalSignature,
    isInternalSignature
} from "./util/KeyUtils"
import {getNonce, getState} from "./util/StateUtils";


export default class AuthRequestService {
    private resolver: Resolvable;


    constructor(opts?: {
        resolver: Resolvable;
    }) {
        this.setResolver(opts.resolver);
    }

    /**
     * Sets the resolver to use for SIOP Auth
     * @param resolver
     */
    setResolver(resolver: Resolvable) {
        this.resolver = resolver;
    }

    /**
     * Create a signed URL encoded URI with a signed DidAuth request token
     *
     * @param opts Request input data to build a  DidAuth Request Token
     */
    async createAuthRequest(opts: RequestOpts): Promise<AuthRequestResponse> {
        AuthRequestService.assertValidRequestOpts(opts)
        const payload = AuthRequestService.createDidAuthRequestPayload(opts);
        const {nonce, state} = payload;
        const jwt = await signDidJwtPayload(payload, opts);

        return {
            jwt,
            nonce,
            state
        }

        /*const responseUri = `openid://?${querystring.encode({
            response_type: DidAuth.ResponseType.ID_TOKEN,
            client_id: opts.redirectUri,
            scope: DidAuth.Scope.OPENID_DIDAUTHN,
            nonce,
            request: jwt,
        })}`;
        // returns a URI with Request JWT embedded
        return {uri: responseUri};*/
    }

    /**
     * Verifies a DidAuth ID Request Token
     *
     * @param didAuthJwt signed DidAuth Request Token
     */
    async verifyAuthRequest(didAuthJwt: string): Promise<jwt.VerifiedJWT> {
        // as audience is set in payload as a DID, it is required to be set as options
        const options = {
            audience: AuthRequestService.getAudience(didAuthJwt),
        };
        const verifiedJWT = await didJwt.verifyDidJWT(didAuthJwt, this.resolver, options);
        if (!verifiedJWT || !verifiedJWT.payload) {
            throw Error("ERROR_VERIFYING_SIGNATURE");
        }
        return verifiedJWT;
    }


    /**
     * Creates a DidAuth Response Object
     *
     * @param didAuthResponse
     */
    async createAuthResponse(opts: ResponseOpts): Promise<string> {
        AuthRequestService.assertValidResponseOpts(opts);
        const payload = await AuthRequestService.createAuthResponsePayload(opts);
        return signDidJwtPayload(payload, opts);

        /*if (isInternalSignature(opts.signatureType)) {
            return didJwt.signDidJwtInternal(payload, ResponseIss.SELF_ISSUE, opts.signatureType.hexPrivateKey, opts.signatureType.kid);
        } else if (isExternalSignature(opts.signatureType)) {
            return didJwt.signDidJwtExternal(payload, opts.signatureType.signatureUri, opts.signatureType.authZToken, opts.signatureType.kid);
        } else {
            throw new Error("INVALID_SIGNATURE_TYPE");
        }*/
        /*const params = `id_token=${jwt}`;
        const uriResponse = {
            urlEncoded: "",
            bodyEncoded: "",
            encoding: DidAuth.UrlEncodingFormat.FORM_URL_ENCODED,
            responseMode: didAuthResponseCall.responseMode
                ? didAuthResponseCall.responseMode
                : DidAuth.ResponseMode.FRAGMENT, // FRAGMENT is the default
        };

        if (didAuthResponseCall.responseMode === DidAuth.ResponseMode.FORM_POST) {
            uriResponse.urlEncoded = encodeURI(didAuthResponseCall.redirectUri);
            uriResponse.bodyEncoded = encodeURI(params);
        } else if (didAuthResponseCall.responseMode === DidAuth.ResponseMode.QUERY) {
            uriResponse.urlEncoded = encodeURI(`${didAuthResponseCall.redirectUri}?${params}`);
        } else {
            uriResponse.responseMode = DidAuth.ResponseMode.FRAGMENT;
            uriResponse.urlEncoded = encodeURI(`${didAuthResponseCall.redirectUri}#${params}`);
        }
        return uriResponse;*/
    }


    private static createDidAuthRequestPayload(opts: RequestOpts): DidAuthRequest {
        AuthRequestService.assertValidRequestOpts(opts)
        const state = getState(opts.state);
        const registration = null;
        const requestPayload = {
            iss: opts.signatureType.did,
            scope: DidAuth.Scope.OPENID_DIDAUTHN,
            response_type: DidAuth.ResponseType.ID_TOKEN,
            response_mode: opts.responseMode || DidAuth.ResponseMode.FORM_POST,
            response_context: opts.responseContext || DidAuth.ResponseContext.RP,
            client_id: opts.redirectUri,
            nonce: getNonce(state, opts.nonce),
            state,
            registration,
            claims: opts.claims
        };
        return requestPayload;
    }


    private static getAudience(jwt: string) {
        const {payload} = decodeJWT(jwt);
        if (!payload)
            throw new Error("NO_AUDIENCE");
        if (!payload.aud)
            return undefined;
        if (Array.isArray(payload.aud))
            throw new Error("INVALID_AUDIENCE");
        return payload.aud;
    }

    private static async createAuthResponsePayload(opts: ResponseOpts): Promise<DidAuthResponse> {
        this.assertValidResponseOpts(opts);

        let thumbprint;
        let subJwk;
        if (isInternalSignature(opts.signatureType)) {
            thumbprint = getThumbprint(opts.signatureType.hexPrivateKey, opts.did);
            subJwk = getPublicJWKFromHexPrivateKey(opts.signatureType.hexPrivateKey, opts.signatureType.kid || `${opts.signatureType.did}#key-1`, opts.did);
        } else if (isExternalSignature(opts.signatureType)) {
            const didDocument = await fetchDidDocument(opts);
            thumbprint = getThumbprintFromJwk(didDocument.verificationMethod[0].publicKeyJwk, opts.did);
            subJwk = didDocument.verificationMethod[0].publicKeyJwk;
        } else {
            throw new Error("SIGNATURE_OBJECT_TYPE_NOT_SET");
        }

        return {
            iss: DidAuth.ResponseIss.SELF_ISSUE,
            sub: thumbprint,
            aud: opts.redirectUri,
            nonce: opts.nonce,
            did: opts.did,
            sub_jwk: subJwk,
            vp: opts.vp
        };
    }




    private static assertValidResponseOpts(opts: ResponseOpts) {
        if (!opts || !opts.redirectUri || !opts.signatureType || !opts.nonce || !opts.did) {
            throw new Error("BAD_PARAMS");
        } else if (!(isInternalSignature(opts.signatureType) || isExternalSignature(opts.signatureType))) {
            throw new Error("SIGNATURE_OBJECT_TYPE_NOT_SET");
        }
    }

    private static assertValidRequestOpts(opts: RequestOpts) {
        if (!opts || !opts.redirectUri) {
            throw new Error("BAD_PARAMS");
        } else if (!opts || !opts.redirectUri || !opts.requestBy || !opts.registrationType) {
            throw new Error("BAD_PARAMS");
        } else if (opts.requestBy.type !== PassBy.REFERENCE && opts.requestBy.type !== PassBy.VALUE) {
            throw new Error("REQUEST_OBJECT_TYPE_NOT_SET");
        } else if (opts.requestBy.type === PassBy.REFERENCE && !opts.requestBy.referenceUri) {
            throw new Error("NO_REFERENCE_URI");
        } else if (opts.registrationType.type !== PassBy.REFERENCE && opts.registrationType.type !== PassBy.VALUE) {
            throw new Error("REGISTRATION_OBJECT_TYPE_NOT_SET");
        } else if (opts.registrationType.type === PassBy.REFERENCE && !opts.registrationType.referenceUri) {
            throw new Error("NO_REFERENCE_URI");
        }
    }


}
