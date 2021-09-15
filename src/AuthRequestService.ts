import {Resolvable} from "did-resolver";
import querystring from "querystring";
import uuid from "uuid";
import {didJwt} from "./did";
import {decodeJWT, ES256KSigner} from "did-jwt";
import {getECKeyfromHexPrivateKey} from "./util/KeyUtils"
import calculateThumbprint from "jose/jwk/thumbprint";
import {didAuth, jwt} from "./types";


export default class AuthRequestService {
    private resolver: Resolvable;


    constructor(opts) {
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
     * @param didAuthRequestCall  Request input data to build a signed DidAuth Request Token
     */
    async createAuthRequest(didAuthRequest: didAuth.DidAuthRequestCall): Promise<{ uri: string }> {
        if (!didAuthRequest ||
            !didAuthRequest.redirectUri ||
            !didAuthRequest.hexPrivateKey)
            throw new Error("BAD_PARAMS");
        const {jwt, nonce} = await this.createDidAuthRequest(didAuthRequest);
        const responseUri = `openid://?${querystring.encode({
            response_type: didAuth.ResponseType.ID_TOKEN,
            client_id: didAuthRequest.redirectUri,
            scope: didAuth.Scope.OPENID_DIDAUTHN,
            nonce,
            request: jwt,
        })}`;
        // returns a URI with Request JWT embedded
        return {uri: responseUri};
    }

    private async createDidAuthRequest(didAuthRequest: didAuth.DidAuthRequestCall): Promise<{ jwt: string; nonce: string; }> {
        if (!didAuthRequest || !didAuthRequest.redirectUri) {
            throw new Error("BAD_PARAMS");
        }

        const payload = AuthRequestService.createDidAuthRequestPayload(didAuthRequest, uuid.v4());
        return AuthRequestService.signDidAuthImpl(didAuthRequest.kid, payload, didAuthRequest.hexPrivateKey).then(jwt => {
            return {jwt, nonce: payload.nonce}
        });
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
    async createAuthResponse(didAuthResponseCall: didAuth.DidAuthResponseCall): Promise<didAuth.UriResponse> {
        if (!didAuthResponseCall ||
            !didAuthResponseCall.hexPrivateKey ||
            !didAuthResponseCall.did ||
            !didAuthResponseCall.redirectUri) {
            throw new Error("BAD_PARAMS");
        }

        const payload = await AuthRequestService.createAuthenticationResponsePayload(didAuthResponseCall);
        // signs payload using internal libraries
        const jwt = await AuthRequestService.signDidAuthImpl(didAuthResponseCall.did, payload, didAuthResponseCall.hexPrivateKey);
        const params = `id_token=${jwt}`;
        const uriResponse = {
            urlEncoded: "",
            bodyEncoded: "",
            encoding: didAuth.UrlEncodingFormat.FORM_URL_ENCODED,
            responseMode: didAuthResponseCall.responseMode
                ? didAuthResponseCall.responseMode
                : didAuth.DidAuthResponseMode.FRAGMENT, // FRAGMENT is the default
        };

        if (didAuthResponseCall.responseMode === didAuth.DidAuthResponseMode.FORM_POST) {
            uriResponse.urlEncoded = encodeURI(didAuthResponseCall.redirectUri);
            uriResponse.bodyEncoded = encodeURI(params);
        } else if (didAuthResponseCall.responseMode === didAuth.DidAuthResponseMode.QUERY) {
            uriResponse.urlEncoded = encodeURI(`${didAuthResponseCall.redirectUri}?${params}`);
        } else {
            uriResponse.responseMode = didAuth.DidAuthResponseMode.FRAGMENT;
            uriResponse.urlEncoded = encodeURI(`${didAuthResponseCall.redirectUri}#${params}`);
        }
        return uriResponse;
    }


    private static createDidAuthRequestPayload(input, nonce) {
        const requestPayload = {
            iss: input.issuer,
            scope: didAuth.Scope.OPENID_DIDAUTHN,
            response_type: didAuth.ResponseType.ID_TOKEN,
            client_id: input.redirectUri,
            nonce: nonce,
            claims: input.claims,
        };
        return requestPayload;
    }

    private static async signDidAuthImpl(id, payload, hexPrivateKey) {
        const request = !!payload.client_id;
        const header = {
            alg: didAuth.KeyAlgo.ES256K,
            kid: request ? id : `${id}#key-1`, // TODO check user kid
        };
        const response = await didJwt.createDidJWT({...payload}, {
            issuer: request ? payload.iss : didAuth.ResponseIss.SELF_ISSUE,
            signer: ES256KSigner(hexPrivateKey.replace("0x", "")),
            expiresIn: didAuth.expirationTime,
        }, header);
        return response;
    }

    private static getAudience(jwt) {
        const {payload} = decodeJWT(jwt);
        if (!payload)
            throw new Error("NO_AUDIENCE");
        if (!payload.aud)
            return undefined;
        if (Array.isArray(payload.aud))
            throw new Error("INVALID_AUDIENCE");
        return payload.aud;
    }


    private static async createAuthenticationResponsePayload(input) {
        const responsePayload = {
            iss: didAuth.ResponseIss.SELF_ISSUE,
            sub: await this.getThumbprint(input.hexPrivateKey),
            aud: input.redirectUri,
            nonce: input.nonce,
            sub_jwk: this.getJWK(input.hexPrivateKey, `${input.did}#key-1`),
            claims: input.claims,
        };
        return responsePayload;
    }

    private static async getThumbprint(hexPrivateKey) {
        const jwk = AuthRequestService.getJWK(hexPrivateKey);
        const thumbprint = await calculateThumbprint(jwk, "sha256");
        return thumbprint;
    }

    private static getJWK(hexPrivateKey, kid?) {
        const {x, y} = getECKeyfromHexPrivateKey(hexPrivateKey);
        return {
            kid,
            kty: didAuth.KeyType.EC,
            crv: didAuth.KeyCurve.SECP256k1,
            x,
            y,
        };
    }
}

