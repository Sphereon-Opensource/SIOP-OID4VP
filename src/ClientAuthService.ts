import DidAuth, {KeyAlgo, KeyCurve, KeyType, ResponseIss, ResponseType, Scope} from "./did/DidAuth";
import {Resolvable} from "did-resolver";
import querystring from "querystring";
import uuid from "uuid";
import {createDidJWT, verifyDidJWT} from "./did/DidJWT";
import {decodeJWT, ES256KSigner} from "did-jwt";
import {getECKeyfromHexPrivateKey} from "./util/KeyUtils"
import calculateThumbprint from "jose/jwk/thumbprint";

export default class ClientAuthService {
    private resolver: Resolvable;

    constructor(opts) {
        this.setResolver(opts.resolver);
    }

    setResolver(resolver) {
        this.resolver = resolver;
    }

    async createAuthRequest(didAuthRequest) {
        if (!didAuthRequest ||
            !didAuthRequest.redirectUri ||
            !didAuthRequest.hexPrivateKey)
            throw new Error("BAD_PARAMS");
        const {jwt, nonce} = await this.createDidAuthRequest(didAuthRequest);
        const responseUri = `openid://?${querystring.encode({
            response_type: ResponseType.ID_TOKEN,
            client_id: didAuthRequest.redirectUri,
            scope: Scope.OPENID_DIDAUTHN,
            nonce,
            request: jwt,
        })}`;
        // returns a URI with Request JWT embedded
        return {uri: responseUri};
    }

    private async createDidAuthRequest(didAuthRequest) {
        if (!didAuthRequest || !didAuthRequest.redirectUri) {
            throw new Error("BAD_PARAMS");
        }

        const payload = ClientAuthService.createDidAuthRequestPayload(didAuthRequest, uuid.v4());
        return ClientAuthService.signDidAuthImpl(didAuthRequest.kid, payload, didAuthRequest.hexPrivateKey).then(jwt => {
            return {jwt, nonce: payload.nonce}
        });
    }


    async verifyAuthRequest(didAuthJwt) {
        // as audience is set in payload as a DID, it is required to be set as options
        const options = {
            audience: ClientAuthService.getAudience(didAuthJwt),
        };
        const verifiedJWT = await verifyDidJWT(didAuthJwt, this.resolver, options);
        if (!verifiedJWT || !verifiedJWT.payload) {
            throw Error("ERROR_VERIFYING_SIGNATURE");
        }
        return verifiedJWT.payload;
    }


    /**
     * Creates a DidAuth Response Object
     *
     * @param didAuthResponse
     */
    async createAuthenticationResponse(didAuthResponseCall) {
        if (!didAuthResponseCall ||
            !didAuthResponseCall.hexPrivateKey ||
            !didAuthResponseCall.did ||
            !didAuthResponseCall.redirectUri) {
            throw new Error("BAD_PARAMS");
        }

        const payload = await ClientAuthService.createAuthenticationResponsePayload(didAuthResponseCall);
        // signs payload using internal libraries
        const jwt = await ClientAuthService.signDidAuthImpl(didAuthResponseCall.did, payload, didAuthResponseCall.hexPrivateKey);
        const params = `id_token=${jwt}`;
        const uriResponse = {
            urlEncoded: "",
            bodyEncoded: "",
            encoding: DidAuth.UrlEncodingFormat.FORM_URL_ENCODED,
            responseMode: didAuthResponseCall.responseMode
                ? didAuthResponseCall.responseMode
                : DidAuth.DidAuthResponseMode.FRAGMENT, // FRAGMENT is the default
        };

        if (didAuthResponseCall.responseMode === DidAuth.DidAuthResponseMode.FORM_POST) {
            uriResponse.urlEncoded = encodeURI(didAuthResponseCall.redirectUri);
            uriResponse.bodyEncoded = encodeURI(params);
        } else if (didAuthResponseCall.responseMode === DidAuth.DidAuthResponseMode.QUERY) {
            uriResponse.urlEncoded = encodeURI(`${didAuthResponseCall.redirectUri}?${params}`);
        } else {
            uriResponse.responseMode = DidAuth.DidAuthResponseMode.FRAGMENT;
            uriResponse.urlEncoded = encodeURI(`${didAuthResponseCall.redirectUri}#${params}`);
        }
        return uriResponse;
    }






    private static createDidAuthRequestPayload(input, nonce) {
        const requestPayload = {
            iss: input.issuer,
            scope: Scope.OPENID_DIDAUTHN,
            response_type: ResponseType.ID_TOKEN,
            client_id: input.redirectUri,
            nonce: nonce,
            claims: input.claims,
        };
        return requestPayload;
    }

    private static async signDidAuthImpl(id, payload, hexPrivateKey) {
        const request = !!payload.client_id;
        const header = {
            alg: KeyAlgo.ES256K,
            kid: request ? id : `${id}#key-1`, // TODO check user kid
        };
        const response = await createDidJWT({...payload}, {
            issuer: request ? payload.iss : ResponseIss.SELF_ISSUE,
            signer: ES256KSigner(hexPrivateKey.replace("0x", "")),
            expiresIn: DidAuth.expirationTime,
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
            iss: ResponseIss.SELF_ISSUE,
            sub: await this.getThumbprint(input.hexPrivateKey),
            aud: input.redirectUri,
            nonce: input.nonce,
            sub_jwk: this.getJWK(input.hexPrivateKey, `${input.did}#key-1`),
            claims: input.claims,
        };
        return responsePayload;
    }

    private static async getThumbprint(hexPrivateKey) {
        const jwk = ClientAuthService.getJWK(hexPrivateKey);
        const thumbprint = await calculateThumbprint(jwk, "sha256");
        return thumbprint;
    }

    private static getJWK(hexPrivateKey, kid?) {
        const {x, y} = getECKeyfromHexPrivateKey(hexPrivateKey);
        return {
            kid,
            kty: KeyType.EC,
            crv: KeyCurve.SECP256k1,
            x,
            y,
        };
    }
}
