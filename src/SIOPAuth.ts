import DidAuth, {KeyAlgo, ResponseIss, ResponseType, Scope} from "./DidAuth";
import {Resolvable} from "did-resolver";
import querystring from "querystring";
import uuid from "uuid";
import {createDidJWT, verifyDidJWT} from "./DidJWT";
import {decodeJWT, ES256KSigner} from "did-jwt";

class SIOPAuth {
    private resolver: Resolvable;

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

    async createDidAuthRequest(didAuthRequest) {
        if (!didAuthRequest || !didAuthRequest.redirectUri) {
            throw new Error("BAD_PARAMS");
        }

        const payload = SIOPAuth.createDidAuthRequestPayload(didAuthRequest, uuid.v4());
        return SIOPAuth.signDidAuthImpl(didAuthRequest.kid, payload, didAuthRequest.hexPrivateKey).then(jwt => {
            return {jwt, nonce: payload.nonce}
        });
    }


    async verifyAuthRequest(didAuthJwt) {
        // as audience is set in payload as a DID, it is required to be set as options
        const options = {
            audience: SIOPAuth.getAudience(didAuthJwt),
        };
        const verifiedJWT = await verifyDidJWT(didAuthJwt, this.resolver, options);
        if (!verifiedJWT || !verifiedJWT.payload) {
            throw Error("ERROR_VERIFYING_SIGNATURE");
        }
        return verifiedJWT.payload;
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
}
