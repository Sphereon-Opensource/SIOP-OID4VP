import * as dotenv from "dotenv";
import SignJWT from "jose/JWT/sign";
import parseJwk from "jose/jwk/parse";

import {AuthenticationRequest, SIOP} from "../src";
import {State} from "../src/functions";
import SIOPErrors from "../src/types/Errors";
import {
    PassBy,
    ResponseContext,
    ResponseMode,
    SubjectIdentifierType,
    VerificationMode,
    VerifyAuthenticationRequestOpts
} from "../src/types/SIOP.types";

import {mockedGetEnterpriseAuthToken} from "./TestUtils";


dotenv.config();

describe("SIOP Request Validation", () => {

    it("should verify", async () => {

        // const mockVerifyJwt = verifyJWT as jest.Mock;
        // const mockDecodeJWT = decodeJWT as jest.Mock;
        expect.assertions(1);
        const mockEntity = await mockedGetEnterpriseAuthToken("COMPANY AA INC");
        const header = {
            alg: SIOP.KeyAlgo.ES256K,
            typ: "JWT",
            kid: `${mockEntity.did}#controller`,
        };
        const state = State.getState();
        const payload: SIOP.AuthenticationRequestPayload = {
            iss: mockEntity.did,
            aud: "test",
            response_mode: ResponseMode.POST,
            response_context: ResponseContext.RP,
            redirect_uri: "",
            scope: SIOP.Scope.OPENID,
            response_type: SIOP.ResponseType.ID_TOKEN,
            client_id: "http://localhost:8080/test",
            state,
            nonce: State.getNonce(state),
            registration: {
                did_methods_supported: ['did:ethr:'],
                subject_identifiers_supported: SubjectIdentifierType.DID,
                /*subject_types_supported: SubjectType.PAIRWISE,
                scopes_supported: Scope.OPENID,
                request_object_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256K],
                issuer: ResponseIss.SELF_ISSUED_V2,
                response_types_supported: ResponseType.ID_TOKEN,
                id_token_signing_alg_values_supported: [KeyAlgo.EDDSA, KeyAlgo.ES256K],
                authorization_endpoint: Schema.OPENID*/
            },
            /*registration: {
                jwks_uri: `https://dev.uniresolver.io/1.0/identifiers/${mockEntity.did}`,
                // jwks_uri: `https://dev.uniresolver.io/1.0/identifiers/${mockEntity.did};transform-keys=jwks`,
                id_token_signed_response_alg: SIOP.KeyAlgo.ES256K,
            },*/
        };
        const privateKey = await parseJwk(
            mockEntity.jwk,
            SIOP.KeyAlgo.ES256K
        );
        const jwt = await new SignJWT(payload)
            .setProtectedHeader(header)
            .sign(privateKey);

        const optsVerify: SIOP.VerifyAuthenticationRequestOpts = {
            verification: {
                mode: VerificationMode.INTERNAL,
                resolveOpts: {
                    didMethods: ["ethr"]
                },
            },

        };
        await expect(AuthenticationRequest.verifyJWT(jwt, optsVerify)).resolves.toBeDefined();
    });
});


describe("verifyJWT should", () => {

    it("throw VERIFY_BAD_PARAMETERS when no JWT is passed", async () => {
        expect.assertions(1);
        await expect(
            AuthenticationRequest.verifyJWT(undefined as never, undefined as never)
        ).rejects.toThrow(SIOPErrors.VERIFY_BAD_PARAMETERS);
    });

    it("throw VERIFY_BAD_PARAMETERS when no responseOpts is passed", async () => {
        expect.assertions(1);
        await expect(
            AuthenticationRequest.verifyJWT("a valid JWT", undefined as never)
        ).rejects.toThrow(SIOPErrors.VERIFY_BAD_PARAMETERS);
    });

    it("throw VERIFY_BAD_PARAMETERS when no responseOpts.verification is passed", async () => {
        expect.assertions(1);
        await expect(AuthenticationRequest.verifyJWT("a valid JWT", {} as never)).rejects.toThrow(
            SIOPErrors.VERIFY_BAD_PARAMETERS
        );
    });

    it("succeed if a valid JWT is passed", async () => {
        const mockEntity = await mockedGetEnterpriseAuthToken("COMPANY AA INC");
        /*const header = {
            alg: SIOP.KeyAlgo.ES256K,
            typ: "JWT",
            kid: `${mockEntity.did}#controller`,
        };
        const state = State.getState();*/
        const requestOpts = {
            redirectUri: "https://acme.com/hello",
            requestBy: {type: PassBy.REFERENCE, referenceUri: "https://my-request.com/here"},
            signatureType: {
                hexPrivateKey: mockEntity.hexPrivateKey,
                did: mockEntity.did,
                kid: `${mockEntity.did}#controller`,
            },
            registration: {
                didMethodsSupported: "did:ethr:",
                subjectIdentifiersSupported: SubjectIdentifierType.DID,
                registrationBy: {type: PassBy.VALUE}
            }
        }
        const requestWithJWT = await AuthenticationRequest.createJWT(requestOpts);

        const verifyOpts : VerifyAuthenticationRequestOpts = {
            verification: {
                mode: VerificationMode.INTERNAL,
                resolveOpts: {
                    didMethods: ["ethr"]
                }
            },
        }

        // expect.assertions(1);
        const verifyJWT = await AuthenticationRequest.verifyJWT(requestWithJWT.jwt, verifyOpts);
        console.log(JSON.stringify(verifyJWT));
        expect(verifyJWT.jwt).toMatch(/^eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXRocjowe.*$/);
    });
});
