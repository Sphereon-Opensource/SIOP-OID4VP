import * as dotenv from 'dotenv';
import parseJwk from 'jose/jwk/parse';
import SignJWT from 'jose/jwt/sign';

import { AuthenticationRequest, SIOP } from '../src/main';
import { State } from '../src/main/functions';
import SIOPErrors from '../src/main/types/Errors';
import {
    CredentialFormat,
    PassBy,
    ResponseContext,
    ResponseMode,
    SubjectIdentifierType,
    VerificationMode,
    VerifyAuthenticationRequestOpts
} from '../src/main/types/SIOP.types';

import { metadata, mockedGetEnterpriseAuthToken } from './TestUtils';

const EXAMPLE_REDIRECT_URL = "https://acme.com/hello";
const EXAMPLE_REFERENCE_URL = "https://rp.acme.com/siop/jwts";

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
                credential_formats_supported: [CredentialFormat.JSON_LD, CredentialFormat.JWT]
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
        ).rejects.toThrow(SIOPErrors.VERIFY_BAD_PARAMS);
    });

    it("throw VERIFY_BAD_PARAMETERS when no responseOpts is passed", async () => {
        expect.assertions(1);
        await expect(
          AuthenticationRequest.verifyJWT("a valid JWT", undefined as never)
        ).rejects.toThrow(SIOPErrors.VERIFY_BAD_PARAMS);
    });

    it("throw VERIFY_BAD_PARAMETERS when no responseOpts.verification is passed", async () => {
        expect.assertions(1);
        await expect(AuthenticationRequest.verifyJWT("a valid JWT", {} as never)).rejects.toThrow(
          SIOPErrors.VERIFY_BAD_PARAMS
        );
    });

    it("throw BAD_NONCE when a different nonce is supplied during verification", async () => {
        expect.assertions(1);
        const requestOpts: SIOP.AuthenticationRequestOpts = {
            redirectUri: EXAMPLE_REDIRECT_URL,
            requestBy: {
                type: SIOP.PassBy.REFERENCE,
                referenceUri: EXAMPLE_REFERENCE_URL,
            },
            nonce: "expected nonce",
            signatureType: {
                hexPrivateKey:
                    "d474ffdb3ea75fbb3f07673e67e52002a3b7eb42767f709f4100acf493c7fc8743017577997b72e7a8b4bce8c32c8e78fd75c1441e95d6aaa888056d1200beb3",
                did: "did:key:z6MkixpejjET5qJK4ebN5m3UcdUPmYV4DPSCs1ALH8x2UCfc",
                kid: "did:key:z6MkixpejjET5qJK4ebN5m3UcdUPmYV4DPSCs1ALH8x2UCfc#keys-1",
            },
            registration: {
                didMethodsSupported: ['did:key:'],
                subjectIdentifiersSupported: SubjectIdentifierType.DID,
                credentialFormatsSupported: [CredentialFormat.JWT],
                registrationBy: {
                    type: SIOP.PassBy.VALUE,
                },
            }
        };

        const requestWithJWT = await AuthenticationRequest.createJWT(requestOpts);

        const verifyOpts: VerifyAuthenticationRequestOpts = {
            verification: {
                mode: VerificationMode.INTERNAL,
                resolveOpts: {
                    didMethods: ["key"]
                }
            },
            nonce: "This nonce is different and should throw error"
        }

        // expect.assertions(1);
        await expect(AuthenticationRequest.verifyJWT(requestWithJWT.jwt, verifyOpts)).rejects.toThrow(SIOPErrors.BAD_NONCE);
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
            requestBy: { type: PassBy.REFERENCE, referenceUri: "https://my-request.com/here" },
            signatureType: {
                hexPrivateKey: mockEntity.hexPrivateKey,
                did: mockEntity.did,
                kid: `${mockEntity.did}#controller`,
            },
            registration: {
                didMethodsSupported: "did:ethr:",
                subjectIdentifiersSupported: SubjectIdentifierType.DID,
                credentialFormatsSupported: [CredentialFormat.JWT],
                registrationBy: { type: PassBy.VALUE }
            }
        }
        const requestWithJWT = await AuthenticationRequest.createJWT(requestOpts);

        const verifyOpts: VerifyAuthenticationRequestOpts = {
            verification: {
                mode: VerificationMode.INTERNAL,
                resolveOpts: {
                    didMethods: ["ethr"]
                }
            },
        }

        const verifyJWT = await AuthenticationRequest.verifyJWT(requestWithJWT.jwt, verifyOpts);
        expect(verifyJWT.jwt).toMatch(/^eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXRocjowe.*$/);
    });
});

describe('OP and RP communication should', () => {

    it('work if both support the same did methods', () => {
        metadata.verify();
        expect(metadata.verify()).toEqual({op_rp_credential_formats_supported: ['jwt', 'w3cvc-jsonld'], op_rp_did_methods_supported: ['did:web']});
    });

    it('work if RP supports any OP did methods', () => {
        metadata.opMetadata.credential_formats_supported = [CredentialFormat.JSON_LD];
        metadata.rpMetadata.subject_identifiers_supported = SubjectIdentifierType.DID;
        metadata.rpMetadata.did_methods_supported = undefined;
        expect(metadata.verify()).toEqual({op_rp_credential_formats_supported: ['w3cvc-jsonld'], op_rp_did_methods_supported: ['did:web']});
    });

    it('work if RP supports any OP credential formats', () => {
        metadata.opMetadata.credential_formats_supported = [CredentialFormat.JSON_LD];
        expect(metadata.verify()).toEqual({op_rp_credential_formats_supported: ['w3cvc-jsonld'], op_rp_did_methods_supported: ['did:web']});
    });

    it('not work if RP does not support any OP did method', () => {
        metadata.rpMetadata.did_methods_supported = ['web:3:'];
        expect(() => metadata.verify()).toThrowError('DID_METHODS_NOT_SUPPORTED');
    });

    it('not work if RP does not support any OP credentials', () => {
        metadata.rpMetadata.credential_formats_supported = undefined;
        expect(() => metadata.verify()).toThrowError('CREDENTIAL_FORMATS_NOT_SUPPORTED');
    });
});
