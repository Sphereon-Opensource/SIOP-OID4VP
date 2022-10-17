import { IProofType } from '@sphereon/ssi-types';
import { IVerifyCallbackArgs, IVerifyCredentialResult } from '@sphereon/wellknown-dids-client';
import * as dotenv from 'dotenv';
import { importJWK, SignJWT } from 'jose';

import {
  AuthenticationRequest,
  AuthenticationRequestOpts,
  AuthenticationRequestPayload,
  CheckLinkedDomain,
  getNonce,
  getState,
  KeyAlgo,
  PassBy,
  ResponseContext,
  ResponseMode,
  ResponseType,
  Scope,
  SigningAlgo,
  SubjectSyntaxTypesSupportedValues,
  SubjectType,
  VerificationMode,
  VerifyAuthenticationRequestOpts,
} from '../src/main';
import SIOPErrors from '../src/main/types/Errors';

import { metadata, mockedGetEnterpriseAuthToken } from './TestUtils';
import {
  UNIT_TEST_TIMEOUT,
  VERIFIER_LOGO_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT_NL,
  VERIFIERZ_PURPOSE_TO_VERIFY,
  VERIFIERZ_PURPOSE_TO_VERIFY_NL,
} from './data/mockedData';

const EXAMPLE_REDIRECT_URL = 'https://acme.com/hello';
const EXAMPLE_REFERENCE_URL = 'https://rp.acme.com/siop/jwts';

dotenv.config();

describe('SIOP Request Validation', () => {
  it(
    'should verify',
    async () => {
      // const mockVerifyJwt = verifyJWT as jest.Mock;
      // const mockDecodeJWT = decodeJWT as jest.Mock;
      expect.assertions(1);
      const mockEntity = await mockedGetEnterpriseAuthToken('COMPANY AA INC');
      const header = {
        alg: KeyAlgo.ES256K,
        typ: 'JWT',
        kid: `${mockEntity.did}#controller`,
      };
      const state = getState();
      const payload: AuthenticationRequestPayload = {
        iss: mockEntity.did,
        aud: 'test',
        response_mode: ResponseMode.POST,
        response_context: ResponseContext.RP,
        redirect_uri: '',
        scope: Scope.OPENID,
        response_type: ResponseType.ID_TOKEN,
        client_id: 'http://localhost:8080/test',
        state,
        nonce: getNonce(state),
        registration: {
          id_token_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256K],
          request_object_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256K],
          response_types_supported: [ResponseType.ID_TOKEN],
          scopes_supported: [Scope.OPENID],
          subject_syntax_types_supported: ['did:ethr:', SubjectSyntaxTypesSupportedValues.DID],
          subject_types_supported: [SubjectType.PAIRWISE],
          vp_formats: {
            ldp_vc: {
              proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
            },
          },
          logo_uri: VERIFIER_LOGO_FOR_CLIENT,
          client_name: VERIFIER_NAME_FOR_CLIENT,
          'client_name#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100307',
          client_purpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'client_purpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        },
        /*registration: {
          jwks_uri: `https://dev.uniresolver.io/1.0/identifiers/${mockEntity.did}`,
          // jwks_uri: `https://dev.uniresolver.io/1.0/identifiers/${mockEntity.did};transform-keys=jwks`,
          id_token_signed_response_alg: KeyAlgo.ES256K,
      },*/
      };
      const privateKey = await importJWK(mockEntity.jwk, KeyAlgo.ES256K);
      const jwt = await new SignJWT(payload).setProtectedHeader(header).sign(privateKey);

      const optsVerify: VerifyAuthenticationRequestOpts = {
        verification: {
          mode: VerificationMode.INTERNAL,
          resolveOpts: {
            subjectSyntaxTypesSupported: ['did:ethr'],
          },
        },
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        verifyCallback: async (_args: IVerifyCallbackArgs): Promise<IVerifyCredentialResult> => ({ verified: true }),
      };
      await expect(AuthenticationRequest.verifyJWT(jwt, optsVerify)).resolves.toBeDefined();
    },
    UNIT_TEST_TIMEOUT
  );
});

describe('verifyJWT should', () => {
  it('throw VERIFY_BAD_PARAMETERS when no JWT is passed', async () => {
    expect.assertions(1);
    await expect(AuthenticationRequest.verifyJWT(undefined as never, undefined as never)).rejects.toThrow(SIOPErrors.VERIFY_BAD_PARAMS);
  });

  it('throw VERIFY_BAD_PARAMETERS when no responseOpts is passed', async () => {
    expect.assertions(1);
    await expect(AuthenticationRequest.verifyJWT('a valid JWT', undefined as never)).rejects.toThrow(SIOPErrors.VERIFY_BAD_PARAMS);
  });

  it('throw VERIFY_BAD_PARAMETERS when no responseOpts.verification is passed', async () => {
    expect.assertions(1);
    await expect(AuthenticationRequest.verifyJWT('a valid JWT', {} as never)).rejects.toThrow(SIOPErrors.VERIFY_BAD_PARAMS);
  });

  it('throw BAD_NONCE when a different nonce is supplied during verification', async () => {
    expect.assertions(1);
    const requestOpts: AuthenticationRequestOpts = {
      clientId: 'test_client_id',
      scope: 'test',
      responseType: 'id_token',
      checkLinkedDomain: CheckLinkedDomain.NEVER,
      requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
      redirectUri: EXAMPLE_REDIRECT_URL,
      requestBy: {
        type: PassBy.REFERENCE,
        referenceUri: EXAMPLE_REFERENCE_URL,
      },
      nonce: 'expected nonce',
      signatureType: {
        hexPrivateKey:
          'd474ffdb3ea75fbb3f07673e67e52002a3b7eb42767f709f4100acf493c7fc8743017577997b72e7a8b4bce8c32c8e78fd75c1441e95d6aaa888056d1200beb3',
        did: 'did:key:z6MkixpejjET5qJK4ebN5m3UcdUPmYV4DPSCs1ALH8x2UCfc',
        kid: 'did:key:z6MkixpejjET5qJK4ebN5m3UcdUPmYV4DPSCs1ALH8x2UCfc#z6MkixpejjET5qJK4ebN5m3UcdUPmYV4DPSCs1ALH8x2UCfc',
      },
      registration: {
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID, Scope.OPENID_DIDAUTHN],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256K],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256K],
        subjectSyntaxTypesSupported: ['did:ethr:', SubjectSyntaxTypesSupportedValues.DID],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        registrationBy: {
          type: PassBy.VALUE,
        },
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100308',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
    };

    const requestWithJWT = await AuthenticationRequest.createJWT(requestOpts);

    const verifyOpts: VerifyAuthenticationRequestOpts = {
      verification: {
        mode: VerificationMode.INTERNAL,
        resolveOpts: {
          subjectSyntaxTypesSupported: ['key'],
        },
      },
      nonce: 'This nonce is different and should throw error',
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      verifyCallback: async (_args: IVerifyCallbackArgs): Promise<IVerifyCredentialResult> => ({ verified: true }),
    };

    // expect.assertions(1);
    await expect(AuthenticationRequest.verifyJWT(requestWithJWT.jwt, verifyOpts)).rejects.toThrow(SIOPErrors.BAD_NONCE);
  });
  it(
    'succeed if a valid JWT is passed',
    async () => {
      const mockEntity = await mockedGetEnterpriseAuthToken('COMPANY AA INC');
      /*const header = {
        alg: KeyAlgo.ES256K,
        typ: "JWT",
        kid: `${mockEntity.did}#controller`,
    };
    const state = State.getState();*/
      const requestOpts: AuthenticationRequestOpts = {
        clientId: 'test_client_id',
        scope: 'test',
        responseType: 'id_token',
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        authorizationEndpoint: '',
        redirectUri: 'https://acme.com/hello',
        requestBy: { type: PassBy.REFERENCE, referenceUri: 'https://my-request.com/here' },
        signatureType: {
          hexPrivateKey: mockEntity.hexPrivateKey,
          did: mockEntity.did,
          kid: `${mockEntity.did}#controller`,
        },
        registration: {
          responseTypesSupported: [ResponseType.ID_TOKEN],
          scopesSupported: [Scope.OPENID, Scope.OPENID_DIDAUTHN],
          subjectTypesSupported: [SubjectType.PAIRWISE],
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256K],
          requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256K],
          subjectSyntaxTypesSupported: ['did:ethr:'],
          vpFormatsSupported: {
            ldp_vc: {
              proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
            },
          },
          registrationBy: { type: PassBy.VALUE },
          logoUri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100309',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        },
      };
      const requestWithJWT = await AuthenticationRequest.createJWT(requestOpts);

      const verifyOpts: VerifyAuthenticationRequestOpts = {
        verification: {
          mode: VerificationMode.INTERNAL,
          resolveOpts: {
            subjectSyntaxTypesSupported: ['did:ethr'],
          },
        },
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        verifyCallback: async (_args: IVerifyCallbackArgs): Promise<IVerifyCredentialResult> => ({ verified: true }),
      };

      const verifyJWT = await AuthenticationRequest.verifyJWT(requestWithJWT.jwt, verifyOpts);
      expect(verifyJWT.jwt).toMatch(/^eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXRocjowe.*$/);
    },
    UNIT_TEST_TIMEOUT
  );
});

describe('OP and RP communication should', () => {
  it('work if both support the same did methods', () => {
    const actualResult = metadata.verify();
    const expectedResult = {
      vp_formats: {
        jwt_vc: { alg: [SigningAlgo.ES256, SigningAlgo.ES256K] },
        ldp_vc: {
          proof_type: ['EcdsaSecp256k1Signature2019', 'EcdsaSecp256k1Signature2019'],
        },
      },
      subject_syntax_types_supported: ['did:web'],
    };
    expect(actualResult).toEqual(expectedResult);
  });

  it('work if RP supports any OP did methods', () => {
    metadata.opMetadata.vp_formats = {
      ldp_vc: {
        proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
      },
    };
    metadata.rpMetadata.subject_syntax_types_supported = ['did:web'];
    expect(metadata.verify()).toEqual({
      subject_syntax_types_supported: ['did:web'],
      vp_formats: {
        ldp_vc: {
          proof_type: ['EcdsaSecp256k1Signature2019', 'EcdsaSecp256k1Signature2019'],
        },
      },
    });
  });

  it('work if RP supports any OP credential formats', () => {
    metadata.opMetadata.vp_formats = {
      ldp_vc: {
        proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
      },
    };
    const result = metadata.verify();
    expect(result['subject_syntax_types_supported']).toContain('did:web');
    expect(result['vp_formats']).toStrictEqual({
      ldp_vc: {
        proof_type: ['EcdsaSecp256k1Signature2019', 'EcdsaSecp256k1Signature2019'],
      },
    });
  });

  it('not work if RP does not support any OP did method', () => {
    metadata.rpMetadata.subject_syntax_types_supported = ['did:notsupported'];
    expect(() => metadata.verify()).toThrowError(SIOPErrors.DID_METHODS_NOT_SUPORTED);
  });

  it('not work if RP does not support any OP credentials', () => {
    metadata.rpMetadata.vp_formats = undefined;
    expect(() => metadata.verify()).toThrowError(SIOPErrors.CREDENTIALS_FORMATS_NOT_PROVIDED);
  });
});
