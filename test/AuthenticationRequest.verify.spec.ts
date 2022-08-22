import { ProofType } from '@sphereon/pex';
import * as dotenv from 'dotenv';
import parseJwk from 'jose/jwk/parse';
import SignJWT from 'jose/jwt/sign';

import { AuthenticationRequest, SIOP } from '../src/main';
import { State } from '../src/main/functions';
import SIOPErrors from '../src/main/types/Errors';
import {
  AuthenticationRequestOpts,
  LinkedDomainValidationMode,
  PassBy,
  ResponseContext,
  ResponseMode,
  ResponseType,
  Scope,
  SigningAlgo,
  SubjectIdentifierType,
  SubjectType,
  VerificationMode,
  VerifyAuthenticationRequestOpts,
} from '../src/main/types/SIOP.types';

import { metadata, mockedGetEnterpriseAuthToken } from './TestUtils';

const EXAMPLE_REDIRECT_URL = 'https://acme.com/hello';
const EXAMPLE_REFERENCE_URL = 'https://rp.acme.com/siop/jwts';

dotenv.config();

describe('SIOP Request Validation', () => {
  it('should verify', async () => {
    // const mockVerifyJwt = verifyJWT as jest.Mock;
    // const mockDecodeJWT = decodeJWT as jest.Mock;
    expect.assertions(1);
    const mockEntity = await mockedGetEnterpriseAuthToken('COMPANY AA INC');
    const header = {
      alg: SIOP.KeyAlgo.ES256K,
      typ: 'JWT',
      kid: `${mockEntity.did}#controller`,
    };
    const state = State.getState();
    const payload: SIOP.AuthenticationRequestPayload = {
      iss: mockEntity.did,
      aud: 'test',
      response_mode: ResponseMode.POST,
      response_context: ResponseContext.RP,
      redirect_uri: '',
      scope: SIOP.Scope.OPENID,
      response_type: SIOP.ResponseType.ID_TOKEN,
      client_id: 'http://localhost:8080/test',
      state,
      nonce: State.getNonce(state),
      registration: {
        id_token_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256K],
        request_object_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256K],
        response_types_supported: [ResponseType.ID_TOKEN],
        scopes_supported: [Scope.OPENID],
        subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
        subject_types_supported: [SubjectType.PAIRWISE],
        vp_formats: {
          ldp_vc: {
            proof_type: [ProofType.EcdsaSecp256k1Signature2019, ProofType.EcdsaSecp256k1Signature2019],
          },
        },
      },
      /*registration: {
          jwks_uri: `https://dev.uniresolver.io/1.0/identifiers/${mockEntity.did}`,
          // jwks_uri: `https://dev.uniresolver.io/1.0/identifiers/${mockEntity.did};transform-keys=jwks`,
          id_token_signed_response_alg: SIOP.KeyAlgo.ES256K,
      },*/
    };
    const privateKey = await parseJwk(mockEntity.jwk, SIOP.KeyAlgo.ES256K);
    const jwt = await new SignJWT(payload).setProtectedHeader(header).sign(privateKey);

    const optsVerify: SIOP.VerifyAuthenticationRequestOpts = {
      verification: {
        mode: VerificationMode.INTERNAL,
        resolveOpts: {
          subjectSyntaxTypesSupported: ['ethr'],
        },
      },
    };
    await expect(AuthenticationRequest.verifyJWT(jwt, optsVerify)).resolves.toBeDefined();
  });
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
    const requestOpts: SIOP.AuthenticationRequestOpts = {
      linkedDomainValidationMode: LinkedDomainValidationMode.NEVER,
      requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
      redirectUri: EXAMPLE_REDIRECT_URL,
      requestBy: {
        type: SIOP.PassBy.REFERENCE,
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
        subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [ProofType.EcdsaSecp256k1Signature2019, ProofType.EcdsaSecp256k1Signature2019],
          },
        },
        registrationBy: {
          type: SIOP.PassBy.VALUE,
        },
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
    };

    // expect.assertions(1);
    await expect(AuthenticationRequest.verifyJWT(requestWithJWT.jwt, verifyOpts)).rejects.toThrow(SIOPErrors.BAD_NONCE);
  });
  it('succeed if a valid JWT is passed', async () => {
    const mockEntity = await mockedGetEnterpriseAuthToken('COMPANY AA INC');
    /*const header = {
        alg: SIOP.KeyAlgo.ES256K,
        typ: "JWT",
        kid: `${mockEntity.did}#controller`,
    };
    const state = State.getState();*/
    const requestOpts: AuthenticationRequestOpts = {
      linkedDomainValidationMode: LinkedDomainValidationMode.NEVER,
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
            proof_type: [ProofType.EcdsaSecp256k1Signature2019, ProofType.EcdsaSecp256k1Signature2019],
          },
        },
        registrationBy: { type: PassBy.VALUE },
      },
    };
    const requestWithJWT = await AuthenticationRequest.createJWT(requestOpts);

    const verifyOpts: VerifyAuthenticationRequestOpts = {
      verification: {
        mode: VerificationMode.INTERNAL,
        resolveOpts: {
          subjectSyntaxTypesSupported: ['ethr'],
        },
      },
    };

    const verifyJWT = await AuthenticationRequest.verifyJWT(requestWithJWT.jwt, verifyOpts);
    expect(verifyJWT.jwt).toMatch(/^eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXRocjowe.*$/);
  });
});

describe('OP and RP communication should', () => {
  it('work if both support the same did methods', () => {
    metadata.verify();
    expect(metadata.verify()).toEqual({
      vp_formats: {
        jwt_vc: { alg: [SigningAlgo.ES256, SigningAlgo.ES256K] },
        ldp_vc: {
          proof_type: ['EcdsaSecp256k1Signature2019', 'EcdsaSecp256k1Signature2019'],
        },
      },
      subject_syntax_types_supported: [SubjectIdentifierType.DID, 'did:web'],
    });
  });

  it('work if RP supports any OP did methods', () => {
    metadata.opMetadata.vp_formats = {
      ldp_vc: {
        proof_type: [ProofType.EcdsaSecp256k1Signature2019, ProofType.EcdsaSecp256k1Signature2019],
      },
    };
    metadata.rpMetadata.subject_syntax_types_supported = ['did:web', SubjectIdentifierType.DID];
    expect(metadata.verify()).toEqual({
      subject_syntax_types_supported: ['did:web', SubjectIdentifierType.DID],
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
        proof_type: [ProofType.EcdsaSecp256k1Signature2019, ProofType.EcdsaSecp256k1Signature2019],
      },
    };
    const result = metadata.verify();
    expect(result['subject_syntax_types_supported']).toContain(SubjectIdentifierType.DID);
    expect(result['subject_syntax_types_supported']).toContain('did:web');
    expect(result['vp_formats']).toStrictEqual({
      ldp_vc: {
        proof_type: ['EcdsaSecp256k1Signature2019', 'EcdsaSecp256k1Signature2019'],
      },
    });
  });

  it('not work if RP does not support any OP did method', () => {
    metadata.rpMetadata.subject_syntax_types_supported = ['did:notsupported:', SubjectIdentifierType.DID];
    expect(() => metadata.verify()).toThrowError(SIOPErrors.DID_METHODS_NOT_SUPORTED);
  });

  it('not work if RP does not support any OP credentials', () => {
    metadata.rpMetadata.vp_formats = undefined;
    expect(() => metadata.verify()).toThrowError(SIOPErrors.CREDENTIALS_FORMATS_NOT_PROVIDED);
  });
});
