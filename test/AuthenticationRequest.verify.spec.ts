import { IProofType } from '@sphereon/ssi-types';
import { IVerifyCallbackArgs, IVerifyCredentialResult } from '@sphereon/wellknown-dids-client';
import Ajv from 'ajv';
import * as dotenv from 'dotenv';

import {
  AuthorizationRequest,
  CreateAuthorizationRequestOpts,
  PassBy,
  RequestObject,
  ResponseType,
  Scope,
  SigningAlgo,
  SubjectSyntaxTypesSupportedValues,
  SubjectType,
  SupportedVersion,
  VerificationMode,
  VerifyAuthorizationRequestOpts,
} from '../src';
import { RPRegistrationMetadataPayloadSchemaObj } from '../src/schemas';
import SIOPErrors from '../src/types/Errors';

import { metadata, mockedGetEnterpriseAuthToken, WELL_KNOWN_OPENID_FEDERATION } from './TestUtils';
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

describe('verifyJWT should', () => {
  it('should compile schema', async () => {
    const schema = {
      $schema: 'http://json-schema.org/draft-07/schema#',
      $ref: '#/definitions/RPRegistrationMetadataPayload',
      definitions: {
        RPRegistrationMetadataPayload: {
          type: 'object',
          properties: {
            client_id: {
              anyOf: [
                {
                  type: 'string',
                },
                {},
              ],
            },
            id_token_signing_alg_values_supported: {
              anyOf: [
                {
                  type: 'array',
                  items: {
                    $ref: '#/definitions/SigningAlgo',
                  },
                },
                {
                  $ref: '#/definitions/SigningAlgo',
                },
              ],
            },
            request_object_signing_alg_values_supported: {
              anyOf: [
                {
                  type: 'array',
                  items: {
                    $ref: '#/definitions/SigningAlgo',
                  },
                },
                {
                  $ref: '#/definitions/SigningAlgo',
                },
              ],
            },
            response_types_supported: {
              anyOf: [
                {
                  type: 'array',
                  items: {
                    $ref: '#/definitions/ResponseType',
                  },
                },
                {
                  $ref: '#/definitions/ResponseType',
                },
              ],
            },
            scopes_supported: {
              anyOf: [
                {
                  type: 'array',
                  items: {
                    $ref: '#/definitions/Scope',
                  },
                },
                {
                  $ref: '#/definitions/Scope',
                },
              ],
            },
            subject_types_supported: {
              anyOf: [
                {
                  type: 'array',
                  items: {
                    $ref: '#/definitions/SubjectType',
                  },
                },
                {
                  $ref: '#/definitions/SubjectType',
                },
              ],
            },
            subject_syntax_types_supported: {
              type: 'array',
              items: {
                type: 'string',
              },
            },
            vp_formats: {
              anyOf: [
                {
                  $ref: '#/definitions/Format',
                },
                {},
              ],
            },
            client_name: {
              anyOf: [
                {
                  type: 'string',
                },
                {},
              ],
            },
            logo_uri: {
              anyOf: [
                {},
                {
                  type: 'string',
                },
              ],
            },
            client_purpose: {
              anyOf: [
                {},
                {
                  type: 'string',
                },
              ],
            },
          },
        },
        SigningAlgo: {
          type: 'string',
          enum: ['EdDSA', 'RS256', 'ES256', 'ES256K'],
        },
        ResponseType: {
          type: 'string',
          enum: ['id_token', 'vp_token'],
        },
        Scope: {
          type: 'string',
          enum: ['openid', 'openid did_authn', 'profile', 'email', 'address', 'phone'],
        },
        SubjectType: {
          type: 'string',
          enum: ['public', 'pairwise'],
        },
        Format: {
          type: 'object',
          properties: {
            jwt: {
              $ref: '#/definitions/JwtObject',
            },
            jwt_vc: {
              $ref: '#/definitions/JwtObject',
            },
            jwt_vp: {
              $ref: '#/definitions/JwtObject',
            },
            ldp: {
              $ref: '#/definitions/LdpObject',
            },
            ldp_vc: {
              $ref: '#/definitions/LdpObject',
            },
            ldp_vp: {
              $ref: '#/definitions/LdpObject',
            },
          },
          additionalProperties: false,
        },
        JwtObject: {
          type: 'object',
          properties: {
            alg: {
              type: 'array',
              items: {
                type: 'string',
              },
            },
          },
          required: ['alg'],
          additionalProperties: false,
        },
        LdpObject: {
          type: 'object',
          properties: {
            proof_type: {
              type: 'array',
              items: {
                type: 'string',
              },
            },
          },
          required: ['proof_type'],
          additionalProperties: false,
        },
      },
    };
    const ajv = new Ajv({ allowUnionTypes: true, strict: false });
    ajv.compile(RPRegistrationMetadataPayloadSchemaObj);
    ajv.compile(schema);
  });
  it('throw VERIFY_BAD_PARAMETERS when no JWT is passed', async () => {
    expect.assertions(1);
    await expect(AuthorizationRequest.verify(undefined as never, undefined as never)).rejects.toThrow(SIOPErrors.VERIFY_BAD_PARAMS);
  });

  it('throw VERIFY_BAD_PARAMETERS when no responseOpts is passed', async () => {
    expect.assertions(1);
    await expect(AuthorizationRequest.verify('an invalid JWT bypassing the undefined check', undefined as never)).rejects.toThrow(
      SIOPErrors.VERIFY_BAD_PARAMS
    );
  });

  it('throw VERIFY_BAD_PARAMETERS when no responseOpts.verification is passed', async () => {
    expect.assertions(1);
    await expect(AuthorizationRequest.verify('an invalid JWT bypassing the undefined check', {} as never)).rejects.toThrow(
      SIOPErrors.VERIFY_BAD_PARAMS
    );
  });

  it('throw BAD_NONCE when a different nonce is supplied during verification', async () => {
    expect.assertions(1);
    const requestOpts: CreateAuthorizationRequestOpts = {
      version: SupportedVersion.SIOPv2_ID1,

      requestObject: {
        passBy: PassBy.REFERENCE,
        reference_uri: EXAMPLE_REFERENCE_URL,

        signature: {
          hexPrivateKey:
            'd474ffdb3ea75fbb3f07673e67e52002a3b7eb42767f709f4100acf493c7fc8743017577997b72e7a8b4bce8c32c8e78fd75c1441e95d6aaa888056d1200beb3',
          did: 'did:key:z6MkixpejjET5qJK4ebN5m3UcdUPmYV4DPSCs1ALH8x2UCfc',
          kid: 'did:key:z6MkixpejjET5qJK4ebN5m3UcdUPmYV4DPSCs1ALH8x2UCfc#z6MkixpejjET5qJK4ebN5m3UcdUPmYV4DPSCs1ALH8x2UCfc',
          alg: SigningAlgo.EDDSA,
        },
        payload: {
          state: 'expected state',
          client_id: WELL_KNOWN_OPENID_FEDERATION,
          scope: 'test',
          response_type: 'id_token',
          request_object_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          redirect_uri: EXAMPLE_REDIRECT_URL,
          nonce: 'expected nonce',
        },
      },
      clientMetadata: {
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID, Scope.OPENID_DIDAUTHN],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256K],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256K],
        subject_syntax_types_supported: ['did:ethr:', SubjectSyntaxTypesSupportedValues.DID],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100308',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
    };

    const requestObject = await RequestObject.fromOpts(requestOpts);

    const verifyOpts: VerifyAuthorizationRequestOpts = {
      verification: {
        mode: VerificationMode.INTERNAL,
        resolveOpts: {
          subjectSyntaxTypesSupported: ['did:key'],
        },
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        wellknownDIDVerifyCallback: async (_args: IVerifyCallbackArgs): Promise<IVerifyCredentialResult> => ({ verified: true }),
      },
      correlationId: '1234',
      supportedVersions: [SupportedVersion.SIOPv2_ID1],
      nonce: 'This nonce is different and should throw error',
    };

    // expect.assertions(1);
    await expect(AuthorizationRequest.verify(await requestObject.toJwt(), verifyOpts)).rejects.toThrow(SIOPErrors.BAD_NONCE);
  });
  it(
    'succeed if a valid JWT is passed',
    async () => {
      const mockEntity = await mockedGetEnterpriseAuthToken('COMPANY AA INC');
      const requestOpts: CreateAuthorizationRequestOpts = {
        version: SupportedVersion.SIOPv2_ID1,

        requestObject: {
          passBy: PassBy.REFERENCE,
          reference_uri: 'https://my-request.com/here',
          signature: {
            hexPrivateKey: mockEntity.hexPrivateKey,
            did: mockEntity.did,
            kid: `${mockEntity.did}#controller`,
            alg: SigningAlgo.ES256K,
          },
          payload: {
            client_id: WELL_KNOWN_OPENID_FEDERATION,
            scope: 'test',
            response_type: 'id_token',
            state: '12345',
            nonce: '12345',
            request_object_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
            authorization_endpoint: '',
            redirect_uri: 'https://acme.com/hello',
          },
        },
        clientMetadata: {
          client_id: WELL_KNOWN_OPENID_FEDERATION,
          responseTypesSupported: [ResponseType.ID_TOKEN],
          scopesSupported: [Scope.OPENID, Scope.OPENID_DIDAUTHN],
          subjectTypesSupported: [SubjectType.PAIRWISE],
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256K],
          requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256K],
          subject_syntax_types_supported: ['did:ethr:'],
          vpFormatsSupported: {
            ldp_vc: {
              proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
            },
          },
          passBy: PassBy.VALUE,
          logo_uri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100309',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        },
      };
      const requestObject = await RequestObject.fromOpts(requestOpts);

      const verifyOpts: VerifyAuthorizationRequestOpts = {
        verification: {
          mode: VerificationMode.INTERNAL,
          resolveOpts: {
            subjectSyntaxTypesSupported: ['did:ethr'],
          },
          // eslint-disable-next-line @typescript-eslint/no-unused-vars
          wellknownDIDVerifyCallback: async (_args: IVerifyCallbackArgs): Promise<IVerifyCredentialResult> => ({ verified: true }),
        },
        supportedVersions: [SupportedVersion.SIOPv2_ID1],
        correlationId: '1234',
      };

      const verifyJWT = await AuthorizationRequest.verify(await requestObject.toJwt(), verifyOpts);
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
