import { IPresentationDefinition } from '@sphereon/pex';
import { ICredential, IProofType, IVerifiableCredential, IVerifiablePresentation } from '@sphereon/ssi-types';
import { IVerifyCallbackArgs, IVerifyCredentialResult } from '@sphereon/wellknown-dids-client';

import {
  AuthenticationRequest,
  AuthenticationRequestOpts,
  AuthenticationResponse,
  AuthenticationResponseOpts,
  CheckLinkedDomain,
  PassBy,
  PresentationExchange,
  PresentationLocation,
  PresentationSignCallback,
  ResponseIss,
  ResponseMode,
  ResponseType,
  Scope,
  SigningAlgo,
  SubjectIdentifierType,
  SubjectType,
  VerifiablePresentationTypeFormat,
  VerificationMode,
  VerifyAuthenticationRequestOpts,
} from '../src/main';
import SIOPErrors from '../src/main/types/Errors';

import { mockedGetEnterpriseAuthToken } from './TestUtils';
import {
  UNIT_TEST_TIMEOUT,
  VERIFIER_LOGO_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT_NL,
  VERIFIERZ_PURPOSE_TO_VERIFY,
  VERIFIERZ_PURPOSE_TO_VERIFY_NL,
} from './data/mockedData';

jest.setTimeout(30000);

const EXAMPLE_REFERENCE_URL = 'https://rp.acme.com/siop/jwts';
const HEX_KEY = 'f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f';
const DID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0';
const KID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#keys-1';

const validButExpiredJWT =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1NjEzNTEyOTAsImV4cCI6MTU2MTM1MTg5MCwicmVzcG9uc2VfdHlwZSI6ImlkX3Rva2VuIiwic2NvcGUiOiJvcGVuaWQiLCJjbGllbnRfaWQiOiJkaWQ6ZXRocjoweDQ4NzNFQzc0MUQ4RDFiMjU4YUYxQjUyNDczOEIzNjNhQTIxOTk5MjAiLCJyZWRpcmVjdF91cmkiOiJodHRwczovL2FjbWUuY29tL2hlbGxvIiwiaXNzIjoiZGlkOmV0aHI6MHg0ODczRUM3NDFEOEQxYjI1OGFGMUI1MjQ3MzhCMzYzYUEyMTk5OTIwIiwicmVzcG9uc2VfbW9kZSI6InBvc3QiLCJyZXNwb25zZV9jb250ZXh0IjoicnAiLCJub25jZSI6IlVTLU9wY1FHLXlXS3lWUTRlTU53UFB3Um10UVVGdmpkOHJXeTViRC10MXciLCJzdGF0ZSI6IjdmMjcxYzZjYjk2ZThmOThhMzkxYWU5ZCIsInJlZ2lzdHJhdGlvbiI6eyJpZF90b2tlbl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkVkRFNBIiwiRVMyNTYiXSwicmVxdWVzdF9vYmplY3Rfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJFZERTQSIsIkVTMjU2Il0sInJlc3BvbnNlX3R5cGVzX3N1cHBvcnRlZCI6WyJpZF90b2tlbiJdLCJzY29wZXNfc3VwcG9ydGVkIjpbIm9wZW5pZCBkaWRfYXV0aG4iLCJvcGVuaWQiXSwic3ViamVjdF90eXBlc19zdXBwb3J0ZWQiOlsicGFpcndpc2UiXSwic3ViamVjdF9zeW50YXhfdHlwZXNfc3VwcG9ydGVkIjpbImRpZDpldGhyOiIsImRpZCJdLCJ2cF9mb3JtYXRzIjp7ImxkcF92YyI6eyJwcm9vZl90eXBlIjpbIkVjZHNhU2VjcDI1NmsxU2lnbmF0dXJlMjAxOSIsIkVjZHNhU2VjcDI1NmsxU2lnbmF0dXJlMjAxOSJdfX19fQ.Wd6I7BT7fWZSuYozUwHnyEsEoAe6OjdyzEEKXnWk8bY';

const EXAMPLE_REDIRECT_URL = 'https://acme.com/hello';

describe('create JWT from Request JWT should', () => {
  const responseOpts: AuthenticationResponseOpts = {
    checkLinkedDomain: CheckLinkedDomain.NEVER,
    redirectUri: EXAMPLE_REDIRECT_URL,
    registration: {
      authorizationEndpoint: 'www.myauthorizationendpoint.com',
      responseTypesSupported: [ResponseType.ID_TOKEN],
      subjectSyntaxTypesSupported: ['did:web'],
      vpFormats: {
        ldp_vc: {
          proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
        },
      },
      issuer: ResponseIss.SELF_ISSUED_V2,
      registrationBy: {
        type: PassBy.REFERENCE,
        referenceUri: EXAMPLE_REFERENCE_URL,
      },
      logoUri: VERIFIER_LOGO_FOR_CLIENT,
      clientName: VERIFIER_NAME_FOR_CLIENT,
      'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100310',
      clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
      'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
    },
    signatureType: {
      did: DID,
      hexPrivateKey: HEX_KEY,
      kid: KID,
    },
    did: DID,
    responseMode: ResponseMode.POST,
  };
  const verifyOpts: VerifyAuthenticationRequestOpts = {
    verification: {
      resolveOpts: {
        subjectSyntaxTypesSupported: ['did:ethr'],
      },
      mode: VerificationMode.INTERNAL,
    },
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    verifyCallback: async (_args: IVerifyCallbackArgs): Promise<IVerifyCredentialResult> => ({ verified: true }),
  };

  it('throw NO_JWT when no jwt is passed', async () => {
    expect.assertions(1);
    await expect(AuthenticationResponse.createJWTFromRequestJWT(undefined as never, responseOpts, verifyOpts)).rejects.toThrow(SIOPErrors.NO_JWT);
  });
  it('throw BAD_PARAMS when no responseOpts is passed', async () => {
    expect.assertions(1);
    await expect(AuthenticationResponse.createJWTFromRequestJWT(validButExpiredJWT, undefined as never, verifyOpts)).rejects.toThrow(
      SIOPErrors.BAD_PARAMS
    );
  });
  it('throw VERIFY_BAD_PARAMS when no verifyOpts is passed', async () => {
    expect.assertions(1);
    await expect(AuthenticationResponse.createJWTFromRequestJWT(validButExpiredJWT, responseOpts, undefined as never)).rejects.toThrow(
      SIOPErrors.VERIFY_BAD_PARAMS
    );
  });

  it('throw JWT_ERROR when expired but valid JWT is passed in', async () => {
    expect.assertions(1);
    const mockReqEntity = await mockedGetEnterpriseAuthToken('REQ COMPANY');
    const mockResEntity = await mockedGetEnterpriseAuthToken('RES COMPANY');
    const requestOpts: AuthenticationRequestOpts = {
      clientId: 'test_client_id',
      scope: 'test',
      responseType: 'id_token',
      checkLinkedDomain: CheckLinkedDomain.NEVER,
      redirectUri: EXAMPLE_REDIRECT_URL,
      requestBy: { type: PassBy.REFERENCE, referenceUri: 'https://my-request.com/here' },
      signatureType: {
        hexPrivateKey: mockReqEntity.hexPrivateKey,
        did: mockReqEntity.did,
        kid: `${mockReqEntity.did}#controller`,
      },
      registration: {
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        registrationBy: { type: PassBy.VALUE },
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100311',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
    };
    const responseOpts: AuthenticationResponseOpts = {
      checkLinkedDomain: CheckLinkedDomain.NEVER,
      redirectUri: EXAMPLE_REDIRECT_URL,
      registration: {
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        issuer: ResponseIss.SELF_ISSUED_V2,
        responseTypesSupported: [ResponseType.ID_TOKEN],
        subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
        vpFormats: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        registrationBy: {
          type: PassBy.REFERENCE,
          referenceUri: EXAMPLE_REFERENCE_URL,
        },
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100312',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
      signatureType: {
        did: mockResEntity.did,
        hexPrivateKey: mockResEntity.hexPrivateKey,
        kid: `${mockResEntity.did}#controller`,
      },
      did: mockResEntity.did, // FIXME: Why do we need this, isn't this handled in the signature type already?
      responseMode: ResponseMode.POST,
    };

    jest.useFakeTimers().setSystemTime(new Date('2020-01-01'));
    jest.useFakeTimers().setSystemTime(new Date('2020-01-01'));

    const requestWithJWT = await AuthenticationRequest.createJWT(requestOpts);

    jest.useRealTimers();
    await expect(AuthenticationResponse.createJWTFromRequestJWT(requestWithJWT.jwt, responseOpts, verifyOpts)).rejects.toThrow(
      /invalid_jwt: JWT has expired: exp: 1577837400/
    );
  });

  it(
    'succeed when valid JWT is passed in',
    async () => {
      expect.assertions(1);

      const mockReqEntity = await mockedGetEnterpriseAuthToken('REQ COMPANY');
      const mockResEntity = await mockedGetEnterpriseAuthToken('RES COMPANY');
      const requestOpts: AuthenticationRequestOpts = {
        clientId: 'test_client_id',
        scope: 'test',
        responseType: 'id_token',
        checkLinkedDomain: CheckLinkedDomain.NEVER,
        redirectUri: EXAMPLE_REDIRECT_URL,
        requestBy: { type: PassBy.REFERENCE, referenceUri: 'https://my-request.com/here' },
        signatureType: {
          hexPrivateKey: mockReqEntity.hexPrivateKey,
          did: mockReqEntity.did,
          kid: `${mockReqEntity.did}#controller`,
        },
        registration: {
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
          requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          responseTypesSupported: [ResponseType.ID_TOKEN],
          scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
          subjectTypesSupported: [SubjectType.PAIRWISE],
          vpFormatsSupported: {
            ldp_vc: {
              proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
            },
          },
          registrationBy: { type: PassBy.VALUE },
          logoUri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100313',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        },
      };
      const responseOpts: AuthenticationResponseOpts = {
        checkLinkedDomain: CheckLinkedDomain.NEVER,
        redirectUri: EXAMPLE_REDIRECT_URL,
        registration: {
          authorizationEndpoint: 'www.myauthorizationendpoint.com',
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          issuer: ResponseIss.SELF_ISSUED_V2,
          responseTypesSupported: [ResponseType.ID_TOKEN],
          subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
          vpFormats: {
            ldp_vc: {
              proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
            },
          },
          registrationBy: {
            type: PassBy.REFERENCE,
            referenceUri: EXAMPLE_REFERENCE_URL,
          },
          logoUri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100314',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        },
        signatureType: {
          did: mockResEntity.did,
          hexPrivateKey: mockResEntity.hexPrivateKey,
          kid: `${mockResEntity.did}#controller`,
        },
        did: mockResEntity.did, // FIXME: Why do we need this, isn't this handled in the signature type already?
        responseMode: ResponseMode.POST,
      };

      const requestWithJWT = await AuthenticationRequest.createJWT(requestOpts);
      console.log(JSON.stringify(await AuthenticationResponse.createJWTFromRequestJWT(requestWithJWT.jwt, responseOpts, verifyOpts)));
      await expect(AuthenticationResponse.createJWTFromRequestJWT(requestWithJWT.jwt, responseOpts, verifyOpts)).resolves.toBeDefined();
    },
    UNIT_TEST_TIMEOUT
  );

  it('succeed when valid JWT with PD is passed in', async () => {
    expect.assertions(1);

    const mockReqEntity = await mockedGetEnterpriseAuthToken('REQ COMPANY');
    const mockResEntity = await mockedGetEnterpriseAuthToken('RES COMPANY');
    const presentationSignCallback: PresentationSignCallback = async (_args) => ({
      ..._args.presentation,
      proof: {
        type: 'RsaSignature2018',
        created: '2018-09-14T21:19:10Z',
        proofPurpose: 'authentication',
        verificationMethod: 'did:example:ebfeb1f712ebc6f1c276e12ec21#keys-1',
        challenge: '1f44d55f-f161-4938-a659-f8026467f126',
        domain: '4jt78h47fh47',
        jws: 'eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..kTCYt5XsITJX1CxPCT8yAV-TVIw5WEuts01mq-pQy7UJiN5mgREEMGlv50aqzpqh4Qq_PbChOMqsLfRoPsnsgxD-WUcX16dUOqV0G_zS245-kronKb78cPktb3rk-BuQy72IFLN25DYuNzVBAh4vGHSrQyHUGlcTwLtjPAnKb78',
      },
    });
    const definition: IPresentationDefinition = {
      id: 'Credentials',
      input_descriptors: [
        {
          id: 'ID Card Credential',
          schema: [
            {
              uri: 'https://www.w3.org/2018/credentials/examples/v1/IDCardCredential',
            },
          ],
          constraints: {
            limit_disclosure: 'required',
            fields: [
              {
                path: ['$.issuer.id'],
                purpose: 'We can only verify bank accounts if they are attested by a source.',
                filter: {
                  type: 'string',
                  pattern: 'did:example:issuer',
                },
              },
            ],
          },
        },
      ],
    };
    const requestOpts: AuthenticationRequestOpts = {
      clientId: 'test_client_id',
      scope: 'test',
      responseType: 'id_token',
      checkLinkedDomain: CheckLinkedDomain.NEVER,
      redirectUri: EXAMPLE_REDIRECT_URL,
      requestBy: { type: PassBy.REFERENCE, referenceUri: 'https://my-request.com/here' },
      signatureType: {
        hexPrivateKey: mockReqEntity.hexPrivateKey,
        did: mockReqEntity.did,
        kid: `${mockReqEntity.did}#controller`,
      },
      registration: {
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        registrationBy: { type: PassBy.VALUE },
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100315',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
      claims: {
        presentationDefinitions: [
          {
            location: PresentationLocation.VP_TOKEN,
            definition: definition,
          },
        ],
      },
    };
    const vc: ICredential = {
      id: 'https://example.com/credentials/1872',
      type: ['VerifiableCredential', 'IDCardCredential'],
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/2018/credentials/examples/v1/IDCardCredential'],
      issuer: {
        id: 'did:example:issuer',
      },
      issuanceDate: '2010-01-01T19:23:24Z',
      credentialSubject: {
        given_name: 'Fredrik',
        family_name: 'Stremberg',
        birthdate: '1949-01-22',
      },
    };
    const vp: IVerifiablePresentation = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      presentation_submission: undefined,
      type: ['verifiablePresentation'],
      holder: 'did:example:holder',
      verifiableCredential: [vc as IVerifiableCredential],
      proof: undefined,
    };

    // fixme: This is probably here because the VC interface in the PEX is not correct
    /*vp['id'] = 'ebc6f1c2';
    vp['type'] = ['VerifiablePresentation'];
    vp['holder'] = 'did:example:holder';*/
    /*  vp.getVerifiableCredentials()[0]['@context'] = [
      'https://www.w3.org/2018/credentials/v1',
      'https://www.w3.org/2018/credentials/examples/v1/IDCardCredential',
    ];
    vp.getVerifiableCredentials()[0]['issuer'] = {
      id: 'did:example:issuer',
    };
    vp.getVerifiableCredentials()[0]['issuanceDate'] = '2010-01-01T19:23:24Z';
*/
    const pex = new PresentationExchange({
      did: 'did:example:holder',
      allVerifiableCredentials: vp.verifiableCredential,
    });
    await pex.selectVerifiableCredentialsForSubmission(definition);
    const result: IVerifiablePresentation = (await pex.submissionFrom(
      definition,
      vp.verifiableCredential,
      {},
      presentationSignCallback
    )) as IVerifiablePresentation;
    const responseOpts: AuthenticationResponseOpts = {
      checkLinkedDomain: CheckLinkedDomain.NEVER,
      redirectUri: EXAMPLE_REDIRECT_URL,
      registration: {
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        issuer: ResponseIss.SELF_ISSUED_V2,
        responseTypesSupported: [ResponseType.ID_TOKEN],
        registrationBy: {
          type: PassBy.REFERENCE,
          referenceUri: EXAMPLE_REFERENCE_URL,
        },
        subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
        vpFormats: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100316',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
      signatureType: {
        did: mockResEntity.did,
        hexPrivateKey: mockResEntity.hexPrivateKey,
        kid: `${mockResEntity.did}#controller`,
      },
      vp: [
        {
          location: PresentationLocation.VP_TOKEN,
          format: VerifiablePresentationTypeFormat.LDP_VP,
          presentation: result,
        },
      ],
      did: mockResEntity.did, // FIXME: Why do we need this, isn't this handled in the signature type already?
      responseMode: ResponseMode.POST,
    };

    const requestWithJWT = await AuthenticationRequest.createJWT(requestOpts);
    /* console.log(
      JSON.stringify(await AuthenticationResponse.createJWTFromRequestJWT(requestWithJWT.jwt, responseOpts, verifyOpts))
    );*/
    await expect(AuthenticationResponse.createJWTFromRequestJWT(requestWithJWT.jwt, responseOpts, verifyOpts)).resolves.toBeDefined();
  });

  it('succeed when valid JWT with PD is passed in for id_token', async () => {
    expect.assertions(1);

    const mockReqEntity = await mockedGetEnterpriseAuthToken('REQ COMPANY');
    const mockResEntity = await mockedGetEnterpriseAuthToken('RES COMPANY');
    const definition: IPresentationDefinition = {
      id: 'Credentials',
      input_descriptors: [
        {
          id: 'ID Card Credential',
          schema: [
            {
              uri: 'https://www.w3.org/2018/credentials/examples/v1/IDCardCredential',
            },
          ],
          constraints: {
            limit_disclosure: 'required',
            fields: [
              {
                path: ['$.issuer.id'],
                purpose: 'We can only verify bank accounts if they are attested by a source.',
                filter: {
                  type: 'string',
                  pattern: 'did:example:issuer',
                },
              },
            ],
          },
        },
      ],
    };
    const requestOpts: AuthenticationRequestOpts = {
      clientId: 'test_client_id',
      scope: 'test',
      responseType: 'token_id',
      checkLinkedDomain: CheckLinkedDomain.NEVER,
      redirectUri: EXAMPLE_REDIRECT_URL,
      requestBy: { type: PassBy.REFERENCE, referenceUri: 'https://my-request.com/here' },
      signatureType: {
        hexPrivateKey: mockReqEntity.hexPrivateKey,
        did: mockReqEntity.did,
        kid: `${mockReqEntity.did}#controller`,
      },
      registration: {
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        registrationBy: { type: PassBy.VALUE },
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL,
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
      claims: {
        presentationDefinitions: [
          {
            location: PresentationLocation.ID_TOKEN,
            definition: definition,
          },
        ],
      },
    };
    const vc: ICredential = {
      id: 'https://example.com/credentials/1872',
      type: ['VerifiableCredential', 'IDCardCredential'],
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/2018/credentials/examples/v1/IDCardCredential'],
      issuer: {
        id: 'did:example:issuer',
      },
      issuanceDate: '2010-01-01T19:23:24Z',
      credentialSubject: {
        given_name: 'Fredrik',
        family_name: 'Stremberg',
        birthdate: '1949-01-22',
      },
    };
    const vp: IVerifiablePresentation = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      presentation_submission: undefined,
      type: ['verifiablePresentation'],
      holder: 'did:example:holder',
      verifiableCredential: [vc as IVerifiableCredential],
      proof: undefined,
    };

    const pex = new PresentationExchange({
      did: 'did:example:holder',
      allVerifiableCredentials: vp.verifiableCredential,
    });
    await pex.selectVerifiableCredentialsForSubmission(definition);
    const presentationSignCallback: PresentationSignCallback = async (_args) => ({
      ..._args.presentation,
      proof: {
        type: 'RsaSignature2018',
        created: '2018-09-14T21:19:10Z',
        proofPurpose: 'authentication',
        verificationMethod: 'did:example:ebfeb1f712ebc6f1c276e12ec21#keys-1',
        challenge: '1f44d55f-f161-4938-a659-f8026467f126',
        domain: '4jt78h47fh47',
        jws: 'eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..kTCYt5XsITJX1CxPCT8yAV-TVIw5WEuts01mq-pQy7UJiN5mgREEMGlv50aqzpqh4Qq_PbChOMqsLfRoPsnsgxD-WUcX16dUOqV0G_zS245-kronKb78cPktb3rk-BuQy72IFLN25DYuNzVBAh4vGHSrQyHUGlcTwLtjPAnKb78',
      },
    });
    const result: IVerifiablePresentation = (await pex.submissionFrom(
      definition,
      vp.verifiableCredential,
      {},
      presentationSignCallback
    )) as IVerifiablePresentation;
    const responseOpts: AuthenticationResponseOpts = {
      checkLinkedDomain: CheckLinkedDomain.NEVER,
      redirectUri: EXAMPLE_REDIRECT_URL,
      registration: {
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        issuer: ResponseIss.SELF_ISSUED_V2,
        responseTypesSupported: [ResponseType.ID_TOKEN],
        registrationBy: {
          type: PassBy.REFERENCE,
          referenceUri: EXAMPLE_REFERENCE_URL,
        },
        subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
        vpFormats: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL,
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
      signatureType: {
        did: mockResEntity.did,
        hexPrivateKey: mockResEntity.hexPrivateKey,
        kid: `${mockResEntity.did}#controller`,
      },
      vp: [
        {
          location: PresentationLocation.ID_TOKEN,
          format: VerifiablePresentationTypeFormat.LDP_VP,
          presentation: result,
        },
      ],
      presentationSignCallback: presentationSignCallback,
      did: mockResEntity.did, // FIXME: Why do we need this, isn't this handled in the signature type already?
      responseMode: ResponseMode.POST,
    };

    const requestWithJWT = await AuthenticationRequest.createJWT(requestOpts);
    await expect(AuthenticationResponse.createJWTFromRequestJWT(requestWithJWT.jwt, responseOpts, verifyOpts)).resolves.toBeDefined();
  });
});
