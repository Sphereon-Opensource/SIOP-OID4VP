import { parse } from 'querystring';

import { IPresentationDefinition } from '@sphereon/pex';
import { IProofType } from '@sphereon/ssi-types';

import {
  AuthenticationRequest,
  AuthenticationRequestOpts,
  CheckLinkedDomain,
  PassBy,
  PresentationLocation,
  ResponseType,
  Scope,
  SigningAlgo,
  SubjectIdentifierType,
  SubjectType,
} from '../src/main';
import SIOPErrors from '../src/main/types/Errors';

import { VERIFIER_LOGO_FOR_CLIENT, VERIFIER_NAME_FOR_CLIENT, VERIFIERZ_PURPOSE_TO_VERIFY } from './data/mockedData';

const EXAMPLE_REDIRECT_URL = 'https://acme.com/hello';
const EXAMPLE_REFERENCE_URL = 'https://rp.acme.com/siop/jwts';
const HEX_KEY = 'f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f';
const DID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0';
const KID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#keys-1';

describe('create Request Uri should', () => {
  it('throw BAD_PARAMS when no responseOpts is passed', async () => {
    expect.assertions(1);
    await expect(AuthenticationRequest.createURI(undefined as never)).rejects.toThrow(SIOPErrors.BAD_PARAMS);
  });

  it('throw BAD_PARAMS when no responseOpts.redirectUri is passed', async () => {
    expect.assertions(1);
    const opts = {};
    await expect(AuthenticationRequest.createURI(opts as never)).rejects.toThrow(SIOPErrors.BAD_PARAMS);
  });

  it('throw BAD_PARAMS when no responseOpts.requestBy is passed', async () => {
    expect.assertions(1);
    const opts = {
      redirectUri: EXAMPLE_REDIRECT_URL,
    };
    await expect(AuthenticationRequest.createURI(opts as never)).rejects.toThrow(SIOPErrors.BAD_PARAMS);
  });

  it('throw REQUEST_OBJECT_TYPE_NOT_SET when responseOpts.requestBy type is different from REFERENCE or VALUE', async () => {
    expect.assertions(1);
    const opts = {
      redirectUri: EXAMPLE_REDIRECT_URL,
      requestBy: {
        type: 'other type',
      },
    };
    await expect(AuthenticationRequest.createURI(opts as never)).rejects.toThrow(SIOPErrors.REQUEST_OBJECT_TYPE_NOT_SET);
  });

  it('throw NO_REFERENCE_URI when responseOpts.requestBy type is REFERENCE and no referenceUri is passed', async () => {
    expect.assertions(1);
    const opts = {
      redirectUri: EXAMPLE_REDIRECT_URL,
      requestBy: {
        type: PassBy.REFERENCE,
      },
    };
    await expect(AuthenticationRequest.createURI(opts as never)).rejects.toThrow(SIOPErrors.NO_REFERENCE_URI);
  });

  it('return a reference url', async () => {
    expect.assertions(11);
    const opts: AuthenticationRequestOpts = {
      checkLinkedDomain: CheckLinkedDomain.NEVER,
      requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
      redirectUri: EXAMPLE_REDIRECT_URL,
      requestBy: {
        type: PassBy.REFERENCE,
        referenceUri: EXAMPLE_REFERENCE_URL,
      },
      signatureType: {
        hexPrivateKey: HEX_KEY,
        did: DID,
        kid: KID,
      },
      registration: {
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        registrationBy: {
          type: PassBy.VALUE,
        },
        clientName: VERIFIER_NAME_FOR_CLIENT,
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
      },
    };

    const uriRequest = await AuthenticationRequest.createURI(opts);
    expect(uriRequest).toBeDefined();
    expect(uriRequest).toHaveProperty('encodedUri');
    expect(uriRequest).toHaveProperty('encodingFormat');

    const uriDecoded = decodeURIComponent(uriRequest.encodedUri);
    expect(uriDecoded).toContain(`openid://`);
    expect(uriDecoded).toContain(`?response_type=${ResponseType.ID_TOKEN}`);
    expect(uriDecoded).toContain(`&redirect_uri=${opts.redirectUri}`);
    expect(uriDecoded).toContain(`&scope=${Scope.OPENID}`);
    expect(uriDecoded).toContain(`&request_uri=`);

    const data = parse(uriDecoded);
    expect(data.request_uri).toStrictEqual(opts.requestBy.referenceUri);
    expect(uriRequest).toHaveProperty('jwt');
    expect(uriRequest.jwt).toBeDefined();
  });

  it('return a reference url when using did:key', async () => {
    expect.assertions(3);
    const opts: AuthenticationRequestOpts = {
      checkLinkedDomain: CheckLinkedDomain.NEVER,
      requestObjectSigningAlgValuesSupported: [SigningAlgo.ES256, SigningAlgo.EDDSA],
      redirectUri: EXAMPLE_REDIRECT_URL,
      requestBy: {
        type: PassBy.REFERENCE,
        referenceUri: EXAMPLE_REFERENCE_URL,
      },
      signatureType: {
        hexPrivateKey:
          'd474ffdb3ea75fbb3f07673e67e52002a3b7eb42767f709f4100acf493c7fc8743017577997b72e7a8b4bce8c32c8e78fd75c1441e95d6aaa888056d1200beb3',
        did: 'did:key:z6MkixpejjET5qJK4ebN5m3UcdUPmYV4DPSCs1ALH8x2UCfc',
        kid: 'did:key:z6MkixpejjET5qJK4ebN5m3UcdUPmYV4DPSCs1ALH8x2UCfc#keys-1',
      },
      registration: {
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        registrationBy: {
          type: PassBy.VALUE,
        },
        clientName: VERIFIER_NAME_FOR_CLIENT,
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
      },
    };

    const uriRequest = await AuthenticationRequest.createURI(opts);
    const uriDecoded = decodeURIComponent(uriRequest.encodedUri);

    const data = parse(uriDecoded);
    expect(data.request_uri).toStrictEqual(opts.requestBy.referenceUri);
    expect(uriRequest).toHaveProperty('jwt');
    expect(uriRequest.jwt).toBeDefined();
  });

  it('return an url with an embedded token value', async () => {
    expect.assertions(2);
    const opts: AuthenticationRequestOpts = {
      checkLinkedDomain: CheckLinkedDomain.NEVER,
      requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
      redirectUri: EXAMPLE_REDIRECT_URL,
      requestBy: {
        type: PassBy.VALUE,
      },
      signatureType: {
        hexPrivateKey: HEX_KEY,
        did: DID,
        kid: KID,
      },
      registration: {
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        registrationBy: {
          type: PassBy.VALUE,
        },
        clientName: VERIFIER_NAME_FOR_CLIENT,
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
      },
    };

    const uriRequest = await AuthenticationRequest.createURI(opts);

    const uriDecoded = decodeURIComponent(uriRequest.encodedUri);
    expect(uriDecoded).toContain(`&request=`);

    const data = parse(uriDecoded);
    expect(data.request).toBeDefined();
  });
});

describe('create Request JWT should', () => {
  it('throw REQUEST_OBJECT_TYPE_NOT_SET when requestBy type is different from REFERENCE and VALUE', async () => {
    expect.assertions(1);
    const opts = {
      redirectUri: EXAMPLE_REDIRECT_URL,
      requestBy: {
        type: 'other type',
      },
      signatureType: {
        hexPrivateKey: HEX_KEY,
        did: DID,
        kid: KID,
      },
      registration: {
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        registrationBy: {
          type: PassBy.VALUE,
        },
      },
    };
    await expect(AuthenticationRequest.createJWT(opts as never)).rejects.toThrow(SIOPErrors.REQUEST_OBJECT_TYPE_NOT_SET);
  });

  it('throw NO_REFERENCE_URI when no referenceUri is passed with REFERENCE requestBy type is set', async () => {
    expect.assertions(1);
    const opts = {
      redirectUri: EXAMPLE_REDIRECT_URL,
      requestBy: {
        type: PassBy.REFERENCE,
      },
      signatureType: {
        hexPrivateKey: HEX_KEY,
        did: DID,
        kid: KID,
      },
      registration: {
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        registrationBy: {
          type: PassBy.VALUE,
        },
      },
    };
    await expect(AuthenticationRequest.createJWT(opts as never)).rejects.toThrow(SIOPErrors.NO_REFERENCE_URI);
  });

  it('throw BAD_SIGNATURE_PARAMS when signature Type is neither internal nor external', async () => {
    expect.assertions(1);
    const opts = {
      redirectUri: EXAMPLE_REDIRECT_URL,
      requestBy: {
        type: PassBy.REFERENCE,
        referenceUri: EXAMPLE_REFERENCE_URL,
      },
      signatureType: {},
      registration: {
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        registrationBy: {
          type: PassBy.VALUE,
        },
      },
    };
    await expect(AuthenticationRequest.createJWT(opts as never)).rejects.toThrow(SIOPErrors.BAD_SIGNATURE_PARAMS);
  });

  it('throw REGISTRATION_OBJECT_TYPE_NOT_SET when registrationBy type is neither REFERENCE nor VALUE', async () => {
    expect.assertions(1);
    const opts = {
      redirectUri: EXAMPLE_REDIRECT_URL,
      requestBy: {
        type: PassBy.REFERENCE,
        referenceUri: EXAMPLE_REFERENCE_URL,
      },
      signatureType: {
        hexPrivateKey: HEX_KEY,
        did: DID,
        kid: KID,
      },
      registration: {
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        registrationBy: {
          type: 'FAILURE',
        },
      },
    };
    await expect(AuthenticationRequest.createJWT(opts as never)).rejects.toThrow(SIOPErrors.REGISTRATION_OBJECT_TYPE_NOT_SET);
  });

  it('throw NO_REFERENCE_URI when registrationBy type is REFERENCE and no referenceUri is passed', async () => {
    expect.assertions(1);
    const opts = {
      redirectUri: EXAMPLE_REDIRECT_URL,
      requestBy: {
        type: PassBy.REFERENCE,
        referenceUri: EXAMPLE_REFERENCE_URL,
      },
      signatureType: {
        hexPrivateKey: HEX_KEY,
        did: DID,
        kid: KID,
      },
      registration: {
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        registrationBy: {
          type: PassBy.REFERENCE,
        },
      },
    };
    await expect(AuthenticationRequest.createJWT(opts as never)).rejects.toThrow(SIOPErrors.NO_REFERENCE_URI);
  });

  it('succeed when all params are set', async () => {
    // expect.assertions(1);
    const opts: AuthenticationRequestOpts = {
      checkLinkedDomain: CheckLinkedDomain.NEVER,
      requestObjectSigningAlgValuesSupported: [SigningAlgo.ES256, SigningAlgo.EDDSA],
      redirectUri: EXAMPLE_REDIRECT_URL,
      requestBy: {
        type: PassBy.REFERENCE,
        referenceUri: EXAMPLE_REFERENCE_URL,
      },
      signatureType: {
        hexPrivateKey: HEX_KEY,
        did: DID,
        kid: KID,
      },
      registration: {
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        registrationBy: {
          type: PassBy.VALUE,
        },
        clientName: VERIFIER_NAME_FOR_CLIENT,
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
      },
    };

    const expected = {
      payload: {
        response_type: 'id_token',
        scope: 'openid',
        client_id: 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0',
        redirect_uri: 'https://acme.com/hello',
        iss: 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0',
        response_mode: 'post',
        response_context: 'rp',
        registration: {
          id_token_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          request_object_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          response_types_supported: [ResponseType.ID_TOKEN],
          scopes_supported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
          subject_types_supported: [SubjectType.PAIRWISE],
          subject_syntax_types_supported: ['did:ethr:', 'did'],
          vp_formats: {
            ldp_vc: {
              proof_type: ['EcdsaSecp256k1Signature2019', 'EcdsaSecp256k1Signature2019'],
            },
          },
        },
      },
      opts: {
        redirectUri: 'https://acme.com/hello',
        requestBy: {
          type: 'REFERENCE',
          referenceUri: 'https://rp.acme.com/siop/jwts',
        },
        signatureType: {
          hexPrivateKey: 'f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f',
          did: 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0',
          kid: 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#keys-1',
        },
        registration: {
          idTokenSigningAlgValuesSupported: ['EdDSA', 'ES256'],
          subjectSyntaxTypesSupported: ['did:ethr:', 'did'],
          vpFormatsSupported: {
            ldp_vc: {
              proof_type: ['EcdsaSecp256k1Signature2019', 'EcdsaSecp256k1Signature2019'],
            },
          },
          registrationBy: {
            type: 'VALUE',
          },
        },
      },
    };

    AuthenticationRequest.createURI(opts).then((uri) => console.log(uri.encodedUri));
    await expect(AuthenticationRequest.createJWT(opts)).resolves.toMatchObject(expected);
  });

  it('succeed when requesting with a valid PD', async () => {
    const opts: AuthenticationRequestOpts = {
      checkLinkedDomain: CheckLinkedDomain.NEVER,
      redirectUri: EXAMPLE_REDIRECT_URL,
      requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
      requestBy: {
        type: PassBy.REFERENCE,
        referenceUri: EXAMPLE_REFERENCE_URL,
      },
      signatureType: {
        hexPrivateKey: HEX_KEY,
        did: DID,
        kid: KID,
      },
      registration: {
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        registrationBy: {
          type: PassBy.VALUE,
        },
        clientName: VERIFIER_NAME_FOR_CLIENT,
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
      },
      claims: {
        presentationDefinitions: [
          {
            location: PresentationLocation.VP_TOKEN,
            definition: {
              id: 'Insurance Plans',
              input_descriptors: [
                {
                  id: 'Ontario Health Insurance Plan',
                  schema: [
                    {
                      uri: 'https://did.itsourweb.org:3000/smartcredential/Ontario-Health-Insurance-Plan',
                    },
                  ],
                },
              ],
            },
          },
        ],
      },
    };

    const uriRequest = await AuthenticationRequest.createURI(opts);

    const uriDecoded = decodeURIComponent(uriRequest.encodedUri);
    expect(uriDecoded).toContain(`&claims=`);
  });

  it('should throw error if presentation definition object is not valid', async () => {
    const opts: AuthenticationRequestOpts = {
      checkLinkedDomain: CheckLinkedDomain.NEVER,
      redirectUri: EXAMPLE_REDIRECT_URL,
      requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
      requestBy: {
        type: PassBy.REFERENCE,
        referenceUri: EXAMPLE_REFERENCE_URL,
      },
      signatureType: {
        hexPrivateKey: HEX_KEY,
        did: DID,
        kid: KID,
      },
      registration: {
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        registrationBy: {
          type: PassBy.VALUE,
        },
        clientName: VERIFIER_NAME_FOR_CLIENT,
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
      },
      claims: {
        presentationDefinitions: [
          {
            location: PresentationLocation.VP_TOKEN,
            definition: {
              input_descriptors: [
                {
                  id: 'Ontario Health Insurance Plan',
                  schema: [
                    {
                      uri: 'https://did.itsourweb.org:3000/smartcredential/Ontario-Health-Insurance-Plan',
                    },
                  ],
                },
              ],
            } as IPresentationDefinition,
          },
        ],
      },
    };
    await expect(AuthenticationRequest.createURI(opts)).rejects.toThrow(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
  });
});
