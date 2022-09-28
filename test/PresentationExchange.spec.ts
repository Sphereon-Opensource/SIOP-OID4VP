import { PresentationDefinitionV1 } from '@sphereon/pex-models';
import { IProofType, IVerifiableCredential, IVerifiablePresentation } from '@sphereon/ssi-types';
import nock from 'nock';

import {
  AuthenticationRequestPayload,
  getNonce,
  getState,
  IdTokenType,
  PresentationDefinitionWithLocation,
  PresentationExchange,
  ResponseContext,
  ResponseMode,
  ResponseType,
  Scope,
  SigningAlgo,
  SubjectIdentifierType,
  SubjectType,
  VerifiablePresentationPayload,
  VerifiablePresentationTypeFormat,
  VerifiedAuthenticationRequestWithJWT,
} from '../src/main';
import { SIOPErrors } from '../src/main/types';

import { mockedGetEnterpriseAuthToken } from './TestUtils';
import { VERIFIER_LOGO_FOR_CLIENT, VERIFIER_NAME_FOR_CLIENT, VERIFIERZ_PURPOSE_TO_VERIFY } from './data/mockedData';

const HOLDER_DID = 'did:example:ebfeb1f712ebc6f1c276e12ec21';
const EXAMPLE_PD_URL = 'http://my_own_pd.com/pd/';

async function getPayloadPdVal(): Promise<AuthenticationRequestPayload> {
  const mockEntity = await mockedGetEnterpriseAuthToken('ACME Corp');
  const state = getState();
  return {
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
      id_token_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
      id_token_types_supported: [IdTokenType.SUBJECT_SIGNED],
      request_object_signing_alg_values_supported: [SigningAlgo.ES256K, SigningAlgo.ES256, SigningAlgo.EDDSA],
      response_types_supported: [ResponseType.ID_TOKEN],
      scopes_supported: [Scope.OPENID, Scope.OPENID_DIDAUTHN],
      subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
      subject_types_supported: [SubjectType.PAIRWISE],
      vp_formats: {
        ldp_vc: {
          proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
        },
        jwt_vc: {
          alg: [SigningAlgo.ES256, SigningAlgo.ES256K],
        },
      },
      client_name: VERIFIER_NAME_FOR_CLIENT,
      logo_uri: VERIFIER_LOGO_FOR_CLIENT,
      client_purpose: VERIFIERZ_PURPOSE_TO_VERIFY,
    },
    claims: {
      id_token: {
        acr: null,
      },
      vp_token: {
        response_type: 'vp_token',
        nonce: getNonce(state),
        presentation_definition: {
          id: 'Insurance Plans',
          input_descriptors: [
            {
              id: 'Ontario Health Insurance Plan',
              schema: [
                {
                  uri: 'https://did.itsourweb.org:3000/smartcredential/Ontario-Health-Insurance-Plan',
                },
                {
                  uri: 'https://www.w3.org/2018/credentials/v1',
                },
              ],
              constraints: {
                limit_disclosure: 'preferred',
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
        },
      },
    },
  };
}

async function getPayloadPdRef(): Promise<AuthenticationRequestPayload> {
  const mockEntity = await mockedGetEnterpriseAuthToken('ACME Corp');
  const state = getState();
  return {
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
      id_token_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
      id_token_types_supported: [IdTokenType.SUBJECT_SIGNED],
      request_object_signing_alg_values_supported: [SigningAlgo.ES256K, SigningAlgo.ES256, SigningAlgo.EDDSA],
      response_types_supported: [ResponseType.ID_TOKEN],
      scopes_supported: [Scope.OPENID, Scope.OPENID_DIDAUTHN],
      subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
      subject_types_supported: [SubjectType.PAIRWISE],
      vp_formats: {
        ldp_vc: {
          proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
        },
        jwt_vc: {
          alg: [SigningAlgo.ES256, SigningAlgo.ES256K],
        },
      },
      client_name: VERIFIER_NAME_FOR_CLIENT,
      logo_uri: VERIFIER_LOGO_FOR_CLIENT,
      client_purpose: VERIFIERZ_PURPOSE_TO_VERIFY,
    },
    claims: {
      id_token: {
        acr: null,
      },
      vp_token: {
        response_type: 'vp_token',
        nonce: getNonce(state),
        presentation_definition_uri: EXAMPLE_PD_URL,
      },
    },
  };
}

function getVCs(): IVerifiableCredential[] {
  return [
    {
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/2018/credentials/examples/v1'],
      issuanceDate: '2021-11-01T03:05:06T000z',
      id: 'https://example.com/credentials/1872',
      type: ['VerifiableCredential', 'IDCardCredential'],
      issuer: {
        id: 'did:example:issuer',
      },
      credentialSubject: {
        given_name: 'Fredrik',
        family_name: 'Stremberg',
        birthdate: '1949-01-22',
      },
      proof: {
        type: 'BbsBlsSignatureProof2020',
        created: '2020-04-25',
        verificationMethod: 'did:example:489398593#test',
        proofPurpose: 'assertionMethod',
        proofValue:
          'kTTbA3pmDa6Qia/JkOnIXDLmoBz3vsi7L5t3DWySI/VLmBqleJ/Tbus5RoyiDERDBEh5rnACXlnOqJ/U8yFQFtcp/mBCc2FtKNPHae9jKIv1dm9K9QK1F3GI1AwyGoUfjLWrkGDObO1ouNAhpEd0+et+qiOf2j8p3MTTtRRx4Hgjcl0jXCq7C7R5/nLpgimHAAAAdAx4ouhMk7v9dXijCIMaG0deicn6fLoq3GcNHuH5X1j22LU/hDu7vvPnk/6JLkZ1xQAAAAIPd1tu598L/K3NSy0zOy6obaojEnaqc1R5Ih/6ZZgfEln2a6tuUp4wePExI1DGHqwj3j2lKg31a/6bSs7SMecHBQdgIYHnBmCYGNQnu/LZ9TFV56tBXY6YOWZgFzgLDrApnrFpixEACM9rwrJ5ORtxAAAAAgE4gUIIC9aHyJNa5TBklMOh6lvQkMVLXa/vEl+3NCLXblxjgpM7UEMqBkE9/QcoD3Tgmy+z0hN+4eky1RnJsEg=',
      },
    },
  ];
}

describe('presentation exchange manager tests', () => {
  it("validatePresentationAgainstDefinition: should throw error if provided VP doesn't match the PD val", async function () {
    const payload: AuthenticationRequestPayload = await getPayloadPdVal();
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(payload);
    const vcs = getVCs();
    vcs[0].issuer = { id: 'did:example:totallyDifferentIssuer' };
    const verifiedJwt: VerifiedAuthenticationRequestWithJWT = {
      didResolutionResult: undefined,
      issuer: '',
      jwt: '',
      signer: undefined,
      payload: payload,
      presentationDefinitions: pd,
      verifyOpts: null,
    };
    await expect(
      PresentationExchange.validatePresentationAgainstDefinition(verifiedJwt.presentationDefinitions[0].definition, {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        verifiableCredential: vcs,
      })
    ).rejects.toThrow(SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD);
  });

  it("validatePresentationAgainstDefinition: should throw error if provided VP doesn't match the PD ref", async function () {
    const payload: AuthenticationRequestPayload = await getPayloadPdRef();
    const response = {
      id: 'Insurance Plans',
      input_descriptors: [
        {
          id: 'Ontario Health Insurance Plan',
          schema: [
            {
              uri: 'https://did.itsourweb.org:3000/smartcredential/Ontario-Health-Insurance-Plan',
            },
            {
              uri: 'https://www.w3.org/2018/credentials/v1',
            },
          ],
          constraints: {
            limit_disclosure: 'preferred',
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
    nock('http://my_own_pd.com')
      .persist()
      .get(/pd/)
      .reply(200, { ...response });
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(payload);
    const vcs = getVCs();
    vcs[0].issuer = { id: 'did:example:totallyDifferentIssuer' };
    const verifiedJwt: VerifiedAuthenticationRequestWithJWT = {
      didResolutionResult: undefined,
      issuer: '',
      jwt: '',
      signer: undefined,
      payload: payload,
      presentationDefinitions: pd,
      verifyOpts: null,
    };
    await expect(
      PresentationExchange.validatePresentationAgainstDefinition(verifiedJwt.presentationDefinitions[0].definition, {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        verifiableCredential: vcs,
      })
    ).rejects.toThrow(SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD);
  });

  it('validatePresentationAgainstDefinition: should throw error if both pd and pd_ref is present', async function () {
    const payload: AuthenticationRequestPayload = await getPayloadPdVal();
    payload.claims.vp_token.presentation_definition_uri = 'my_pd_url';
    await expect(PresentationExchange.findValidPresentationDefinitions(payload)).rejects.toThrow(
      SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_BY_REF_AND_VALUE_NON_EXCLUSIVE
    );
  });

  it('validatePresentationAgainstDefinition: should pass if provided VP match the PD', async function () {
    const payload: AuthenticationRequestPayload = await getPayloadPdVal();
    const vcs = getVCs();
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(payload);
    const verifiedJwt: VerifiedAuthenticationRequestWithJWT = {
      didResolutionResult: undefined,
      issuer: '',
      jwt: '',
      signer: undefined,
      payload: payload,
      presentationDefinitions: pd,
      verifyOpts: null,
    };
    const result = await PresentationExchange.validatePresentationAgainstDefinition(verifiedJwt.presentationDefinitions[0].definition, {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiablePresentation'],
      verifiableCredential: vcs,
    });
    expect(result.errors.length).toBe(0);
    expect(result.value.definition_id).toBe('Insurance Plans');
  });

  it('submissionFrom: should pass if a valid presentationSubmission object created', async function () {
    const vcs = getVCs();
    const pex = new PresentationExchange({ did: HOLDER_DID, allVerifiableCredentials: vcs });
    const payload: AuthenticationRequestPayload = await getPayloadPdVal();
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(payload);
    await PresentationExchange.validatePresentationAgainstDefinition(pd[0].definition, {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiablePresentation'],
      verifiableCredential: vcs,
    });
    await pex.selectVerifiableCredentialsForSubmission(pd[0].definition);
    const result = await pex.submissionFrom(pd[0].definition, vcs);
    expect(result.presentation_submission.definition_id).toBe('Insurance Plans');
    expect(result.presentation_submission.descriptor_map.length).toBe(1);
    expect(result.presentation_submission.descriptor_map[0]).toStrictEqual({
      id: 'Ontario Health Insurance Plan',
      format: 'ldp_vc',
      path: '$.verifiableCredential[0]',
    });
  });

  it('selectVerifiableCredentialsForSubmission: should fail if selectResults object contains error', async function () {
    const payload: AuthenticationRequestPayload = await getPayloadPdVal();
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(payload);
    const vcs = getVCs();
    vcs[0].issuer = undefined;
    const pex = new PresentationExchange({ did: HOLDER_DID, allVerifiableCredentials: vcs });
    try {
      await expect(pex.selectVerifiableCredentialsForSubmission(pd[0].definition)).rejects.toThrow();
    } catch (e) {
      expect(e.message).toContain(SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD);
    }
  });

  it('selectVerifiableCredentialsForSubmission: should pass if a valid selectResults object created', async function () {
    const vcs = getVCs();
    const pex = new PresentationExchange({ did: HOLDER_DID, allVerifiableCredentials: vcs });
    const payload: AuthenticationRequestPayload = await getPayloadPdVal();
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(payload);
    const result = await pex.selectVerifiableCredentialsForSubmission(pd[0].definition);
    expect(result.errors.length).toBe(0);
    expect(result.matches.length).toBe(1);
    expect(result.matches[0].vc_path.length).toBe(1);
    expect(result.matches[0].vc_path[0]).toBe('$.verifiableCredential[0]');
  });

  it('pass if no PresentationDefinition is found', async () => {
    const payload: AuthenticationRequestPayload = await getPayloadPdVal();
    payload.claims = undefined;
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(payload);
    expect(pd.length).toBe(0);
  });

  it('pass if findValidPresentationDefinitions finds a valid presentation_definition', async () => {
    const payload: AuthenticationRequestPayload = await getPayloadPdVal();
    const pd = await PresentationExchange.findValidPresentationDefinitions(payload);
    const definition = pd[0].definition as PresentationDefinitionV1;
    expect(definition['id']).toBe('Insurance Plans');
    expect(definition['input_descriptors'][0].schema.length).toBe(2);
  });

  it('should validate a list of VerifiablePresentations against a list of PresentationDefinitions', async () => {
    const payload: AuthenticationRequestPayload = await getPayloadPdVal();
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(payload);
    const vcs = getVCs();
    const pex = new PresentationExchange({ did: HOLDER_DID, allVerifiableCredentials: vcs });
    await pex.selectVerifiableCredentialsForSubmission(pd[0].definition);
    const vp: IVerifiablePresentation = await pex.submissionFrom(pd[0].definition, vcs);
    const vpw: VerifiablePresentationPayload = {
      presentation: vp,
      format: VerifiablePresentationTypeFormat.LDP_VP,
    };
    try {
      await PresentationExchange.validatePayloadsAgainstDefinitions(pd, [vpw]);
    } catch (e) {
      console.log(e);
    }
  });
});
