import { Presentation, VP } from '@sphereon/pe-js';

import { PresentationExchange, SIOP } from '../src/main';
import { State } from '../src/main/functions';
import { SIOPErrors } from '../src/main/types';
import {
  AuthenticationRequestPayload,
  CredentialFormat,
  PresentationDefinitionWithLocation,
  ResponseContext,
  ResponseMode,
  SubjectIdentifierType,
  VerifiablePresentationPayload,
  VerifiablePresentationTypeFormat,
} from '../src/main/types/SIOP.types';

import { mockedGetEnterpriseAuthToken } from './TestUtils';

const HOLDER_DID = 'did:example:ebfeb1f712ebc6f1c276e12ec21';

async function getPayload(): Promise<AuthenticationRequestPayload> {
  const mockEntity = await mockedGetEnterpriseAuthToken('ACME Corp');
  const state = State.getState();
  return {
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
      did_methods_supported: ['did:ethr:'],
      subject_identifiers_supported: SubjectIdentifierType.DID,
      credential_formats_supported: [CredentialFormat.JSON_LD, CredentialFormat.JWT],
    },
    claims: {
      id_token: {
        acr: null,
      },
      vp_token: {
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
        },
      },
    },
  };
}

async function getVCs() {
  return [
    {
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/2018/credentials/examples/v1'],
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
    },
  ];
}

describe('presentation exchange manager tests', () => {
  it("validatePresentationAgainstDefinition: should throw error if provided VP doesn't match the PD", async function () {
    const payload: AuthenticationRequestPayload = await getPayload();
    const pd: PresentationDefinitionWithLocation[] = PresentationExchange.findValidPresentationDefinitions(payload);
    const vcs = await getVCs();
    vcs[0].issuer = { id: 'did:example:totallyDifferentIssuer' };
    const verifiedJwt: SIOP.VerifiedAuthenticationRequestWithJWT = {
      didResolutionResult: undefined,
      issuer: '',
      jwt: '',
      signer: undefined,
      payload: payload,
      presentationDefinitions: pd,
      verifyOpts: null,
    };
    try {
      await PresentationExchange.validatePresentationAgainstDefinition(
        verifiedJwt.presentationDefinitions[0].definition,
        new VP(new Presentation(null, null, null, vcs, null, null))
      );
    } catch (e) {
      expect(e.message).toContain(SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD);
    }
  });

  it('validatePresentationAgainstDefinition: should pass if provided VP match the PD', async function () {
    const payload: AuthenticationRequestPayload = await getPayload();
    const vcs = await getVCs();
    const pd: PresentationDefinitionWithLocation[] = PresentationExchange.findValidPresentationDefinitions(payload);
    const verifiedJwt: SIOP.VerifiedAuthenticationRequestWithJWT = {
      didResolutionResult: undefined,
      issuer: '',
      jwt: '',
      signer: undefined,
      payload: payload,
      presentationDefinitions: pd,
      verifyOpts: null,
    };
    const result = await PresentationExchange.validatePresentationAgainstDefinition(
      verifiedJwt.presentationDefinitions[0].definition,
      new VP(new Presentation(null, null, null, vcs, null, null))
    );
    console.log(JSON.stringify(result));
    expect(result.errors.length).toBe(0);
    expect(result.value.definition_id).toBe('Insurance Plans');
  });

  it('submissionFrom: should pass if a valid presentationSubmission object created', async function () {
    const pex = new PresentationExchange({ did: HOLDER_DID, allVerifiableCredentials: await getVCs() });
    const payload: AuthenticationRequestPayload = await getPayload();
    const vcs = await getVCs();
    const pd: PresentationDefinitionWithLocation[] = PresentationExchange.findValidPresentationDefinitions(payload);
    await PresentationExchange.validatePresentationAgainstDefinition(
      pd[0].definition,
      new VP(new Presentation(null, null, null, vcs, null, null))
    );
    await pex.selectVerifiableCredentialsForSubmission(pd[0].definition);
    const result = await pex.submissionFrom(pd[0].definition, vcs);
    expect(result.getPresentationSubmission().definition_id).toBe('Insurance Plans');
    expect(result.getPresentationSubmission().descriptor_map.length).toBe(1);
    expect(result.getPresentationSubmission().descriptor_map[0]).toStrictEqual({
      id: 'Ontario Health Insurance Plan',
      format: 'ldp_vc',
      path: '$.verifiableCredential[0]',
    });
  });

  it('selectVerifiableCredentialsForSubmission: should fail if selectResults object contains error', async function () {
    const payload: AuthenticationRequestPayload = await getPayload();
    const pd: PresentationDefinitionWithLocation[] = PresentationExchange.findValidPresentationDefinitions(payload);
    const vcs = await getVCs();
    vcs[0].issuer = undefined;
    const pex = new PresentationExchange({ did: HOLDER_DID, allVerifiableCredentials: vcs });
    try {
      await expect(pex.selectVerifiableCredentialsForSubmission(pd[0].definition)).rejects.toThrow();
    } catch (e) {
      expect(e.message).toContain(SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD);
    }
  });

  it('selectVerifiableCredentialsForSubmission: should pass if a valid selectResults object created', async function () {
    const vcs = await getVCs();
    const pex = new PresentationExchange({ did: HOLDER_DID, allVerifiableCredentials: vcs });
    const payload: AuthenticationRequestPayload = await getPayload();
    const pd: PresentationDefinitionWithLocation[] = PresentationExchange.findValidPresentationDefinitions(payload);
    const result = await pex.selectVerifiableCredentialsForSubmission(pd[0].definition);
    expect(result.errors.length).toBe(0);
    expect(result.matches.length).toBe(1);
    expect(result.matches[0].matches.length).toBe(1);
    expect(result.matches[0].matches[0]).toBe('$.verifiableCredential[0]');
  });

  it('pass if no PresentationDefinition is found', async () => {
    const payload: AuthenticationRequestPayload = await getPayload();
    payload.claims = undefined;
    const pd: PresentationDefinitionWithLocation[] = PresentationExchange.findValidPresentationDefinitions(payload);
    expect(pd).toBeUndefined();
  });

  it('pass if findValidPresentationDefinitions finds a valid presentation_definition', async () => {
    const payload: AuthenticationRequestPayload = await getPayload();
    const pd = PresentationExchange.findValidPresentationDefinitions(payload);
    expect(pd[0]['definition']['id']).toBe('Insurance Plans');
    expect(pd[0]['definition']['input_descriptors'][0].schema.length).toBe(2);
  });

  it('should validate a list of VerifiablePresentations against a list of PresentationDefinitions', async () => {
    const payload: AuthenticationRequestPayload = await getPayload();
    const pd: PresentationDefinitionWithLocation[] = PresentationExchange.findValidPresentationDefinitions(payload);
    const vcs = await getVCs();
    const pex = new PresentationExchange({ did: HOLDER_DID, allVerifiableCredentials: vcs });
    await pex.selectVerifiableCredentialsForSubmission(pd[0].definition);
    const vp: VP = await pex.submissionFrom(pd[0].definition, vcs);
    const vpw: VerifiablePresentationPayload = {
      presentation: vp.getRoot(),
      format: VerifiablePresentationTypeFormat.LDP_VP,
    };
    try {
      await PresentationExchange.validatePayloadsAgainstDefinitions(pd, [vpw]);
    } catch (e) {
      console.log(e);
    }
  });

  it('should not validate a list of VerifiablePresentations against a list of PresentationDefinitions', async () => {
    const payload: AuthenticationRequestPayload = await getPayload();
    const pd: PresentationDefinitionWithLocation[] = PresentationExchange.findValidPresentationDefinitions(payload);
    const vcs = await getVCs();
    const pex = new PresentationExchange({ did: HOLDER_DID, allVerifiableCredentials: vcs });
    await pex.selectVerifiableCredentialsForSubmission(pd[0].definition);
    const vp = await pex.submissionFrom(pd[0].definition, vcs);
    const vpw: VerifiablePresentationPayload = {
      presentation: vp.getRoot(),
      format: VerifiablePresentationTypeFormat.JWT_VP,
    };
    await expect(PresentationExchange.validatePayloadsAgainstDefinitions(pd, [vpw])).rejects.toThrow(
      Error("This type of verifiable presentation isn't supported in this version")
    );
  });
});
