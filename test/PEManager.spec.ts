import { Presentation, VP } from '@sphereon/pe-js';
import { PresentationDefinition } from '@sphereon/pe-models';

import { PEManager, SIOP } from '../src/main';
import { State } from '../src/main/functions';
import { SIOPErrors } from '../src/main/types';
import {
  AuthenticationRequestPayload,
  CredentialFormat,
  ResponseContext,
  ResponseMode,
  SubjectIdentifierType
} from '../src/main/types/SIOP.types';

import { mockedGetEnterpriseAuthToken } from './TestUtils';

// const HOLDER_DID = 'did:example:ebfeb1f712ebc6f1c276e12ec21';

async function getPayload() {
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
      credential_formats_supported: [CredentialFormat.JSON_LD, CredentialFormat.JWT]
    },
    claims: {
      'id_token': {
        'acr': null,
        'verifiable_presentations': {
          'presentation_definition': {
            'id': 'Insurance Plans',
            'input_descriptors': [
              {
                'id': 'Ontario Health Insurance Plan',
                'schema': [
                  {
                    'uri': 'https://did.itsourweb.org:3000/smartcredential/Ontario-Health-Insurance-Plan'
                  },
                  {
                    'uri': 'https://www.w3.org/2018/credentials/v1'
                  }
                ],
                constraints: {
                  'limit_disclosure': 'required',
                  'fields': [
                    {
                      'path': [
                        '$.issuer.id'
                      ],
                      'purpose': 'We can only verify bank accounts if they are attested by a source.',
                      'filter': {
                        'type': 'string',
                        'pattern': 'did:example:issuer'
                      }
                    }
                  ]
                }
              }
            ]
          }
        }
      }
    }
  };
}

async function getVCs() {
  return [{
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://www.w3.org/2018/credentials/examples/v1'
    ],
    'id': 'https://example.com/credentials/1872',
    'type': [
      'VerifiableCredential',
      'IDCardCredential'
    ],
    'issuer': {
      'id': 'did:example:issuer'
    },
    'credentialSubject': {
      'given_name': 'Fredrik',
      'family_name': 'Stremberg',
      'birthdate': '1949-01-22'
    }
  }];
}

describe('presentation exchange manager tests', () => {
  it('evaluate: should throw error if provided VP doesn\'t match the PD', async function() {
    const peManager: PEManager = new PEManager();
    const payload: AuthenticationRequestPayload = await getPayload();
    const vcs = await getVCs();
    vcs[0].issuer = { 'id': 'did:example:totallyDifferentIssuer' };
    try {
      await peManager.evaluate(payload, new VP(new Presentation(null, null, null, vcs, null, null)));
    } catch (e) {
      expect(e.message).toContain(SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD);
    }
  });

  it('evaluate: should pass if provided VP match the PD', async function() {
    const peManager: PEManager = new PEManager();
    const payload: AuthenticationRequestPayload = await getPayload();
    const vcs = await getVCs();
    const result = await peManager.evaluate(payload, new VP(new Presentation(null, null, null, vcs, null, null)));
    console.log(JSON.stringify(result));
    expect(result.errors.length).toBe(0);
    expect(result.value.definition_id).toBe('Insurance Plans');
  });

  /*it('submissionFrom: should fail if can\'t create a valid presentationSubmission object', async function() {
    const peManager: PEManager = new PEManager();
    const payload: AuthenticationRequestPayload = await getPayload();
    const vcs = await getVCs();
    await peManager.evaluate(payload, new VP(new Presentation(null, null, null, vcs, null, null)));
    delete payload.claims['id_token'];
    await expect(peManager.submissionFrom(payload, vcs)).rejects.toThrow(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
  });*/

  /*it('submissionFrom: should pass if a valid presentationSubmission object created', async function() {
    const peManager: PEManager = new PEManager();
    const payload: AuthenticationRequestPayload = await getPayload();
    const vcs = await getVCs();
    await peManager.evaluate(payload, new VP(new Presentation(null, null, null, vcs, null, null)));
    const result = await peManager.submissionFrom(payload, vcs);
    expect(result.definition_id).toBe('Insurance Plans');
    expect(result.descriptor_map.length).toBe(1);
    expect(result.descriptor_map[0]).toStrictEqual({
      'id': 'Ontario Health Insurance Plan',
      'format': 'ldp_vc',
      'path': '$.verifiableCredential[0]'
    });
  });*/

  /*it('selectVerifiableCredentialsForSubmission: should fail if selectResults object contains error', async function() {
    const peManager: PEManager = new PEManager();
    const payload: AuthenticationRequestPayload = await getPayload();
    const vcs = await getVCs();
    vcs[0].issuer = undefined;
    try {
      await expect(peManager.selectVerifiableCredentialsForSubmission(payload, vcs, HOLDER_DID)).rejects.toThrow();
    } catch (e) {
      expect(e.message).toContain(SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD);
    }
  });*/

  /*it('selectVerifiableCredentialsForSubmission: should pass if a valid selectResults object created', async function() {
    const peManager: PEManager = new PEManager();
    const payload: AuthenticationRequestPayload = await getPayload();
    const vcs = await getVCs();
    const result = await peManager.selectVerifiableCredentialsForSubmission(payload, vcs, HOLDER_DID);
    expect(result.errors.length).toBe(0);
    expect(result.matches.length).toBe(1);
    expect(result.matches[0].matches.length).toBe(1);
    expect(result.matches[0].matches[0]).toBe('$.verifiableCredential[0]');
  });*/

  it('pass if no PresentationDefinition is found', async () => {
    const payload: AuthenticationRequestPayload = await getPayload();
    payload.claims = undefined;
    const pd: PresentationDefinition = await PEManager.findValidPresentationDefinition(payload);
    expect(pd).toBeNull();
  });

  it('pass if findValidPresentationDefinition finds a valid presentation_definition', async () => {
    const payload: AuthenticationRequestPayload = await getPayload();
    const pd = await PEManager.findValidPresentationDefinition(payload);
    expect(pd['id']).toBe('Insurance Plans');
    expect(pd['input_descriptors'][0].schema.length).toBe(2);
  });
});
