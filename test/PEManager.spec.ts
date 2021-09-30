import { PresentationDefinition } from '@sphereon/pe-models';

import { PEManager, SIOP } from '../src/main';
import { State } from '../src/main/functions';
import {
  AuthenticationRequestPayload,
  CredentialFormat,
  ResponseContext,
  ResponseMode,
  SubjectIdentifierType
} from '../src/main/types/SIOP.types';

import { mockedGetEnterpriseAuthToken } from './TestUtils';

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

describe("presentation exchange manager tests", () => {
  it("pass if no PresentationDefinition is found", async () => {
    const payload: AuthenticationRequestPayload = await getPayload();
    const peManager: PEManager = new PEManager();
    payload.claims = undefined;
    const pd: PresentationDefinition = peManager.findValidPresentationDefinition(payload);
    expect(pd).toBeNull();
  });

  it("pass if findValidPresentationDefinition finds a valid presentation_definition", async () => {
    const peManager: PEManager = new PEManager();
    const payload: AuthenticationRequestPayload = await getPayload();
    const pd = peManager.findValidPresentationDefinition(payload);
    expect(pd["id"]).toBe("Insurance Plans");
    expect(pd["input_descriptors"][0].schema.length).toBe(2);
  });
});
