import { VP } from '@sphereon/pe-js';

import { AuthenticationRequest, AuthenticationResponse } from '../src/main';
import SIOPErrors from '../src/main/types/Errors';
import {
    AuthenticationResponseOpts,
    CredentialFormat,
    PassBy,
    ResponseMode,
    SubjectIdentifierType,
    VerificationMode,
    VerifyAuthenticationRequestOpts
} from '../src/main/types/SIOP.types';

import { mockedGetEnterpriseAuthToken } from './TestUtils';

// const EXAMPLE_REDIRECT_URL = "https://acme.com/hello";
const EXAMPLE_REFERENCE_URL = 'https://rp.acme.com/siop/jwts';
const HEX_KEY = 'f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f';
const DID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0';
const KID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#keys-1';

const validButExpiredJWT = 'eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXRocjoweDUwMjM4M2Q0ZmIwOWIzQThEYzYxMzNFQkI2QzFGZTQyOUIxODAyNUEjY29udHJvbGxlciIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2MzIwODkxNTMsImV4cCI6MTYzMjA4OTc1MywicmVzcG9uc2VfdHlwZSI6ImlkX3Rva2VuIiwic2NvcGUiOiJvcGVuaWQiLCJjbGllbnRfaWQiOiJkaWQ6ZXRocjoweDUwMjM4M2Q0ZmIwOWI' +
  'zQThEYzYxMzNFQkI2QzFGZTQyOUIxODAyNUEiLCJyZWRpcmVjdF91cmkiOiJodHRwczovL2FjbWUuY29tL2hlbGxvIiwiaXNzIjoiZGlkOmV0aHI6MHg1MDIzODNkNGZiMDliM0E4RGM2MTMzRUJCNkMxRmU0MjlCMTgwMjVBIiwicmVzcG9uc2VfbW9kZSI6InBvc3QiLCJyZXNwb25zZV9jb250ZXh0IjoicnAiLCJub25jZSI6IlJtZ2l6SDhSQTFYRHJ5enZiNHM5c2tzRXBTd1haYTZLb0dqaUdzR0RzVlkiLCJzdG' +
  'F0ZSI6ImQ3N2M5NDBlYjc0MGYwMmIyMzgxZjYzMiIsInJlZ2lzdHJhdGlvbiI6eyJkaWRfbWV0aG9kc19zdXBwb3J0ZWQiOiJkaWQ6ZXRocjoiLCJzdWJqZWN0X2lkZW50aWZpZXJzX3N1cHBvcnRlZCI6ImRpZCJ9fQ.VqBgIB7A9oNDSv-s0jkLmxPQhazsXMRJ_4k77pqvkM1eV2Kr2B1mTd8scQWjKfbmtiCaDqSvyoUaIEFLWadwPQ';

describe('create JWT from Request JWT should', () => {
  const responseOpts: AuthenticationResponseOpts = {
    registration: {
      didsSupported: true,
      didMethodsSupported: ['did:web'],
      credentialSupported: false,
      credentialName: 'test',
      credentialEndpoint: 'http://test.com',
      credentialClaimsSupported: 'any',
      credentialFormatsSupported: CredentialFormat.JSON_LD,
      registrationBy: {
        type: PassBy.REFERENCE,
        referenceUri: EXAMPLE_REFERENCE_URL
      }
    },
    signatureType: {
      did: DID,
      hexPrivateKey: HEX_KEY,
      kid: KID
    },
    did: DID,
    responseMode: ResponseMode.POST
  };
  const verifyOpts: VerifyAuthenticationRequestOpts = {
    verification: {
      resolveOpts: {
        didMethods: ['ethr']
      },
      mode: VerificationMode.INTERNAL
    }
  };

  it('throw NO_JWT when no jwt is passed', async () => {
    expect.assertions(1);
    await expect(AuthenticationResponse.createJWTFromRequestJWT(undefined as never, responseOpts, verifyOpts)).rejects.toThrow(
      SIOPErrors.NO_JWT
    );
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
    await expect(AuthenticationResponse.createJWTFromRequestJWT(validButExpiredJWT, responseOpts, verifyOpts)).rejects.toThrow(/invalid_jwt: JWT has expired: exp: 1632089753/);
  });

  it('succeed when valid JWT is passed in', async () => {
    expect.assertions(1);

    const mockReqEntity = await mockedGetEnterpriseAuthToken('REQ COMPANY');
    const mockResEntity = await mockedGetEnterpriseAuthToken('RES COMPANY');
    const requestOpts = {
      redirectUri: 'https://acme.com/hello',
      requestBy: { type: PassBy.REFERENCE, referenceUri: 'https://my-request.com/here' },
      signatureType: {
        hexPrivateKey: mockReqEntity.hexPrivateKey,
        did: mockReqEntity.did,
        kid: `${mockReqEntity.did}#controller`
      },
      registration: {
        didMethodsSupported: 'did:ethr:',
        subjectIdentifiersSupported: SubjectIdentifierType.DID,
        credentialFormatsSupported: CredentialFormat.JSON_LD,
        registrationBy: { type: PassBy.VALUE }
      }
    };
    const responseOpts: AuthenticationResponseOpts = {
      registration: {
        registrationBy: {
          type: PassBy.REFERENCE,
          referenceUri: EXAMPLE_REFERENCE_URL
        }
      },
      signatureType: {
        did: mockResEntity.did,
        hexPrivateKey: mockResEntity.hexPrivateKey,
        kid: `${mockResEntity.did}#controller`
      },
      did: mockResEntity.did,   // FIXME: Why do we need this, isn't this handled in the signature type already?
      responseMode: ResponseMode.POST
    };
    const requestWithJWT = await AuthenticationRequest.createJWT(requestOpts);
    console.log(JSON.stringify(await AuthenticationResponse.createJWTFromRequestJWT(requestWithJWT.jwt, responseOpts, verifyOpts)));
    await expect(AuthenticationResponse.createJWTFromRequestJWT(requestWithJWT.jwt, responseOpts, verifyOpts)).resolves.toBeDefined();
  });

  it('succeed when valid JWT with PD is passed in', async () => {
    expect.assertions(1);

    const mockReqEntity = await mockedGetEnterpriseAuthToken('REQ COMPANY');
    const mockResEntity = await mockedGetEnterpriseAuthToken('RES COMPANY');
    const requestOpts = {
      redirectUri: 'https://acme.com/hello',
      requestBy: { type: PassBy.REFERENCE, referenceUri: 'https://my-request.com/here' },
      signatureType: {
        hexPrivateKey: mockReqEntity.hexPrivateKey,
        did: mockReqEntity.did,
        kid: `${mockReqEntity.did}#controller`
      },
      registration: {
        didMethodsSupported: 'did:ethr:',
        subjectIdentifiersSupported: SubjectIdentifierType.DID,
        credentialFormatsSupported: CredentialFormat.JSON_LD,
        registrationBy: { type: PassBy.VALUE }
      },
      claims: {
        'id_token': {
          'acr': null,
          'verifiable_presentations': {
            'presentation_definition': {
              'id': 'Credentials',
              'input_descriptors': [
                {
                  'id': 'ID Card Credential',
                  'schema': [
                    {
                      'uri': 'https://www.w3.org/2018/credentials/examples/v1/IDCardCredential'
                    },
                    {
                      'uri': 'https://www.w3.org/2018/credentials/examples/v1'
                    }
                  ],
                  'constraints': {
                    'limit_disclosure': 'required',
                    'fields': [
                      {
                        "path": [
                          "$.issuer.id"
                        ],
                        "purpose": "We can only verify bank accounts if they are attested by a source.",
                        "filter": {
                          "type": "string",
                          "pattern": "did:example:issuer"
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
    const vp: VP = new VP({
      context: [],
      presentation_submission: undefined,
      type: ['verifiableCredential'],
      verifiableCredential: [
        {
          'id': 'https://example.com/credentials/1872',
          'type': [
            'VerifiableCredential',
            'IDCardCredential'
          ],
          'credentialSubject': {
            'given_name': 'Fredrik',
            'family_name': 'Stremberg',
            'birthdate': '1949-01-22'
          }
        }
      ],
      proof: undefined
    });
    const responseOpts: AuthenticationResponseOpts = {
      registration: {
        registrationBy: {
          type: PassBy.REFERENCE,
          referenceUri: EXAMPLE_REFERENCE_URL
        }
      },
      signatureType: {
        did: mockResEntity.did,
        hexPrivateKey: mockResEntity.hexPrivateKey,
        kid: `${mockResEntity.did}#controller`
      },
      vp,
      did: mockResEntity.did,   // FIXME: Why do we need this, isn't this handled in the signature type already?
      responseMode: ResponseMode.POST
    };
    responseOpts.vp['id'] = 'ebc6f1c2';
    responseOpts.vp['type'] = ['VerifiablePresentation'];
    responseOpts.vp['holder'] = 'did:example:holder';
    responseOpts.vp.getVerifiableCredentials()[0]['@context'] = [
      'https://www.w3.org/2018/credentials/v1',
      'https://www.w3.org/2018/credentials/examples/v1'
    ];
    responseOpts.vp.getVerifiableCredentials()[0]['issuer'] = {
      'id': 'did:example:issuer'
    };
    responseOpts.vp.getVerifiableCredentials()[0]['issuanceDate'] = '2010-01-01T19:23:24Z';
    const requestWithJWT = await AuthenticationRequest.createJWT(requestOpts);
    console.log(JSON.stringify(await AuthenticationResponse.createJWTFromRequestJWT(requestWithJWT.jwt, responseOpts, verifyOpts)));
    await expect(AuthenticationResponse.createJWTFromRequestJWT(requestWithJWT.jwt, responseOpts, verifyOpts)).resolves.toBeDefined();
  });
});
