import { IPresentationDefinition } from '@sphereon/pex';
import { ICredential, IVerifiableCredential, IVerifiablePresentation } from '@sphereon/ssi-types';

import { PresentationExchange } from '../src/main';
import { AuthenticationRequest, AuthenticationResponse } from '../src/main';
import SIOPErrors from '../src/main/types/Errors';
import { AuthenticationRequestOpts } from '../src/main/types/SIOP.types';
import {
  AuthenticationResponseOpts,
  CredentialFormat,
  PassBy,
  PresentationLocation,
  ResponseMode,
  SubjectIdentifierType,
  VerifiablePresentationTypeFormat,
  VerificationMode,
  VerifyAuthenticationRequestOpts,
} from '../src/main/types/SIOP.types';

import { mockedGetEnterpriseAuthToken } from './TestUtils';

// const EXAMPLE_REDIRECT_URL = "https://acme.com/hello";
const EXAMPLE_REFERENCE_URL = 'https://rp.acme.com/siop/jwts';
const HEX_KEY = 'f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f';
const DID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0';
const KID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#keys-1';

const validButExpiredJWT =
  'eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXRocjoweDUwMjM4M2Q0ZmIwOWIzQThEYzYxMzNFQkI2QzFGZTQyOUIxODAyNUEjY29udHJvbGxlciIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2MzIwODkxNTMsImV4cCI6MTYzMjA4OTc1MywicmVzcG9uc2VfdHlwZSI6ImlkX3Rva2VuIiwic2NvcGUiOiJvcGVuaWQiLCJjbGllbnRfaWQiOiJkaWQ6ZXRocjoweDUwMjM4M2Q0ZmIwOWI' +
  'zQThEYzYxMzNFQkI2QzFGZTQyOUIxODAyNUEiLCJyZWRpcmVjdF91cmkiOiJodHRwczovL2FjbWUuY29tL2hlbGxvIiwiaXNzIjoiZGlkOmV0aHI6MHg1MDIzODNkNGZiMDliM0E4RGM2MTMzRUJCNkMxRmU0MjlCMTgwMjVBIiwicmVzcG9uc2VfbW9kZSI6InBvc3QiLCJyZXNwb25zZV9jb250ZXh0IjoicnAiLCJub25jZSI6IlJtZ2l6SDhSQTFYRHJ5enZiNHM5c2tzRXBTd1haYTZLb0dqaUdzR0RzVlkiLCJzdG' +
  'F0ZSI6ImQ3N2M5NDBlYjc0MGYwMmIyMzgxZjYzMiIsInJlZ2lzdHJhdGlvbiI6eyJkaWRfbWV0aG9kc19zdXBwb3J0ZWQiOiJkaWQ6ZXRocjoiLCJzdWJqZWN0X2lkZW50aWZpZXJzX3N1cHBvcnRlZCI6ImRpZCJ9fQ.VqBgIB7A9oNDSv-s0jkLmxPQhazsXMRJ_4k77pqvkM1eV2Kr2B1mTd8scQWjKfbmtiCaDqSvyoUaIEFLWadwPQ';

describe('create JWT from Request JWT should', () => {
  const responseOpts: AuthenticationResponseOpts = {
    redirectUri: 'https://acme.com/hello',
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
        referenceUri: EXAMPLE_REFERENCE_URL,
      },
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
        didMethods: ['ethr'],
      },
      mode: VerificationMode.INTERNAL,
    },
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
    await expect(AuthenticationResponse.createJWTFromRequestJWT(validButExpiredJWT, responseOpts, verifyOpts)).rejects.toThrow(
      /invalid_jwt: JWT has expired: exp: 1632089753/
    );
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
        kid: `${mockReqEntity.did}#controller`,
      },
      registration: {
        didMethodsSupported: 'did:ethr:',
        subjectIdentifiersSupported: SubjectIdentifierType.DID,
        credentialFormatsSupported: CredentialFormat.JSON_LD,
        registrationBy: { type: PassBy.VALUE },
      },
    };
    const responseOpts: AuthenticationResponseOpts = {
      redirectUri: 'https://acme.com/hello',
      registration: {
        registrationBy: {
          type: PassBy.REFERENCE,
          referenceUri: EXAMPLE_REFERENCE_URL,
        },
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
  });

  it('succeed when valid JWT with PD is passed in', async () => {
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
      redirectUri: 'https://acme.com/hello',
      requestBy: { type: PassBy.REFERENCE, referenceUri: 'https://my-request.com/here' },
      signatureType: {
        hexPrivateKey: mockReqEntity.hexPrivateKey,
        did: mockReqEntity.did,
        kid: `${mockReqEntity.did}#controller`,
      },
      registration: {
        didMethodsSupported: 'did:ethr:',
        subjectIdentifiersSupported: SubjectIdentifierType.DID,
        credentialFormatsSupported: CredentialFormat.JSON_LD,
        registrationBy: { type: PassBy.VALUE },
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
    const result: IVerifiablePresentation = await pex.submissionFrom(definition, vp.verifiableCredential);
    const responseOpts: AuthenticationResponseOpts = {
      redirectUri: 'https://acme.com/hello',
      registration: {
        registrationBy: {
          type: PassBy.REFERENCE,
          referenceUri: EXAMPLE_REFERENCE_URL,
        },
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
});
