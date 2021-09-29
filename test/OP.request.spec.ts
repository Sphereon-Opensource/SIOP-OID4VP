import { SelectResults } from '@sphereon/pe-js';

import { OP, OPBuilder, RP, SIOP } from '../src';
import { State } from '../src/functions';
import {
  AuthenticationRequestOpts,
  AuthenticationResponseOpts, AuthenticationResponseWithJWT,
  CredentialFormat,
  PassBy,
  ResponseContext,
  ResponseMode,
  SubjectIdentifierType,
  VerificationMode,
  VerifyAuthenticationRequestOpts
} from '../src/types/SIOP.types';

import { mockedGetEnterpriseAuthToken } from './TestUtils';


const EXAMPLE_REDIRECT_URL = 'https://acme.com/hello';
const EXAMPLE_REFERENCE_URL = 'https://rp.acme.com/siop/jwts';

const HEX_KEY = 'f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f';
const DID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0';
const KID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#controller';


describe('OP Builder should', () => {
  it('throw Error when no arguments are passed', async () => {
    expect.assertions(1);
    await expect(() => new OPBuilder().build()).toThrowError(Error);
  });
  it('build an OP when all arguments are set', async () => {
    expect.assertions(1);

    expect(OP.builder()
      .addDidMethod('ethr')
      .response(ResponseMode.POST)
      .registrationBy(PassBy.REFERENCE, 'https://registration.here')
      .internalSignature('myprivatekey', 'did:example:123', 'did:example:123#key')
      .withExpiresIn(1000)
      .build()
    )
      .toBeInstanceOf(OP);
  });


});

describe('OP should', () => {
  const responseOpts: AuthenticationResponseOpts = {
    signatureType: {
      hexPrivateKey: HEX_KEY,
      did: DID,
      kid: KID
    },
    registration: {
      registrationBy: {
        type: SIOP.PassBy.VALUE
      }
    },
    responseMode: ResponseMode.POST,
    did: DID,
    expiresIn: 2000
  };

  const verifyOpts: VerifyAuthenticationRequestOpts = {
    verification: {
      mode: VerificationMode.INTERNAL,
      resolveOpts: {
        didMethods: ['ethr']
      }
    },
    nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg'
  };

  it('throw Error when build from request opts without enough params', async () => {
    expect.assertions(1);
    await expect(() => OP.fromOpts({} as never, {} as never)).toThrowError(Error);
  });

  it('return an OP when all request arguments are set', async () => {

    expect.assertions(1);

    expect(OP.fromOpts(responseOpts, verifyOpts)).toBeInstanceOf(OP);
  });

  it('succeed from request opts when all params are set', async () => {
    const mockEntity = await mockedGetEnterpriseAuthToken('ACME Corp');
    const requestOpts: AuthenticationRequestOpts = {
      redirectUri: EXAMPLE_REDIRECT_URL,
      requestBy: {
        type: SIOP.PassBy.REFERENCE,
        referenceUri: EXAMPLE_REFERENCE_URL
      },
      signatureType: {
        hexPrivateKey: mockEntity.hexPrivateKey,
        did: mockEntity.did,
        kid: `${mockEntity.did}#controller`
      },
      registration: {
        didMethodsSupported: ['did:ethr:'],
        subjectIdentifiersSupported: SubjectIdentifierType.DID,
        credentialFormatsSupported: [CredentialFormat.JWT],
        registrationBy: {
          type: SIOP.PassBy.VALUE
        }
      }

    };


    const requestURI = await RP.fromRequestOpts(requestOpts).createAuthenticationRequest({
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      state: 'b32f0087fc9816eb813fd11f'
    });

    const verifiedRequest = await OP.fromOpts(responseOpts, verifyOpts).verifyAuthenticationRequest(requestURI.jwt);
    console.log(JSON.stringify(verifiedRequest));
    expect(verifiedRequest.issuer).toMatch(mockEntity.did);
    expect(verifiedRequest.signer).toMatchObject({
      'id': `${mockEntity.did}#controller`,
      'type': 'EcdsaSecp256k1RecoveryMethod2020',
      'controller': `${mockEntity.did}`
    });
    expect(verifiedRequest.jwt).toBeDefined();
  });

  it('succeed from builder when all params are set', async () => {
    const rpMockEntity = await mockedGetEnterpriseAuthToken('ACME RP');
    const opMockEntity = await mockedGetEnterpriseAuthToken('ACME OP');

    const requestURI = await RP.builder()
      .redirect(EXAMPLE_REFERENCE_URL)
      .requestBy(PassBy.REFERENCE, EXAMPLE_REFERENCE_URL)
      .internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, `${rpMockEntity.did}#controller`)
      .addDidMethod('ethr')
      .registrationBy(PassBy.VALUE)
      .build()

      .createAuthenticationRequest({
        nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
        state: 'b32f0087fc9816eb813fd11f'
      });

    const verifiedRequest = await OP.builder()
      .withExpiresIn(1000)
      .addDidMethod('ethr')
      .internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, `${opMockEntity.did}#controller`)
      .registrationBy(PassBy.VALUE)
      .build()

      .verifyAuthenticationRequest(requestURI.jwt);
    console.log(JSON.stringify(verifiedRequest));
    expect(verifiedRequest.issuer).toMatch(rpMockEntity.did);
    expect(verifiedRequest.signer).toMatchObject({
      'id': `${rpMockEntity.did}#controller`,
      'type': 'EcdsaSecp256k1RecoveryMethod2020',
      'controller': `${rpMockEntity.did}`
    });
    expect(verifiedRequest.jwt).toBeDefined();
  });

  it('succeed from OP when selectVerifiableCredentialsForSubmission successfully gets the result', async () => {
    const mockEntity = await mockedGetEnterpriseAuthToken('ACME Corp');
    const opMockEntity = await mockedGetEnterpriseAuthToken('ACME OP');
    const state = State.getState();
    const HOLDER_DID = 'did:example:ebfeb1f712ebc6f1c276e12ec21';

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

    const vc = {
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
    };
    vc['issuer'] = {
      'id': 'did:example:issuer'
    };
    vc['@context'] = [
      'https://www.w3.org/2018/credentials/v1',
      'https://www.w3.org/2018/credentials/examples/v1'
    ];
    const selectResults: SelectResults = await OP.builder()
      .withExpiresIn(1000)
      .addDidMethod('ethr')
      .internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, `${opMockEntity.did}#controller`)
      .registrationBy(PassBy.VALUE)
      .build().selectVerifiableCredentialsForSubmission(
        payload,
        [vc],
        HOLDER_DID
      );
    expect(selectResults.errors.length).toBe(0);
    expect(selectResults.matches.length).toBe(1);
    expect(selectResults.matches[0].matches).toStrictEqual(['$.verifiableCredential[0]']);
  });

  it('succeed from OP when newAuthenticationResponseWithSelected successfully gets the result', async () => {
    const mockEntity = await mockedGetEnterpriseAuthToken('ACME Corp');
    const opMockEntity = {
      hexPrivateKey: '88a62d50de38dc22f5b4e7cc80d68a0f421ea489dda0e3bd5c165f08ce46e666',
      did: 'did:ethr:ropsten:0x03f8b96c88063da2b7f5cc90513560a7ec38b92616fff9c95ae95f46cc692a7c75',
      didKey: 'did:ethr:ropsten:0x03f8b96c88063da2b7f5cc90513560a7ec38b92616fff9c95ae95f46cc692a7c75#controller'
    };
    const rpMockEntity = {
      hexPrivateKey: 'a1458fac9ea502099f40be363ad3144d6d509aa5aa3d17158a9e6c3b67eb0397',
      did: 'did:ethr:ropsten:0x028360fb95417724cb7dd2ff217b15d6f17fc45e0ffc1b3dce6c2b8dd1e704fa98',
      didKey: 'did:ethr:ropsten:0x028360fb95417724cb7dd2ff217b15d6f17fc45e0ffc1b3dce6c2b8dd1e704fa98#controller'
    };
    const state = State.getState();
    const HOLDER_DID = 'did:example:ebfeb1f712ebc6f1c276e12ec21';

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

    const vc = {
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
    };
    vc['issuer'] = {
      'id': 'did:example:issuer'
    };
    vc['@context'] = [
      'https://www.w3.org/2018/credentials/v1',
      'https://www.w3.org/2018/credentials/examples/v1'
    ];
    const rp = RP.builder()
      .redirect(EXAMPLE_REDIRECT_URL)
      .requestBy(PassBy.VALUE)
      .internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey)
      .addDidMethod("ethr")
      .registrationBy(PassBy.VALUE)
      .build();
    const op = OP.builder()
      .withExpiresIn(1000)
      .addDidMethod("ethr")
      .internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey)
      .registrationBy(PassBy.VALUE)
      .build();
    await op.selectVerifiableCredentialsForSubmission(
      payload,
      [vc],
      HOLDER_DID
    );
    const requestURI = await rp.createAuthenticationRequest({
      nonce: "qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg",
      state: "b32f0087fc9816eb813fd11f"
    });
    const parsedAuthReqURI = await op.parseAuthenticationRequestURI(requestURI.encodedUri);
    const verifiedAuthReqWithJWT = await op.verifyAuthenticationRequest(parsedAuthReqURI.jwt);
    const authenticationResponseWithJWT: AuthenticationResponseWithJWT = await op.newAuthenticationResponseWithSelected(
      verifiedAuthReqWithJWT,
      {
        verifiableCredentials: [vc],
        holderDID: HOLDER_DID
      }
    );
    console.log(JSON.stringify(authenticationResponseWithJWT));
    expect(authenticationResponseWithJWT).toBeDefined()
  });
});
