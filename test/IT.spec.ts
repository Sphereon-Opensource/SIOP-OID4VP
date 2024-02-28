import { EventEmitter } from 'events';

import { IPresentationDefinition } from '@sphereon/pex';
import { CredentialMapper, IPresentation, IProofType, IVerifiableCredential, W3CVerifiablePresentation } from '@sphereon/ssi-types';
import { IVerifyCallbackArgs, IVerifyCredentialResult, VerifyCallback, WDCErrors } from '@sphereon/wellknown-dids-client';
import nock from 'nock';

import {
  CheckLinkedDomain,
  OP,
  PassBy,
  PresentationDefinitionWithLocation,
  PresentationExchange,
  PresentationSignCallback,
  PresentationVerificationCallback,
  PropertyTarget,
  ResponseIss,
  ResponseType,
  RevocationStatus,
  RevocationVerification,
  RP,
  Scope,
  SigningAlgo,
  SubjectType,
  SupportedVersion,
  VerificationMode,
  verifyRevocation,
  VPTokenLocation,
} from '../src';
import { checkSIOPSpecVersionSupported } from '../src/helpers/SIOPSpecVersion';
import { InMemoryRPSessionManager } from '../src/rp/InMemoryRPSessionManager';

import { mockedGetEnterpriseAuthToken, WELL_KNOWN_OPENID_FEDERATION } from './TestUtils';
import {
  UNIT_TEST_TIMEOUT,
  VERIFIER_LOGO_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT_NL,
  VERIFIERZ_PURPOSE_TO_VERIFY,
  VERIFIERZ_PURPOSE_TO_VERIFY_NL,
} from './data/mockedData';

jest.setTimeout(30000);

const EXAMPLE_REDIRECT_URL = 'https://acme.com/hello';
const EXAMPLE_REFERENCE_URL = 'https://rp.acme.com/siop/jwts';

const HOLDER_DID = 'did:example:ebfeb1f712ebc6f1c276e12ec21';

const presentationSignCallback: PresentationSignCallback = async (_args) => ({
  ...(_args.presentation as IPresentation),
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

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const verifyCallback: VerifyCallback = async (_args: IVerifyCallbackArgs) => ({ verified: true });

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const presentationVerificationCallback: PresentationVerificationCallback = async (_args: W3CVerifiablePresentation) => ({
  verified: true,
});

function getPresentationDefinition(): IPresentationDefinition {
  return {
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
}

function getVCs(): IVerifiableCredential[] {
  const vcs: IVerifiableCredential[] = [
    {
      identifier: '83627465',
      name: 'Permanent Resident Card',
      type: ['PermanentResidentCard', 'VerifiableCredential'],
      id: 'https://issuer.oidp.uscis.gov/credentials/83627465dsdsdsd',
      credentialSubject: {
        birthCountry: 'Bahamas',
        id: 'did:example:b34ca6cd37bbf23',
        type: ['PermanentResident', 'Person'],
        gender: 'Female',
        familyName: 'SMITH',
        givenName: 'JANE',
        residentSince: '2015-01-01',
        lprNumber: '999-999-999',
        birthDate: '1958-07-17',
        commuterClassification: 'C1',
        lprCategory: 'C09',
        image: 'data:image/png;base64,iVBORw0KGgokJggg==',
      },
      expirationDate: '2029-12-03T12:19:52Z',
      description: 'Government of Example Permanent Resident Card.',
      issuanceDate: '2019-12-03T12:19:52Z',
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/citizenship/v1', 'https://w3id.org/security/suites/ed25519-2020/v1'],
      issuer: 'did:key:z6MkhfRoL9n7ko9d6LnB5jLB4aejd3ir2q6E2xkuzKUYESig',
      proof: {
        type: 'BbsBlsSignatureProof2020',
        created: '2020-04-25',
        verificationMethod: 'did:example:489398593#test',
        proofPurpose: 'assertionMethod',
        proofValue:
          'kTTbA3pmDa6Qia/JkOnIXDLmoBz3vsi7L5t3DWySI/VLmBqleJ/Tbus5RoyiDERDBEh5rnACXlnOqJ/U8yFQFtcp/mBCc2FtKNPHae9jKIv1dm9K9QK1F3GI1AwyGoUfjLWrkGDObO1ouNAhpEd0+et+qiOf2j8p3MTTtRRx4Hgjcl0jXCq7C7R5/nLpgimHAAAAdAx4ouhMk7v9dXijCIMaG0deicn6fLoq3GcNHuH5X1j22LU/hDu7vvPnk/6JLkZ1xQAAAAIPd1tu598L/K3NSy0zOy6obaojEnaqc1R5Ih/6ZZgfEln2a6tuUp4wePExI1DGHqwj3j2lKg31a/6bSs7SMecHBQdgIYHnBmCYGNQnu/LZ9TFV56tBXY6YOWZgFzgLDrApnrFpixEACM9rwrJ5ORtxAAAAAgE4gUIIC9aHyJNa5TBklMOh6lvQkMVLXa/vEl+3NCLXblxjgpM7UEMqBkE9/QcoD3Tgmy+z0hN+4eky1RnJsEg=',
        nonce: '6i3dTz5yFfWJ8zgsamuyZa4yAHPm75tUOOXddR6krCvCYk77sbCOuEVcdBCDd/l6tIY=',
      },
    },
  ];
  vcs[0]['@context'] = ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/2018/credentials/examples/v1'];
  vcs[0]['issuer'] = {
    id: 'did:example:issuer',
  };
  return vcs;
}

describe('RP and OP interaction should', () => {
  it(
    'succeed when calling each other in the full flow',
    async () => {
      // expect.assertions(1);
      const rpMockEntity = await mockedGetEnterpriseAuthToken('ACME RP');
      const opMockEntity = await mockedGetEnterpriseAuthToken('ACME OP');

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const verifyCallback: VerifyCallback = async (_args) => ({ verified: true });
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const presentationVerificationCallback: PresentationVerificationCallback = async (_args) => ({ verified: true });

      const rp = RP.builder({ requestVersion: SupportedVersion.SIOPv2_ID1 })
        .withClientId(rpMockEntity.did)
        .withScope('test')
        .withResponseType(ResponseType.ID_TOKEN)
        .withRedirectUri(EXAMPLE_REDIRECT_URL)
        .withPresentationVerification(presentationVerificationCallback)
        .withWellknownDIDVerifyCallback(verifyCallback)
        .withRevocationVerification(RevocationVerification.NEVER)
        .withRequestBy(PassBy.REFERENCE, EXAMPLE_REFERENCE_URL)
        .withIssuer(ResponseIss.SELF_ISSUED_V2)
        .withInternalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, `${rpMockEntity.did}#controller`, SigningAlgo.ES256K)
        .addDidMethod('ethr')
        .withClientMetadata({
          client_id: WELL_KNOWN_OPENID_FEDERATION,
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
          requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          responseTypesSupported: [ResponseType.ID_TOKEN],
          vpFormatsSupported: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
          scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
          subjectTypesSupported: [SubjectType.PAIRWISE],
          subject_syntax_types_supported: ['did', 'did:ethr'],
          passBy: PassBy.VALUE,
          logo_uri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100317',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        })
        .withSupportedVersions([SupportedVersion.SIOPv2_ID1])
        .build();
      const op = OP.builder()
        .withPresentationSignCallback(presentationSignCallback)
        .withExpiresIn(1000)
        .withWellknownDIDVerifyCallback(verifyCallback)
        .withIssuer(ResponseIss.SELF_ISSUED_V2)
        .withInternalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, `${opMockEntity.did}#controller`, SigningAlgo.ES256K)
        .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
        //FIXME: Move payload options to seperate property
        .withRegistration({
          authorizationEndpoint: 'www.myauthorizationendpoint.com',
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
          issuer: ResponseIss.SELF_ISSUED_V2,
          requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          responseTypesSupported: [ResponseType.ID_TOKEN],
          vpFormats: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
          scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
          subjectTypesSupported: [SubjectType.PAIRWISE],
          subject_syntax_types_supported: ['did:ethr'],
          passBy: PassBy.VALUE,
          logo_uri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100318',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        })
        .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
        .build();

      const requestURI = await rp.createAuthorizationRequestURI({
        correlationId: '1234',
        nonce: { propertyValue: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg' },
        state: { propertyValue: 'b32f0087fc9816eb813fd11f' },
      });

      nock('https://rp.acme.com').get('/siop/jwts').times(3).reply(200, requestURI.requestObjectJwt);

      await checkSIOPSpecVersionSupported(requestURI.authorizationRequestPayload, op.verifyRequestOptions.supportedVersions);
      // The create method also calls the verifyRequest method, so no need to do it manually
      const verifiedRequest = await op.verifyAuthorizationRequest(requestURI.encodedUri);
      const authenticationResponseWithJWT = await op.createAuthorizationResponse(verifiedRequest);

      nock(EXAMPLE_REDIRECT_URL).post(/.*/).times(3).reply(200, { result: 'ok' });
      const response = await op.submitAuthorizationResponse(authenticationResponseWithJWT);
      await expect(response.json()).resolves.toMatchObject({ result: 'ok' });

      const verifiedAuthResponseWithJWT = await rp.verifyAuthorizationResponse(authenticationResponseWithJWT.response.payload, {
        // audience: EXAMPLE_REDIRECT_URL,
      });

      expect(verifiedAuthResponseWithJWT.idToken.jwt).toBeDefined();
      expect(verifiedAuthResponseWithJWT.idToken.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg');
    },
    UNIT_TEST_TIMEOUT
  );

  it('succeed when calling optional steps in the full flow', async () => {
    // expect.assertions(1);
    const rpMockEntity = {
      hexPrivateKey: '2bbd6a78be9ab2193bcf74aa6d39ab59c1d1e2f7e9ef899a38fb4d94d8aa90e2',
      did: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024',
      didKey: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024#controllerKey',
    };

    const opMockEntity = {
      hexPrivateKey: '73d24dd0fb69abdc12e7a99d8f9a970fdc8ad90598cc64cff35b584220ace0c8',
      did: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca',
      didKey: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca#controllerKey',
    };

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const verifyCallback = async (_args: IVerifyCallbackArgs): Promise<IVerifyCredentialResult> => ({ verified: true });
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const presentationVerificationCallback: PresentationVerificationCallback = async (_args) => ({ verified: true });

    const rp = RP.builder({ requestVersion: SupportedVersion.SIOPv2_ID1 })
      .withClientId(rpMockEntity.did)
      .withScope('test')
      .withResponseType(ResponseType.ID_TOKEN)
      .withRedirectUri(EXAMPLE_REDIRECT_URL)
      .withWellknownDIDVerifyCallback(verifyCallback)
      .withPresentationVerification(presentationVerificationCallback)
      .withRevocationVerification(RevocationVerification.NEVER)
      .withRequestBy(PassBy.VALUE)
      .withInternalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey, SigningAlgo.ES256K)
      .addDidMethod('ethr')
      .withClientMetadata({
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormatsSupported: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did', 'did:ethr'],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100319',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      .build();
    const op = OP.builder()
      .withExpiresIn(1000)
      .withWellknownDIDVerifyCallback(verifyCallback)
      .addDidMethod('ethr')
      .withInternalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey, SigningAlgo.ES256K)
      .withRegistration({
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        issuer: ResponseIss.SELF_ISSUED_V2,
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormats: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: [],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100320',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      .build();

    const requestURI = await rp.createAuthorizationRequestURI({
      correlationId: '1234',
      nonce: { propertyValue: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg' },
      state: { propertyValue: 'b32f0087fc9816eb813fd11f' },
    });

    // Let's test the parsing
    const parsedAuthReqURI = await op.parseAuthorizationRequestURI(requestURI.encodedUri);
    expect(parsedAuthReqURI.authorizationRequestPayload).toBeDefined();
    expect(parsedAuthReqURI.requestObjectJwt).toBeDefined();

    const verifiedAuthReqWithJWT = await op.verifyAuthorizationRequest(parsedAuthReqURI.requestObjectJwt, { correlationId: '1234' });
    expect(verifiedAuthReqWithJWT.signer).toBeDefined();
    expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did);

    const authenticationResponseWithJWT = await op.createAuthorizationResponse(verifiedAuthReqWithJWT);
    expect(authenticationResponseWithJWT).toBeDefined();
    expect(authenticationResponseWithJWT.correlationId).toEqual('1234');
    expect(authenticationResponseWithJWT.response.payload).toBeDefined();
    expect(authenticationResponseWithJWT.response.idToken).toBeDefined();

    const verifiedAuthResponseWithJWT = await rp.verifyAuthorizationResponse(authenticationResponseWithJWT.response.payload, {
      /*audience: EXAMPLE_REDIRECT_URL,*/
    });

    expect(verifiedAuthResponseWithJWT.idToken.jwt).toBeDefined();
    expect(verifiedAuthResponseWithJWT.idToken.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg');
  });

  it('fail when calling with presentation definitions and without verifiable presentation', async () => {
    const rpMockEntity = {
      hexPrivateKey: '2bbd6a78be9ab2193bcf74aa6d39ab59c1d1e2f7e9ef899a38fb4d94d8aa90e2',
      did: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024',
      didKey: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024#controllerKey',
    };

    const opMockEntity = {
      hexPrivateKey: '73d24dd0fb69abdc12e7a99d8f9a970fdc8ad90598cc64cff35b584220ace0c8',
      did: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca',
      didKey: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca#controllerKey',
    };

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const verifyCallback = async (_args: IVerifyCallbackArgs): Promise<IVerifyCredentialResult> => ({ verified: true });
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const presentationVerificationCallback: PresentationVerificationCallback = async (_args) => ({ verified: true });

    const rp = RP.builder({ requestVersion: SupportedVersion.SIOPv2_ID1 })
      .withClientId(WELL_KNOWN_OPENID_FEDERATION)
      .withScope('test')
      .withResponseType([ResponseType.ID_TOKEN, ResponseType.VP_TOKEN])
      .withRedirectUri(EXAMPLE_REDIRECT_URL)
      .withWellknownDIDVerifyCallback(verifyCallback)
      .withPresentationVerification(presentationVerificationCallback)
      .withRevocationVerification(RevocationVerification.NEVER)
      .withRequestBy(PassBy.VALUE)
      .withInternalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey, SigningAlgo.ES256K)
      .addDidMethod('ethr')
      .withClientMetadata({
        client_id: rpMockEntity.did,
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN, ResponseType.VP_TOKEN],
        vpFormatsSupported: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did', 'did:ethr'],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100321',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withPresentationDefinition({ definition: getPresentationDefinition() })
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      .build();
    const op = OP.builder()
      .withExpiresIn(1000)
      .withWellknownDIDVerifyCallback(verifyCallback)
      .addDidMethod('ethr')
      .withInternalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey, SigningAlgo.ES256K)
      .withRegistration({
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        issuer: ResponseIss.SELF_ISSUED_V2,
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256K],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormats: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: [],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100321',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      .build();

    const requestURI = await rp.createAuthorizationRequestURI({
      correlationId: '1234',
      nonce: { propertyValue: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg' },
      state: { propertyValue: 'b32f0087fc9816eb813fd11f' },
    });

    //The schema validation needs to be done here otherwise it fails because of JWT properties
    await checkSIOPSpecVersionSupported(requestURI.authorizationRequestPayload, op.verifyRequestOptions.supportedVersions);
    // Let's test the parsing
    const parsedAuthReqURI = await op.parseAuthorizationRequestURI(requestURI.encodedUri);
    expect(parsedAuthReqURI.authorizationRequestPayload).toBeDefined();
    expect(parsedAuthReqURI.requestObjectJwt).toBeDefined();
    // expect(parsedAuthReqURI.registration).toBeDefined();

    const verifiedAuthReqWithJWT = await op.verifyAuthorizationRequest(parsedAuthReqURI.requestObjectJwt);
    expect(verifiedAuthReqWithJWT.signer).toBeDefined();
    expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did);
    await expect(op.createAuthorizationResponse(verifiedAuthReqWithJWT)).rejects.toThrow(
      Error('authentication request expects a verifiable presentation in the response')
    );

    expect(verifiedAuthReqWithJWT.payload['registration'].client_name).toEqual(VERIFIER_NAME_FOR_CLIENT);
    expect(verifiedAuthReqWithJWT.payload['registration']['client_name#nl-NL']).toEqual(VERIFIER_NAME_FOR_CLIENT_NL + '2022100321');
  });

  it('succeed when calling with presentation definitions and right verifiable presentation', async () => {
    try {
      const rpMockEntity = {
        hexPrivateKey: '2bbd6a78be9ab2193bcf74aa6d39ab59c1d1e2f7e9ef899a38fb4d94d8aa90e2',
        did: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024',
        didKey: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024#controllerKey',
      };

      const opMockEntity = {
        hexPrivateKey: '73d24dd0fb69abdc12e7a99d8f9a970fdc8ad90598cc64cff35b584220ace0c8',
        did: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca',
        didKey: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca#controllerKey',
      };

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const verifyCallback = async (_args: IVerifyCallbackArgs): Promise<IVerifyCredentialResult> => ({ verified: true });
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const presentationVerificationCallback: PresentationVerificationCallback = async (_args) => ({ verified: true });

      const rp = RP.builder({ requestVersion: SupportedVersion.SIOPv2_ID1 })
        .withClientId(rpMockEntity.did)
        .withScope('test')
        .withResponseType([ResponseType.ID_TOKEN, ResponseType.VP_TOKEN])
        .withRedirectUri(EXAMPLE_REDIRECT_URL)
        .withPresentationDefinition({ definition: getPresentationDefinition() }, [
          PropertyTarget.REQUEST_OBJECT,
          PropertyTarget.AUTHORIZATION_REQUEST,
        ])
        .withPresentationVerification(presentationVerificationCallback)
        .withWellknownDIDVerifyCallback(verifyCallback)
        .withRevocationVerification(RevocationVerification.NEVER)
        .withRequestBy(PassBy.VALUE)
        .withInternalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey, SigningAlgo.ES256K)
        .withAuthorizationEndpoint('www.myauthorizationendpoint.com')
        .addDidMethod('ethr')
        .withClientMetadata({
          client_id: WELL_KNOWN_OPENID_FEDERATION,
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
          requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          responseTypesSupported: [ResponseType.ID_TOKEN],
          vpFormatsSupported: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
          scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
          subjectTypesSupported: [SubjectType.PAIRWISE],
          subject_syntax_types_supported: ['did', 'did:ethr'],
          passBy: PassBy.VALUE,
          logo_uri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100322',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        })
        .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
        .build();
      const op = OP.builder()
        .withPresentationSignCallback(presentationSignCallback)
        .withExpiresIn(1000)
        .withWellknownDIDVerifyCallback(verifyCallback)
        .addDidMethod('ethr')
        .withInternalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey, SigningAlgo.ES256K)
        .withRegistration({
          authorizationEndpoint: 'www.myauthorizationendpoint.com',
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
          issuer: ResponseIss.SELF_ISSUED_V2,
          requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          responseTypesSupported: [ResponseType.ID_TOKEN, ResponseType.VP_TOKEN],
          vpFormats: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
          scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
          subjectTypesSupported: [SubjectType.PAIRWISE],
          subject_syntax_types_supported: [],
          passBy: PassBy.VALUE,
          logo_uri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100323',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        })
        .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
        .build();

      const requestURI = await rp.createAuthorizationRequestURI({
        correlationId: '1234',
        nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
        state: 'b32f0087fc9816eb813fd11f',
      });

      // Let's test the parsing
      const parsedAuthReqURI = await op.parseAuthorizationRequestURI(requestURI.encodedUri);
      expect(parsedAuthReqURI.authorizationRequestPayload).toBeDefined();
      expect(parsedAuthReqURI.requestObjectJwt).toBeDefined();
      // expect(parsedAuthReqURI.registration).toBeDefined();

      const verifiedAuthReqWithJWT = await op.verifyAuthorizationRequest(parsedAuthReqURI.requestObjectJwt);
      expect(verifiedAuthReqWithJWT.signer).toBeDefined();
      expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did);
      const pex = new PresentationExchange({ allDIDs: [HOLDER_DID], allVerifiableCredentials: getVCs() });
      const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(
        parsedAuthReqURI.authorizationRequestPayload
      );
      await pex.selectVerifiableCredentialsForSubmission(pd[0].definition);
      const verifiablePresentationResult = await pex.createVerifiablePresentation(pd[0].definition, getVCs(), presentationSignCallback, {});
      const authenticationResponseWithJWT = await op.createAuthorizationResponse(verifiedAuthReqWithJWT, {
        presentationExchange: {
          verifiablePresentations: [verifiablePresentationResult.verifiablePresentation],
          vpTokenLocation: VPTokenLocation.AUTHORIZATION_RESPONSE,
          presentationSubmission: verifiablePresentationResult.presentationSubmission,
          /*credentialsAndDefinitions: [
          {
            presentation: vp,
            format: VerifiablePresentationTypeFormat.LDP_VP,
            vpTokenLocation: VPTokenLocation.AUTHORIZATION_RESPONSE,
          },
        ],*/
        },
      });
      expect(authenticationResponseWithJWT.response.payload).toBeDefined();
      expect(authenticationResponseWithJWT.response.idToken).toBeDefined();

      const verifiedAuthResponseWithJWT = await rp.verifyAuthorizationResponse(authenticationResponseWithJWT.response.payload, {
        /*audience: EXAMPLE_REDIRECT_URL,*/
        presentationDefinitions: [{ definition: pd[0].definition, location: pd[0].location }],
      });

      expect(verifiedAuthResponseWithJWT.idToken.jwt).toBeDefined();
      expect(verifiedAuthResponseWithJWT.idToken.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg');
    } catch (error) {
      console.error(error);
      throw error;
    }
  });

  it(
    'should fail when calling with CheckLinkedDomain.ALWAYS',
    async () => {
      const rpMockEntity = {
        hexPrivateKey: '2bbd6a78be9ab2193bcf74aa6d39ab59c1d1e2f7e9ef899a38fb4d94d8aa90e2',
        did: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024',
        didKey: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024#controllerKey',
      };

      const opMockEntity = {
        hexPrivateKey: '73d24dd0fb69abdc12e7a99d8f9a970fdc8ad90598cc64cff35b584220ace0c8',
        did: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca',
        didKey: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca#controllerKey',
      };
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const verifyCallback = async (_args: IVerifyCallbackArgs): Promise<IVerifyCredentialResult> => ({ verified: true });
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const presentationVerificationCallback: PresentationVerificationCallback = async (_args) => ({ verified: true });

      const rp = RP.builder({ requestVersion: SupportedVersion.SIOPv2_ID1 })
        .withClientId(rpMockEntity.did)
        .withScope('test')
        .withResponseType(ResponseType.ID_TOKEN)
        .withCheckLinkedDomain(CheckLinkedDomain.ALWAYS)
        .withPresentationVerification(presentationVerificationCallback)
        .withWellknownDIDVerifyCallback(verifyCallback)
        .withRedirectUri(EXAMPLE_REDIRECT_URL)
        .withRequestBy(PassBy.VALUE)
        .withInternalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey, SigningAlgo.ES256K)
        .withAuthorizationEndpoint('www.myauthorizationendpoint.com')
        .withClientMetadata({
          client_id: WELL_KNOWN_OPENID_FEDERATION,
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
          requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          responseTypesSupported: [ResponseType.ID_TOKEN],
          vpFormatsSupported: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
          scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
          subjectTypesSupported: [SubjectType.PAIRWISE],
          subject_syntax_types_supported: ['did', 'did:ethr'],
          passBy: PassBy.VALUE,
          logo_uri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100324',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        })
        .withPresentationDefinition({ definition: getPresentationDefinition() }, [
          PropertyTarget.REQUEST_OBJECT,
          PropertyTarget.AUTHORIZATION_REQUEST,
        ])
        .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
        .build();
      const op = OP.builder()
        .withPresentationSignCallback(presentationSignCallback)
        .withExpiresIn(1000)
        .withWellknownDIDVerifyCallback(verifyCallback)
        .withInternalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey, SigningAlgo.ES256K)
        .withRegistration({
          authorizationEndpoint: 'www.myauthorizationendpoint.com',
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
          issuer: ResponseIss.SELF_ISSUED_V2,
          requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          responseTypesSupported: [ResponseType.ID_TOKEN],
          vpFormats: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
          scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
          subjectTypesSupported: [SubjectType.PAIRWISE],
          subject_syntax_types_supported: ['did'],
          passBy: PassBy.VALUE,
          logo_uri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100325',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        })
        .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
        .build();

      const requestURI = await rp.createAuthorizationRequestURI({
        correlationId: '1234',
        nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
        state: 'b32f0087fc9816eb813fd11f',
      });

      // Let's test the parsing
      const parsedAuthReqURI = await op.parseAuthorizationRequestURI(requestURI.encodedUri);
      expect(parsedAuthReqURI.authorizationRequestPayload).toBeDefined();
      expect(parsedAuthReqURI.requestObjectJwt).toBeDefined();
      // expect(parsedAuthReqURI.registration).toBeDefined();

      const verifiedAuthReqWithJWT = await op.verifyAuthorizationRequest(parsedAuthReqURI.requestObjectJwt);
      expect(verifiedAuthReqWithJWT.signer).toBeDefined();
      expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did);
      const pex = new PresentationExchange({ allDIDs: [HOLDER_DID], allVerifiableCredentials: getVCs() });
      const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(
        parsedAuthReqURI.authorizationRequestPayload
      );
      await pex.selectVerifiableCredentialsForSubmission(pd[0].definition);
      const verifiablePresentationResult = await pex.createVerifiablePresentation(pd[0].definition, getVCs(), presentationSignCallback, {});
      const authenticationResponseWithJWT = await op.createAuthorizationResponse(verifiedAuthReqWithJWT, {
        presentationExchange: {
          verifiablePresentations: [verifiablePresentationResult.verifiablePresentation],
          presentationSubmission: verifiablePresentationResult.presentationSubmission,
          // vpTokenLocation: VPTokenLocation.AUTHORIZATION_RESPONSE,
          /*credentialsAndDefinitions: [
            {
              presentation: verifiablePresentationResult,
              format: VerifiablePresentationTypeFormat.LDP_VP,
              vpTokenLocation: VPTokenLocation.AUTHORIZATION_RESPONSE,
            },
          ],*/
        },
      });
      expect(authenticationResponseWithJWT.response.payload).toBeDefined();
      await expect(
        rp.verifyAuthorizationResponse(authenticationResponseWithJWT.response.payload, {
          // audience: EXAMPLE_REDIRECT_URL,
          presentationDefinitions: [{ definition: pd[0].definition, location: pd[0].location }],
          verification: {
            mode: VerificationMode.INTERNAL,
            verifyUri: '',
            resolveOpts: {
              subjectSyntaxTypesSupported: ['did', 'did:eth'],
            },
            checkLinkedDomain: CheckLinkedDomain.ALWAYS,
            wellknownDIDVerifyCallback: verifyCallback,
            revocationOpts: {
              revocationVerification: RevocationVerification.ALWAYS,
              // eslint-disable-next-line @typescript-eslint/no-unused-vars
              revocationVerificationCallback: (_credential, _type) => Promise.resolve({ status: RevocationStatus.VALID }),
            },
          },
        })
      ).rejects.toThrow(new Error(WDCErrors.PROPERTY_SERVICE_NOT_PRESENT));
    },
    UNIT_TEST_TIMEOUT
  );

  it('succeed when calling with CheckLinkedDomain.ALWAYS', async () => {
    const rpMockEntity = {
      hexPrivateKey: '2bbd6a78be9ab2193bcf74aa6d39ab59c1d1e2f7e9ef899a38fb4d94d8aa90e2',
      did: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024',
      didKey: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024#controllerKey',
    };

    const opMockEntity = {
      hexPrivateKey: '88a62d50de38dc22f5b4e7cc80d68a0f421ea489dda0e3bd5c165f08ce46e666',
      did: 'did:ion:EiCMvVdXv6iL3W8i4n-LmqUhE614kX4TYxVR5kTY2QGOjg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXkxIiwicHVibGljS2V5SndrIjp7ImNydiI6InNlY3AyNTZrMSIsImt0eSI6IkVDIiwieCI6Ii1MbHNpQVk5b3JmMXpKQlJOV0NuN0RpNUpoYl8tY2xhNlY5R3pHa3FmSFUiLCJ5IjoiRXBIU25GZHQ2ZU5lRkJEZzNVNVFIVDE0TVRsNHZIc0h5NWRpWU9DWEs1TSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiIsImFzc2VydGlvbk1ldGhvZCJdLCJ0eXBlIjoiRWNkc2FTZWNwMjU2azFWZXJpZmljYXRpb25LZXkyMDE5In1dLCJzZXJ2aWNlcyI6W3siaWQiOiJsZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vbGR0ZXN0LnNwaGVyZW9uLmNvbSIsInR5cGUiOiJMaW5rZWREb21haW5zIn1dfX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlBem8wTVVZUW5HNWM0VFJKZVFsNFR5WVRrSmRyeTJoeXlQUlpENzdFQm1CdyJ9LCJzdWZmaXhEYXRhIjp7ImRlbHRhSGFzaCI6IkVpQUwtaEtrLUVsODNsRVJiZkFDUk1kSWNQVjRXWGJqZ3dsZ1ZDWTNwbDhhMGciLCJyZWNvdmVyeUNvbW1pdG1lbnQiOiJFaUItT2NSbTlTNXdhU3QxbU4zSG4zM2RnMzJKN25MOEdBVHpGQ2ZXaWdIXzh3In19',
      didKey:
        'did:ion:EiCMvVdXv6iL3W8i4n-LmqUhE614kX4TYxVR5kTY2QGOjg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXkxIiwicHVibGljS2V5SndrIjp7ImNydiI6InNlY3AyNTZrMSIsImt0eSI6IkVDIiwieCI6Ii1MbHNpQVk5b3JmMXpKQlJOV0NuN0RpNUpoYl8tY2xhNlY5R3pHa3FmSFUiLCJ5IjoiRXBIU25GZHQ2ZU5lRkJEZzNVNVFIVDE0TVRsNHZIc0h5NWRpWU9DWEs1TSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiIsImFzc2VydGlvbk1ldGhvZCJdLCJ0eXBlIjoiRWNkc2FTZWNwMjU2azFWZXJpZmljYXRpb25LZXkyMDE5In1dLCJzZXJ2aWNlcyI6W3siaWQiOiJsZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vbGR0ZXN0LnNwaGVyZW9uLmNvbSIsInR5cGUiOiJMaW5rZWREb21haW5zIn1dfX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlBem8wTVVZUW5HNWM0VFJKZVFsNFR5WVRrSmRyeTJoeXlQUlpENzdFQm1CdyJ9LCJzdWZmaXhEYXRhIjp7ImRlbHRhSGFzaCI6IkVpQUwtaEtrLUVsODNsRVJiZkFDUk1kSWNQVjRXWGJqZ3dsZ1ZDWTNwbDhhMGciLCJyZWNvdmVyeUNvbW1pdG1lbnQiOiJFaUItT2NSbTlTNXdhU3QxbU4zSG4zM2RnMzJKN25MOEdBVHpGQ2ZXaWdIXzh3In19#key1',
    };

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const verifyCallback = async (_args: IVerifyCallbackArgs): Promise<IVerifyCredentialResult> => ({ verified: true });
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const presentationVerificationCallback: PresentationVerificationCallback = async (_args) => ({ verified: true });

    const rp = RP.builder({ requestVersion: SupportedVersion.SIOPv2_ID1 })
      .withClientId(rpMockEntity.did)
      .withScope('test')
      .withResponseType([ResponseType.ID_TOKEN, ResponseType.VP_TOKEN])
      .withCheckLinkedDomain(CheckLinkedDomain.ALWAYS)
      .withPresentationVerification(presentationVerificationCallback)
      .withWellknownDIDVerifyCallback(verifyCallback)
      .withRevocationVerification(RevocationVerification.NEVER)
      .withRedirectUri(EXAMPLE_REDIRECT_URL)
      .withRequestBy(PassBy.VALUE)
      .withInternalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey, SigningAlgo.ES256K)
      .withAuthorizationEndpoint('www.myauthorizationendpoint.com')
      .withClientMetadata({
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.ES256K],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.ES256K],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormatsSupported: {
          jwt_vc: { alg: [SigningAlgo.EDDSA] },
          ldp_vc: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp_vp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
        },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did', 'did:ion'],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100326',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withPresentationDefinition({ definition: getPresentationDefinition() }, [PropertyTarget.REQUEST_OBJECT, PropertyTarget.AUTHORIZATION_REQUEST])
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      .build();
    const op = OP.builder()
      .withPresentationSignCallback(presentationSignCallback)
      .withWellknownDIDVerifyCallback(verifyCallback)
      .withExpiresIn(1000)
      .withInternalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey, SigningAlgo.ES256K)
      .withRegistration({
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.ES256K],
        issuer: ResponseIss.SELF_ISSUED_V2,
        requestObjectSigningAlgValuesSupported: [SigningAlgo.ES256K],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormats: {
          jwt_vc: { alg: [SigningAlgo.EDDSA] },
          ldp_vc: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp_vp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
        },
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100327',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did:ethr'],
        passBy: PassBy.VALUE,
      })
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      .build();

    const requestURI = await rp.createAuthorizationRequestURI({
      correlationId: '1234',
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      state: 'b32f0087fc9816eb813fd11f',
    });

    // Let's test the parsing
    const parsedAuthReqURI = await op.parseAuthorizationRequestURI(requestURI.encodedUri);
    expect(parsedAuthReqURI.authorizationRequestPayload).toBeDefined();
    expect(parsedAuthReqURI.requestObjectJwt).toBeDefined();
    // expect(parsedAuthReqURI.registration).toBeDefined();

    const verifiedAuthReqWithJWT = await op.verifyAuthorizationRequest(parsedAuthReqURI.requestObjectJwt);
    expect(verifiedAuthReqWithJWT.signer).toBeDefined();
    expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did);
    const pex = new PresentationExchange({ allDIDs: [HOLDER_DID], allVerifiableCredentials: getVCs() });
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(
      parsedAuthReqURI.authorizationRequestPayload
    );
    await pex.selectVerifiableCredentialsForSubmission(pd[0].definition);
    const verifiablePresentationResult = await pex.createVerifiablePresentation(pd[0].definition, getVCs(), presentationSignCallback, {});
    const authenticationResponseWithJWT = await op.createAuthorizationResponse(verifiedAuthReqWithJWT, {
      presentationExchange: {
        verifiablePresentations: [verifiablePresentationResult.verifiablePresentation],
        presentationSubmission: verifiablePresentationResult.presentationSubmission,
        vpTokenLocation: VPTokenLocation.AUTHORIZATION_RESPONSE,
        /*credentialsAndDefinitions: [
          {
            presentation: vp,
            format: VerifiablePresentationTypeFormat.LDP_VP,
            vpTokenLocation: VPTokenLocation.AUTHORIZATION_RESPONSE,
          },
        ],*/
      },
    });
    expect(authenticationResponseWithJWT.response.payload).toBeDefined();

    const DID_CONFIGURATION = {
      '@context': 'https://identity.foundation/.well-known/did-configuration/v1',
      linked_dids: [
        'eyJhbGciOiJSUzI1NiIsImtpZCI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNI3o2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSJ9.eyJleHAiOjE3NjQ4NzkxMzksImlzcyI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwibmJmIjoxNjA3MTEyNzM5LCJzdWIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9pZGVudGl0eS5mb3VuZGF0aW9uLy53ZWxsLWtub3duL2RpZC1jb25maWd1cmF0aW9uL3YxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1rb1RIc2dOTnJieThKekNOUTFpUkx5VzVRUTZSOFh1dTZBQThpZ0dyTVZQVU0iLCJvcmlnaW4iOiJodHRwczovL2lkZW50aXR5LmZvdW5kYXRpb24ifSwiZXhwaXJhdGlvbkRhdGUiOiIyMDI1LTEyLTA0VDE0OjEyOjE5LTA2OjAwIiwiaXNzdWFuY2VEYXRlIjoiMjAyMC0xMi0wNFQxNDoxMjoxOS0wNjowMCIsImlzc3VlciI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkRvbWFpbkxpbmthZ2VDcmVkZW50aWFsIl19fQ.YZnpPMAW3GdaPXC2YKoJ7Igt1OaVZKq09XZBkptyhxTAyHTkX2Ewtew-JKHKQjyDyabY3HAy1LUPoIQX0jrU0J82pIYT3k2o7nNTdLbxlgb49FcDn4czntt5SbY0m1XwrMaKEvV0bHQsYPxNTqjYsyySccgPfmvN9IT8gRS-M9a6MZQxuB3oEMrVOQ5Vco0bvTODXAdCTHibAk1FlvKz0r1vO5QMhtW4OlRrVTI7ibquf9Nim_ch0KeMMThFjsBDKetuDF71nUcL5sf7PCFErvl8ZVw3UK4NkZ6iM-XIRsLL6rXP2SnDUVovcldhxd_pyKEYviMHBOgBdoNP6fOgRQ',
        'eyJhbGciOiJSUzI1NiIsImtpZCI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNI3o2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSJ9.eyJleHAiOjE3NjQ4NzkxMzksImlzcyI6ImRpZDprZXk6b3RoZXIiLCJuYmYiOjE2MDcxMTI3MzksInN1YiI6ImRpZDprZXk6b3RoZXIiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vaWRlbnRpdHkuZm91bmRhdGlvbi8ud2VsbC1rbm93bi9kaWQtY29uZmlndXJhdGlvbi92MSJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDprZXk6b3RoZXIiLCJvcmlnaW4iOiJodHRwczovL2lkZW50aXR5LmZvdW5kYXRpb24ifSwiZXhwaXJhdGlvbkRhdGUiOiIyMDI1LTEyLTA0VDE0OjEyOjE5LTA2OjAwIiwiaXNzdWFuY2VEYXRlIjoiMjAyMC0xMi0wNFQxNDoxMjoxOS0wNjowMCIsImlzc3VlciI6ImRpZDprZXk6b3RoZXIiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRG9tYWluTGlua2FnZUNyZWRlbnRpYWwiXX19.rRuc-ojuEgyq8p_tBYK7BayuiNTBeXNyAnC14Rnjs-jsnhae4_E1Q12W99K2NGCGBi5KjNsBcZmdNJPxejiKPrjjcB99poFCgTY8tuRzDjVo0lIeBwfx9qqjKHTRTUR8FGM_imlOpVfBF4AHYxjkHvZn6c9lYvatYcDpB2UfH4BNXkdSVrUXy_kYjpMpAdRtyCAnD_isN1YpEHBqBmnfuVUbYcQK5kk6eiokRFDtWruL1OEeJMYPqjuBSd2m-H54tSM84Oic_pg2zXDjjBlXNelat6MPNT2QxmkwJg7oyewQWX2Ot2yyhSp9WyAQWMlQIe2x84R0lADUmZ1TPQchNw',
      ],
    };
    expect(rp.verifyResponseOptions.verification.checkLinkedDomain).toBe(CheckLinkedDomain.ALWAYS);
    nock('https://ldtest.sphereon.com').get('/.well-known/did-configuration.json').times(3).reply(200, DID_CONFIGURATION);
    const verifiedAuthResponseWithJWT = await rp.verifyAuthorizationResponse(authenticationResponseWithJWT.response.payload, {
      presentationDefinitions: [{ definition: pd[0].definition, location: pd[0].location }],
      // audience: EXAMPLE_REDIRECT_URL,
    });
    expect(verifiedAuthResponseWithJWT.idToken.jwt).toBeDefined();
    expect(verifiedAuthResponseWithJWT.idToken.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg');
  });

  it(
    'should succeed when calling with CheckLinkedDomain.IF_PRESENT',
    async () => {
      const rpMockEntity = {
        hexPrivateKey: '2bbd6a78be9ab2193bcf74aa6d39ab59c1d1e2f7e9ef899a38fb4d94d8aa90e2',
        did: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024',
        didKey: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024#controllerKey',
      };

      const opMockEntity = {
        hexPrivateKey: '73d24dd0fb69abdc12e7a99d8f9a970fdc8ad90598cc64cff35b584220ace0c8',
        did: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca',
        didKey: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca#controllerKey',
      };

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const verifyCallback = async (_args: IVerifyCallbackArgs): Promise<IVerifyCredentialResult> => ({ verified: true });
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const presentationVerificationCallback: PresentationVerificationCallback = async (_args) => ({ verified: true });

      const rp = RP.builder({ requestVersion: SupportedVersion.SIOPv2_ID1 })
        .withClientId(rpMockEntity.did)
        .withScope('test')
        .withResponseType([ResponseType.ID_TOKEN, ResponseType.VP_TOKEN])
        .withCheckLinkedDomain(CheckLinkedDomain.IF_PRESENT)
        .withPresentationVerification(presentationVerificationCallback)
        .withRevocationVerification(RevocationVerification.NEVER)
        .withWellknownDIDVerifyCallback(verifyCallback)
        .withRedirectUri(EXAMPLE_REDIRECT_URL)
        .withRequestBy(PassBy.VALUE)
        .withInternalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey, SigningAlgo.ES256K)
        .withAuthorizationEndpoint('www.myauthorizationendpoint.com')
        .addDidMethod('ethr')
        .withClientMetadata({
          client_id: WELL_KNOWN_OPENID_FEDERATION,
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
          requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          responseTypesSupported: [ResponseType.ID_TOKEN],
          vpFormatsSupported: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
          scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
          subjectTypesSupported: [SubjectType.PAIRWISE],
          subject_syntax_types_supported: ['did', 'did:ethr'],
          passBy: PassBy.VALUE,
          logo_uri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100328',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        })
        .withPresentationDefinition({ definition: getPresentationDefinition() }, [
          PropertyTarget.REQUEST_OBJECT,
          PropertyTarget.AUTHORIZATION_REQUEST,
        ])
        .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
        .build();
      const op = OP.builder()
        .withPresentationSignCallback(presentationSignCallback)
        .withCheckLinkedDomain(CheckLinkedDomain.NEVER)
        .withWellknownDIDVerifyCallback(verifyCallback)
        .withExpiresIn(1000)
        .addDidMethod('ethr')
        .withInternalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey, SigningAlgo.ES256K)
        .withRegistration({
          authorizationEndpoint: 'www.myauthorizationendpoint.com',
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
          issuer: ResponseIss.SELF_ISSUED_V2,
          requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          responseTypesSupported: [ResponseType.ID_TOKEN],
          vpFormats: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
          scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
          subjectTypesSupported: [SubjectType.PAIRWISE],
          subject_syntax_types_supported: [],
          passBy: PassBy.VALUE,
          logo_uri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100329',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        })
        .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
        .build();

      const requestURI = await rp.createAuthorizationRequestURI({
        correlationId: '1234',
        nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
        state: 'b32f0087fc9816eb813fd11f',
      });

      // Let's test the parsing
      const parsedAuthReqURI = await op.parseAuthorizationRequestURI(requestURI.encodedUri);
      expect(parsedAuthReqURI.authorizationRequestPayload).toBeDefined();
      expect(parsedAuthReqURI.requestObjectJwt).toBeDefined();
      // expect(parsedAuthReqURI.registration).toBeDefined();

      const verifiedAuthReqWithJWT = await op.verifyAuthorizationRequest(parsedAuthReqURI.requestObjectJwt);
      expect(verifiedAuthReqWithJWT.signer).toBeDefined();
      expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did);
      const pex = new PresentationExchange({ allDIDs: [HOLDER_DID], allVerifiableCredentials: getVCs() });
      const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(
        parsedAuthReqURI.authorizationRequestPayload
      );
      await pex.selectVerifiableCredentialsForSubmission(pd[0].definition);
      const verifiablePresentationResult = await pex.createVerifiablePresentation(pd[0].definition, getVCs(), presentationSignCallback, {});
      const authenticationResponseWithJWT = await op.createAuthorizationResponse(verifiedAuthReqWithJWT, {
        presentationExchange: {
          verifiablePresentations: [verifiablePresentationResult.verifiablePresentation],
          presentationSubmission: verifiablePresentationResult.presentationSubmission,
          vpTokenLocation: VPTokenLocation.AUTHORIZATION_RESPONSE,
          /*credentialsAndDefinitions: [
            {
              presentation: vp,
              format: VerifiablePresentationTypeFormat.LDP_VP,
              vpTokenLocation: VPTokenLocation.AUTHORIZATION_RESPONSE,
            },
          ],*/
        },
      });
      expect(authenticationResponseWithJWT.response.payload).toBeDefined();
      expect(authenticationResponseWithJWT.response.idToken).toBeDefined();

      const verifiedAuthResponseWithJWT = await rp.verifyAuthorizationResponse(authenticationResponseWithJWT.response.payload, {
        presentationDefinitions: [{ definition: pd[0].definition, location: pd[0].location }],
        // audience: EXAMPLE_REDIRECT_URL,
      });
      expect(verifiedAuthResponseWithJWT.idToken.jwt).toBeDefined();
      expect(verifiedAuthResponseWithJWT.idToken.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg');
    },
    UNIT_TEST_TIMEOUT
  );

  it('succeed when calling with RevocationVerification.ALWAYS with ldp_vp', async () => {
    const rpMockEntity = {
      hexPrivateKey: '2bbd6a78be9ab2193bcf74aa6d39ab59c1d1e2f7e9ef899a38fb4d94d8aa90e2',
      did: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024',
      didKey: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024#controllerKey',
    };

    const opMockEntity = {
      hexPrivateKey: '73d24dd0fb69abdc12e7a99d8f9a970fdc8ad90598cc64cff35b584220ace0c8',
      did: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca',
      didKey: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca#controllerKey',
    };

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const verifyCallback = async (_args: IVerifyCallbackArgs): Promise<IVerifyCredentialResult> => ({ verified: true });
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const presentationVerificationCallback: PresentationVerificationCallback = async (_args) => ({ verified: true });
    const rp = RP.builder({ requestVersion: SupportedVersion.SIOPv2_ID1 })
      .withClientId('test_client_id')
      .withScope('test')
      .withResponseType([ResponseType.VP_TOKEN, ResponseType.ID_TOKEN])
      .withRevocationVerification(RevocationVerification.ALWAYS)
      .withPresentationVerification(presentationVerificationCallback)
      .withWellknownDIDVerifyCallback(verifyCallback)
      .withCheckLinkedDomain(CheckLinkedDomain.NEVER)
      .withRevocationVerificationCallback(async () => {
        return { status: RevocationStatus.VALID };
      })
      .withRedirectUri(EXAMPLE_REDIRECT_URL)
      .withRequestBy(PassBy.VALUE)
      .withInternalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey, SigningAlgo.ES256K)
      .withAuthorizationEndpoint('www.myauthorizationendpoint.com')
      .addDidMethod('ion')
      .withClientMetadata({
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.ES256K],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.ES256K],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormatsSupported: {
          jwt_vc: { alg: [SigningAlgo.EDDSA] },
          jwt_vp: { alg: [SigningAlgo.EDDSA] },
          ldp_vc: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp_vp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
        },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did', 'did:ion'],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100330',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withPresentationDefinition({ definition: getPresentationDefinition() }, [PropertyTarget.REQUEST_OBJECT, PropertyTarget.AUTHORIZATION_REQUEST])
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      .build();

    const op = OP.builder()
      .withPresentationSignCallback(presentationSignCallback)
      .withExpiresIn(1000)
      .addDidMethod('ethr')
      .withInternalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey, SigningAlgo.ES256K)
      .withPresentationSignCallback(presentationSignCallback)
      .withCheckLinkedDomain(CheckLinkedDomain.NEVER)
      .withWellknownDIDVerifyCallback(verifyCallback)
      .withRegistration({
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.ES256K],
        issuer: ResponseIss.SELF_ISSUED_V2,
        requestObjectSigningAlgValuesSupported: [SigningAlgo.ES256K],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormats: {
          jwt_vc: { alg: [SigningAlgo.EDDSA] },
          jwt_vp: { alg: [SigningAlgo.EDDSA] },
          ldp_vc: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp_vp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
        },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: [],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100331',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      .build();

    const requestURI = await rp.createAuthorizationRequestURI({
      correlationId: '1234',
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      state: 'b32f0087fc9816eb813fd11f',
    });

    await checkSIOPSpecVersionSupported(requestURI.authorizationRequestPayload, op.verifyRequestOptions.supportedVersions);
    // Let's test the parsing
    const parsedAuthReqURI = await op.parseAuthorizationRequestURI(requestURI.encodedUri);
    expect(parsedAuthReqURI.authorizationRequestPayload).toBeDefined();
    expect(parsedAuthReqURI.requestObjectJwt).toBeDefined();
    // expect(parsedAuthReqURI.registration).toBeDefined();

    const verifiedAuthReqWithJWT = await op.verifyAuthorizationRequest(parsedAuthReqURI.requestObjectJwt); //, rp.authRequestOpts
    expect(verifiedAuthReqWithJWT.signer).toBeDefined();
    expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did);

    const pex = new PresentationExchange({ allDIDs: [HOLDER_DID], allVerifiableCredentials: getVCs() });
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(
      parsedAuthReqURI.authorizationRequestPayload
    );
    await pex.selectVerifiableCredentialsForSubmission(pd[0].definition);
    const verifiablePresentationResult = await pex.createVerifiablePresentation(pd[0].definition, getVCs(), presentationSignCallback, {});

    const authenticationResponseWithJWT = await op.createAuthorizationResponse(verifiedAuthReqWithJWT, {
      presentationExchange: {
        verifiablePresentations: [verifiablePresentationResult.verifiablePresentation],
        presentationSubmission: verifiablePresentationResult.presentationSubmission,
        vpTokenLocation: VPTokenLocation.AUTHORIZATION_RESPONSE,
        /*credentialsAndDefinitions: [
          {
            presentation: vp,
            format: VerifiablePresentationTypeFormat.LDP_VP,
            vpTokenLocation: VPTokenLocation.AUTHORIZATION_RESPONSE,
          },
        ],*/
      },
    });
    expect(authenticationResponseWithJWT.response.payload).toBeDefined();
    expect(authenticationResponseWithJWT.response.idToken).toBeDefined();

    const DID_CONFIGURATION = {
      '@context': 'https://identity.foundation/.well-known/did-configuration/v1',
      linked_dids: [
        'eyJhbGciOiJSUzI1NiIsImtpZCI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNI3o2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSJ9.eyJleHAiOjE3NjQ4NzkxMzksImlzcyI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwibmJmIjoxNjA3MTEyNzM5LCJzdWIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9pZGVudGl0eS5mb3VuZGF0aW9uLy53ZWxsLWtub3duL2RpZC1jb25maWd1cmF0aW9uL3YxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1rb1RIc2dOTnJieThKekNOUTFpUkx5VzVRUTZSOFh1dTZBQThpZ0dyTVZQVU0iLCJvcmlnaW4iOiJodHRwczovL2lkZW50aXR5LmZvdW5kYXRpb24ifSwiZXhwaXJhdGlvbkRhdGUiOiIyMDI1LTEyLTA0VDE0OjEyOjE5LTA2OjAwIiwiaXNzdWFuY2VEYXRlIjoiMjAyMC0xMi0wNFQxNDoxMjoxOS0wNjowMCIsImlzc3VlciI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkRvbWFpbkxpbmthZ2VDcmVkZW50aWFsIl19fQ.YZnpPMAW3GdaPXC2YKoJ7Igt1OaVZKq09XZBkptyhxTAyHTkX2Ewtew-JKHKQjyDyabY3HAy1LUPoIQX0jrU0J82pIYT3k2o7nNTdLbxlgb49FcDn4czntt5SbY0m1XwrMaKEvV0bHQsYPxNTqjYsyySccgPfmvN9IT8gRS-M9a6MZQxuB3oEMrVOQ5Vco0bvTODXAdCTHibAk1FlvKz0r1vO5QMhtW4OlRrVTI7ibquf9Nim_ch0KeMMThFjsBDKetuDF71nUcL5sf7PCFErvl8ZVw3UK4NkZ6iM-XIRsLL6rXP2SnDUVovcldhxd_pyKEYviMHBOgBdoNP6fOgRQ',
        'eyJhbGciOiJSUzI1NiIsImtpZCI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNI3o2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSJ9.eyJleHAiOjE3NjQ4NzkxMzksImlzcyI6ImRpZDprZXk6b3RoZXIiLCJuYmYiOjE2MDcxMTI3MzksInN1YiI6ImRpZDprZXk6b3RoZXIiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vaWRlbnRpdHkuZm91bmRhdGlvbi8ud2VsbC1rbm93bi9kaWQtY29uZmlndXJhdGlvbi92MSJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDprZXk6b3RoZXIiLCJvcmlnaW4iOiJodHRwczovL2lkZW50aXR5LmZvdW5kYXRpb24ifSwiZXhwaXJhdGlvbkRhdGUiOiIyMDI1LTEyLTA0VDE0OjEyOjE5LTA2OjAwIiwiaXNzdWFuY2VEYXRlIjoiMjAyMC0xMi0wNFQxNDoxMjoxOS0wNjowMCIsImlzc3VlciI6ImRpZDprZXk6b3RoZXIiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRG9tYWluTGlua2FnZUNyZWRlbnRpYWwiXX19.rRuc-ojuEgyq8p_tBYK7BayuiNTBeXNyAnC14Rnjs-jsnhae4_E1Q12W99K2NGCGBi5KjNsBcZmdNJPxejiKPrjjcB99poFCgTY8tuRzDjVo0lIeBwfx9qqjKHTRTUR8FGM_imlOpVfBF4AHYxjkHvZn6c9lYvatYcDpB2UfH4BNXkdSVrUXy_kYjpMpAdRtyCAnD_isN1YpEHBqBmnfuVUbYcQK5kk6eiokRFDtWruL1OEeJMYPqjuBSd2m-H54tSM84Oic_pg2zXDjjBlXNelat6MPNT2QxmkwJg7oyewQWX2Ot2yyhSp9WyAQWMlQIe2x84R0lADUmZ1TPQchNw',
      ],
    };
    nock('https://ldtest.sphereon.com').get('/.well-known/did-configuration.json').times(3).reply(200, DID_CONFIGURATION);
    const verifiedAuthResponseWithJWT = await rp.verifyAuthorizationResponse(authenticationResponseWithJWT.response.payload, {
      presentationDefinitions: [{ definition: pd[0].definition, location: pd[0].location }],
      // audience: EXAMPLE_REDIRECT_URL,
    });
    expect(verifiedAuthResponseWithJWT.idToken.jwt).toBeDefined();
    expect(verifiedAuthResponseWithJWT.idToken.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg');
  });

  it('should verify revocation ldp_vp with RevocationVerification.ALWAYS', async () => {
    const presentation = {
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://identity.foundation/presentation-exchange/submission/v1'],
      type: ['VerifiablePresentation', 'PresentationSubmission'],
      presentation_submission: {
        id: 'K7Zu3C6yJv3TGXYCB3B3n',
        definition_id: 'Insurance Plans',
        descriptor_map: [
          {
            id: 'Ontario Health Insurance Plan',
            format: 'ldp_vc',
            path: '$.verifiableCredential[0]',
          },
        ],
      },
      verifiableCredential: [
        {
          identifier: '83627465',
          name: 'Permanent Resident Card',
          type: ['PermanentResidentCard', 'VerifiableCredential'],
          id: 'https://issuer.oidp.uscis.gov/credentials/83627465dsdsdsd',
          credentialSubject: {
            birthCountry: 'Bahamas',
            id: 'did:example:b34ca6cd37bbf23',
            type: ['PermanentResident', 'Person'],
            gender: 'Female',
            familyName: 'SMITH',
            givenName: 'JANE',
            residentSince: '2015-01-01',
            lprNumber: '999-999-999',
            birthDate: '1958-07-17',
            commuterClassification: 'C1',
            lprCategory: 'C09',
            image: 'data:image/png;base64,iVBORw0KGgokJggg==',
          },
          expirationDate: '2029-12-03T12:19:52Z',
          description: 'Government of Example Permanent Resident Card.',
          issuanceDate: '2019-12-03T12:19:52Z',
          '@context': ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/2018/credentials/examples/v1'],
          issuer: {
            id: 'did:example:issuer',
          },
          proof: {
            type: 'BbsBlsSignatureProof2020',
            created: '2020-04-25',
            verificationMethod: 'did:example:489398593#test',
            proofPurpose: 'assertionMethod',
            proofValue:
              'kTTbA3pmDa6Qia/JkOnIXDLmoBz3vsi7L5t3DWySI/VLmBqleJ/Tbus5RoyiDERDBEh5rnACXlnOqJ/U8yFQFtcp/mBCc2FtKNPHae9jKIv1dm9K9QK1F3GI1AwyGoUfjLWrkGDObO1ouNAhpEd0+et+qiOf2j8p3MTTtRRx4Hgjcl0jXCq7C7R5/nLpgimHAAAAdAx4ouhMk7v9dXijCIMaG0deicn6fLoq3GcNHuH5X1j22LU/hDu7vvPnk/6JLkZ1xQAAAAIPd1tu598L/K3NSy0zOy6obaojEnaqc1R5Ih/6ZZgfEln2a6tuUp4wePExI1DGHqwj3j2lKg31a/6bSs7SMecHBQdgIYHnBmCYGNQnu/LZ9TFV56tBXY6YOWZgFzgLDrApnrFpixEACM9rwrJ5ORtxAAAAAgE4gUIIC9aHyJNa5TBklMOh6lvQkMVLXa/vEl+3NCLXblxjgpM7UEMqBkE9/QcoD3Tgmy+z0hN+4eky1RnJsEg=',
            nonce: '6i3dTz5yFfWJ8zgsamuyZa4yAHPm75tUOOXddR6krCvCYk77sbCOuEVcdBCDd/l6tIY=',
          },
        },
      ],
      proof: {
        type: 'BbsBlsSignatureProof2020',
        created: '2020-04-25',
        verificationMethod: 'did:example:489398593#test',
        proofPurpose: 'assertionMethod',
        proofValue:
          'kTTbA3pmDa6Qia/JkOnIXDLmoBz3vsi7L5t3DWySI/VLmBqleJ/Tbus5RoyiDERDBEh5rnACXlnOqJ/U8yFQFtcp/mBCc2FtKNPHae9jKIv1dm9K9QK1F3GI1AwyGoUfjLWrkGDObO1ouNAhpEd0+et+qiOf2j8p3MTTtRRx4Hgjcl0jXCq7C7R5/nLpgimHAAAAdAx4ouhMk7v9dXijCIMaG0deicn6fLoq3GcNHuH5X1j22LU/hDu7vvPnk/6JLkZ1xQAAAAIPd1tu598L/K3NSy0zOy6obaojEnaqc1R5Ih/6ZZgfEln2a6tuUp4wePExI1DGHqwj3j2lKg31a/6bSs7SMecHBQdgIYHnBmCYGNQnu/LZ9TFV56tBXY6YOWZgFzgLDrApnrFpixEACM9rwrJ5ORtxAAAAAgE4gUIIC9aHyJNa5TBklMOh6lvQkMVLXa/vEl+3NCLXblxjgpM7UEMqBkE9/QcoD3Tgmy+z0hN+4eky1RnJsEg=',
        nonce: '6i3dTz5yFfWJ8zgsamuyZa4yAHPm75tUOOXddR6krCvCYk77sbCOuEVcdBCDd/l6tIY=',
      },
    };

    await expect(
      verifyRevocation(
        CredentialMapper.toWrappedVerifiablePresentation(presentation),
        async () => {
          return { status: RevocationStatus.VALID };
        },
        RevocationVerification.ALWAYS
      )
    ).resolves.not.toThrow();
  });

  it('should verify revocation ldp_vp with RevocationVerification.IF_PRESENT', async () => {
    const presentation = {
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://identity.foundation/presentation-exchange/submission/v1'],
      type: ['VerifiablePresentation', 'PresentationSubmission'],
      presentation_submission: {
        id: 'K7Zu3C6yJv3TGXYCB3B3n',
        definition_id: 'Insurance Plans',
        descriptor_map: [
          {
            id: 'Ontario Health Insurance Plan',
            format: 'ldp_vc',
            path: '$.verifiableCredential[0]',
          },
        ],
      },
      verifiableCredential: [
        {
          identifier: '83627465',
          name: 'Permanent Resident Card',
          type: ['PermanentResidentCard', 'VerifiableCredential'],
          id: 'https://issuer.oidp.uscis.gov/credentials/83627465dsdsdsd',
          credentialSubject: {
            birthCountry: 'Bahamas',
            id: 'did:example:b34ca6cd37bbf23',
            type: ['PermanentResident', 'Person'],
            gender: 'Female',
            familyName: 'SMITH',
            givenName: 'JANE',
            residentSince: '2015-01-01',
            lprNumber: '999-999-999',
            birthDate: '1958-07-17',
            commuterClassification: 'C1',
            lprCategory: 'C09',
            image: 'data:image/png;base64,iVBORw0KGgokJggg==',
          },
          credentialStatus: {
            id: 'https://example.com/credentials/status/3#94567',
            type: 'StatusList2021Entry',
            statusPurpose: 'revocation',
            statusListIndex: '94567',
            statusListCredential: 'https://example.com/credentials/status/3',
          },
          expirationDate: '2029-12-03T12:19:52Z',
          description: 'Government of Example Permanent Resident Card.',
          issuanceDate: '2019-12-03T12:19:52Z',
          '@context': ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/2018/credentials/examples/v1'],
          issuer: {
            id: 'did:example:issuer',
          },
          proof: {
            type: 'BbsBlsSignatureProof2020',
            created: '2020-04-25',
            verificationMethod: 'did:example:489398593#test',
            proofPurpose: 'assertionMethod',
            proofValue:
              'kTTbA3pmDa6Qia/JkOnIXDLmoBz3vsi7L5t3DWySI/VLmBqleJ/Tbus5RoyiDERDBEh5rnACXlnOqJ/U8yFQFtcp/mBCc2FtKNPHae9jKIv1dm9K9QK1F3GI1AwyGoUfjLWrkGDObO1ouNAhpEd0+et+qiOf2j8p3MTTtRRx4Hgjcl0jXCq7C7R5/nLpgimHAAAAdAx4ouhMk7v9dXijCIMaG0deicn6fLoq3GcNHuH5X1j22LU/hDu7vvPnk/6JLkZ1xQAAAAIPd1tu598L/K3NSy0zOy6obaojEnaqc1R5Ih/6ZZgfEln2a6tuUp4wePExI1DGHqwj3j2lKg31a/6bSs7SMecHBQdgIYHnBmCYGNQnu/LZ9TFV56tBXY6YOWZgFzgLDrApnrFpixEACM9rwrJ5ORtxAAAAAgE4gUIIC9aHyJNa5TBklMOh6lvQkMVLXa/vEl+3NCLXblxjgpM7UEMqBkE9/QcoD3Tgmy+z0hN+4eky1RnJsEg=',
            nonce: '6i3dTz5yFfWJ8zgsamuyZa4yAHPm75tUOOXddR6krCvCYk77sbCOuEVcdBCDd/l6tIY=',
          },
        },
      ],
      proof: {
        type: 'BbsBlsSignatureProof2020',
        created: '2020-04-25',
        verificationMethod: 'did:example:489398593#test',
        proofPurpose: 'assertionMethod',
        proofValue:
          'kTTbA3pmDa6Qia/JkOnIXDLmoBz3vsi7L5t3DWySI/VLmBqleJ/Tbus5RoyiDERDBEh5rnACXlnOqJ/U8yFQFtcp/mBCc2FtKNPHae9jKIv1dm9K9QK1F3GI1AwyGoUfjLWrkGDObO1ouNAhpEd0+et+qiOf2j8p3MTTtRRx4Hgjcl0jXCq7C7R5/nLpgimHAAAAdAx4ouhMk7v9dXijCIMaG0deicn6fLoq3GcNHuH5X1j22LU/hDu7vvPnk/6JLkZ1xQAAAAIPd1tu598L/K3NSy0zOy6obaojEnaqc1R5Ih/6ZZgfEln2a6tuUp4wePExI1DGHqwj3j2lKg31a/6bSs7SMecHBQdgIYHnBmCYGNQnu/LZ9TFV56tBXY6YOWZgFzgLDrApnrFpixEACM9rwrJ5ORtxAAAAAgE4gUIIC9aHyJNa5TBklMOh6lvQkMVLXa/vEl+3NCLXblxjgpM7UEMqBkE9/QcoD3Tgmy+z0hN+4eky1RnJsEg=',
        nonce: '6i3dTz5yFfWJ8zgsamuyZa4yAHPm75tUOOXddR6krCvCYk77sbCOuEVcdBCDd/l6tIY=',
      },
    };

    await expect(
      verifyRevocation(
        CredentialMapper.toWrappedVerifiablePresentation(presentation),
        async () => {
          return { status: RevocationStatus.VALID };
        },
        RevocationVerification.ALWAYS
      )
    ).resolves.not.toThrow();
  });

  it('should verify revocation ldp_vp with location id_token', async () => {
    const rpMockEntity = {
      hexPrivateKey: '2bbd6a78be9ab2193bcf74aa6d39ab59c1d1e2f7e9ef899a38fb4d94d8aa90e2',
      did: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024',
      didKey: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024#controllerKey',
    };

    const opMockEntity = {
      hexPrivateKey: '73d24dd0fb69abdc12e7a99d8f9a970fdc8ad90598cc64cff35b584220ace0c8',
      did: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca',
      didKey: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca#controllerKey',
    };

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const verifyCallback = async (_args: IVerifyCallbackArgs): Promise<IVerifyCredentialResult> => ({ verified: true });
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const presentationVerificationCallback: PresentationVerificationCallback = async (_args) => ({ verified: true });

    const rp = RP.builder({ requestVersion: SupportedVersion.SIOPv2_ID1 })
      .withClientId('test_client_id')
      .withScope('test')
      .withResponseType(ResponseType.ID_TOKEN)
      .withCheckLinkedDomain(CheckLinkedDomain.NEVER)
      .withPresentationVerification(presentationVerificationCallback)
      .withWellknownDIDVerifyCallback(verifyCallback)
      .withRevocationVerification(RevocationVerification.NEVER)
      .withRedirectUri(EXAMPLE_REDIRECT_URL)
      .withRequestBy(PassBy.VALUE)
      .withInternalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey, SigningAlgo.ES256K)
      .withAuthorizationEndpoint('www.myauthorizationendpoint.com')
      .withClientMetadata({
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.ES256K],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.ES256K],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormatsSupported: {
          jwt_vc: { alg: [SigningAlgo.EDDSA] },
          ldp_vc: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp_vp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
        },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did', 'did:ion'],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
      })
      .withPresentationDefinition({ definition: getPresentationDefinition() }, [PropertyTarget.REQUEST_OBJECT, PropertyTarget.AUTHORIZATION_REQUEST])
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      .build();
    const op = OP.builder()
      .withPresentationSignCallback(presentationSignCallback)
      .withWellknownDIDVerifyCallback(verifyCallback)
      .withExpiresIn(1000)
      .withInternalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey, SigningAlgo.ES256K)
      .withCheckLinkedDomain(CheckLinkedDomain.NEVER)
      .withRegistration({
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.ES256K],
        issuer: ResponseIss.SELF_ISSUED_V2,
        requestObjectSigningAlgValuesSupported: [SigningAlgo.ES256K],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormats: {
          jwt_vc: { alg: [SigningAlgo.EDDSA] },
          ldp_vc: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp_vp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
        },
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did:ethr'],
        passBy: PassBy.VALUE,
      })
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      .build();

    const requestURI = await rp.createAuthorizationRequestURI({
      correlationId: '1234',
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      state: 'b32f0087fc9816eb813fd11f',
    });

    // Let's test the parsing
    const parsedAuthReqURI = await op.parseAuthorizationRequestURI(requestURI.encodedUri);
    expect(parsedAuthReqURI.authorizationRequestPayload).toBeDefined();
    expect(parsedAuthReqURI.requestObjectJwt).toBeDefined();
    // expect(parsedAuthReqURI.registration).toBeDefined();

    const verifiedAuthReqWithJWT = await op.verifyAuthorizationRequest(parsedAuthReqURI.requestObjectJwt);
    expect(verifiedAuthReqWithJWT.signer).toBeDefined();
    expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did);
    const pex = new PresentationExchange({ allDIDs: [HOLDER_DID], allVerifiableCredentials: getVCs() });
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(
      parsedAuthReqURI.authorizationRequestPayload
    );
    await pex.selectVerifiableCredentialsForSubmission(pd[0].definition);
    const verifiablePresentationResult = await pex.createVerifiablePresentation(pd[0].definition, getVCs(), presentationSignCallback, {});
    const authenticationResponseWithJWT = await op.createAuthorizationResponse(verifiedAuthReqWithJWT, {
      presentationExchange: {
        verifiablePresentations: [verifiablePresentationResult.verifiablePresentation],
        presentationSubmission: verifiablePresentationResult.presentationSubmission,
        vpTokenLocation: VPTokenLocation.ID_TOKEN,
        /*credentialsAndDefinitions: [
          {
            presentation: vp,
            format: VerifiablePresentationTypeFormat.LDP_VP,
            vpTokenLocation: VPTokenLocation.ID_TOKEN
          }
        ]*/
      },
    });
    expect(authenticationResponseWithJWT.response.payload).toBeDefined();
    expect(authenticationResponseWithJWT.response.idToken).toBeDefined();

    const verifiedAuthResponseWithJWT = await rp.verifyAuthorizationResponse(authenticationResponseWithJWT.response.payload, {
      presentationDefinitions: [{ definition: pd[0].definition, location: pd[0].location }],
      audience: 'test_client_id',
    });
    expect(verifiedAuthResponseWithJWT.idToken.jwt).toBeDefined();
    expect(verifiedAuthResponseWithJWT.idToken.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg');
  });

  it('succeed with nonce verification with ldp_vp', async () => {
    const rpMockEntity = {
      hexPrivateKey: '2bbd6a78be9ab2193bcf74aa6d39ab59c1d1e2f7e9ef899a38fb4d94d8aa90e2',
      did: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024',
      didKey: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024#controllerKey',
    };

    const opMockEntity = {
      hexPrivateKey: '73d24dd0fb69abdc12e7a99d8f9a970fdc8ad90598cc64cff35b584220ace0c8',
      did: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca',
      didKey: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca#controllerKey',
    };

    const rp = RP.builder({ requestVersion: SupportedVersion.SIOPv2_ID1 })
      .withClientId('test_client_id')
      .withScope('test')
      .withResponseType(ResponseType.ID_TOKEN)
      .withRevocationVerification(RevocationVerification.NEVER)
      .withPresentationVerification(presentationVerificationCallback)
      .withCheckLinkedDomain(CheckLinkedDomain.NEVER)
      .withRedirectUri(EXAMPLE_REDIRECT_URL)
      .withRequestBy(PassBy.VALUE)
      .withInternalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey, SigningAlgo.ES256K)
      .withAuthorizationEndpoint('www.myauthorizationendpoint.com')
      .addDidMethod('ion')
      .withClientMetadata({
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.ES256K],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.ES256K],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormatsSupported: {
          jwt_vc: { alg: [SigningAlgo.EDDSA] },
          jwt_vp: { alg: [SigningAlgo.EDDSA] },
          ldp_vc: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp_vp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
        },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did', 'did:ion'],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100330',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withPresentationDefinition({ definition: getPresentationDefinition() }, [PropertyTarget.REQUEST_OBJECT, PropertyTarget.AUTHORIZATION_REQUEST])
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      .build();

    const op = OP.builder()
      .withPresentationSignCallback(presentationSignCallback)
      .withExpiresIn(1000)
      .addDidMethod('ethr')
      .withInternalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey, SigningAlgo.ES256K)
      .withPresentationSignCallback(presentationSignCallback)
      .withCheckLinkedDomain(CheckLinkedDomain.NEVER)
      .withWellknownDIDVerifyCallback(verifyCallback)
      .withRegistration({
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.ES256K],
        issuer: ResponseIss.SELF_ISSUED_V2,
        requestObjectSigningAlgValuesSupported: [SigningAlgo.ES256K],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormats: {
          jwt_vc: { alg: [SigningAlgo.EDDSA] },
          jwt_vp: { alg: [SigningAlgo.EDDSA] },
          ldp_vc: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp_vp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
        },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: [],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100331',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      .build();

    const requestURI = await rp.createAuthorizationRequestURI({
      correlationId: '1234',
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      state: 'b32f0087fc9816eb813fd11f',
    });

    const parsedAuthReqURI = await op.parseAuthorizationRequestURI(requestURI.encodedUri);
    const verifiedAuthReqWithJWT = await op.verifyAuthorizationRequest(parsedAuthReqURI.requestObjectJwt);
    const pex = new PresentationExchange({ allDIDs: [HOLDER_DID], allVerifiableCredentials: getVCs() });
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(
      parsedAuthReqURI.authorizationRequestPayload
    );
    await pex.selectVerifiableCredentialsForSubmission(pd[0].definition);
    const verifiablePresentationResult = await pex.createVerifiablePresentation(pd[0].definition, getVCs(), presentationSignCallback, {});

    const authenticationResponseWithJWT = await op.createAuthorizationResponse(verifiedAuthReqWithJWT, {
      presentationExchange: {
        verifiablePresentations: [verifiablePresentationResult.verifiablePresentation],
        presentationSubmission: verifiablePresentationResult.presentationSubmission,
        vpTokenLocation: VPTokenLocation.ID_TOKEN,
        /*credentialsAndDefinitions: [
          {
            presentation: vp,
            format: VerifiablePresentationTypeFormat.LDP_VP,
            vpTokenLocation: VPTokenLocation.AUTHORIZATION_RESPONSE
          }
        ]*/
      },
    });

    const DID_CONFIGURATION = {
      '@context': 'https://identity.foundation/.well-known/did-configuration/v1',
      linked_dids: [
        'eyJhbGciOiJSUzI1NiIsImtpZCI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNI3o2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSJ9.eyJleHAiOjE3NjQ4NzkxMzksImlzcyI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwibmJmIjoxNjA3MTEyNzM5LCJzdWIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9pZGVudGl0eS5mb3VuZGF0aW9uLy53ZWxsLWtub3duL2RpZC1jb25maWd1cmF0aW9uL3YxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1rb1RIc2dOTnJieThKekNOUTFpUkx5VzVRUTZSOFh1dTZBQThpZ0dyTVZQVU0iLCJvcmlnaW4iOiJodHRwczovL2lkZW50aXR5LmZvdW5kYXRpb24ifSwiZXhwaXJhdGlvbkRhdGUiOiIyMDI1LTEyLTA0VDE0OjEyOjE5LTA2OjAwIiwiaXNzdWFuY2VEYXRlIjoiMjAyMC0xMi0wNFQxNDoxMjoxOS0wNjowMCIsImlzc3VlciI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkRvbWFpbkxpbmthZ2VDcmVkZW50aWFsIl19fQ.YZnpPMAW3GdaPXC2YKoJ7Igt1OaVZKq09XZBkptyhxTAyHTkX2Ewtew-JKHKQjyDyabY3HAy1LUPoIQX0jrU0J82pIYT3k2o7nNTdLbxlgb49FcDn4czntt5SbY0m1XwrMaKEvV0bHQsYPxNTqjYsyySccgPfmvN9IT8gRS-M9a6MZQxuB3oEMrVOQ5Vco0bvTODXAdCTHibAk1FlvKz0r1vO5QMhtW4OlRrVTI7ibquf9Nim_ch0KeMMThFjsBDKetuDF71nUcL5sf7PCFErvl8ZVw3UK4NkZ6iM-XIRsLL6rXP2SnDUVovcldhxd_pyKEYviMHBOgBdoNP6fOgRQ',
        'eyJhbGciOiJSUzI1NiIsImtpZCI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNI3o2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSJ9.eyJleHAiOjE3NjQ4NzkxMzksImlzcyI6ImRpZDprZXk6b3RoZXIiLCJuYmYiOjE2MDcxMTI3MzksInN1YiI6ImRpZDprZXk6b3RoZXIiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vaWRlbnRpdHkuZm91bmRhdGlvbi8ud2VsbC1rbm93bi9kaWQtY29uZmlndXJhdGlvbi92MSJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDprZXk6b3RoZXIiLCJvcmlnaW4iOiJodHRwczovL2lkZW50aXR5LmZvdW5kYXRpb24ifSwiZXhwaXJhdGlvbkRhdGUiOiIyMDI1LTEyLTA0VDE0OjEyOjE5LTA2OjAwIiwiaXNzdWFuY2VEYXRlIjoiMjAyMC0xMi0wNFQxNDoxMjoxOS0wNjowMCIsImlzc3VlciI6ImRpZDprZXk6b3RoZXIiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRG9tYWluTGlua2FnZUNyZWRlbnRpYWwiXX19.rRuc-ojuEgyq8p_tBYK7BayuiNTBeXNyAnC14Rnjs-jsnhae4_E1Q12W99K2NGCGBi5KjNsBcZmdNJPxejiKPrjjcB99poFCgTY8tuRzDjVo0lIeBwfx9qqjKHTRTUR8FGM_imlOpVfBF4AHYxjkHvZn6c9lYvatYcDpB2UfH4BNXkdSVrUXy_kYjpMpAdRtyCAnD_isN1YpEHBqBmnfuVUbYcQK5kk6eiokRFDtWruL1OEeJMYPqjuBSd2m-H54tSM84Oic_pg2zXDjjBlXNelat6MPNT2QxmkwJg7oyewQWX2Ot2yyhSp9WyAQWMlQIe2x84R0lADUmZ1TPQchNw',
      ],
    };
    nock('https://ldtest.sphereon.com').get('/.well-known/did-configuration.json').times(3).reply(200, DID_CONFIGURATION);
    const verifiedAuthResponseWithJWT = await rp.verifyAuthorizationResponse(authenticationResponseWithJWT.response.payload, {
      presentationDefinitions: [{ definition: pd[0].definition, location: pd[0].location }],
      audience: 'test_client_id',
    });
    expect(verifiedAuthResponseWithJWT.idToken.jwt).toBeDefined();
    expect(verifiedAuthResponseWithJWT.idToken.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg');
  });

  it('should register authorization request on create', async () => {
    const rpMockEntity = {
      hexPrivateKey: '2bbd6a78be9ab2193bcf74aa6d39ab59c1d1e2f7e9ef899a38fb4d94d8aa90e2',
      did: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024',
      didKey: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024#controllerKey',
    };

    const eventEmitter = new EventEmitter();
    const replayRegistry = new InMemoryRPSessionManager(eventEmitter);
    const rp = RP.builder({ requestVersion: SupportedVersion.SIOPv2_ID1 })
      .withClientId('test_client_id')
      .withScope('test')
      .withResponseType(ResponseType.ID_TOKEN)
      .withRevocationVerification(RevocationVerification.NEVER)
      .withPresentationVerification(presentationVerificationCallback)
      .withCheckLinkedDomain(CheckLinkedDomain.NEVER)
      .withRedirectUri(EXAMPLE_REDIRECT_URL)
      .withRequestBy(PassBy.VALUE)
      .withInternalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey, SigningAlgo.ES256K)
      .withAuthorizationEndpoint('www.myauthorizationendpoint.com')
      .addDidMethod('ion')
      .withClientMetadata({
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.ES256K],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.ES256K],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormatsSupported: {
          jwt_vc: { alg: [SigningAlgo.EDDSA] },
          jwt_vp: { alg: [SigningAlgo.EDDSA] },
          ldp_vc: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp_vp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
        },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did', 'did:ion'],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100330',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withPresentationDefinition({ definition: getPresentationDefinition() })
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      .withSessionManager(replayRegistry)
      .withEventEmitter(eventEmitter)
      .build();

    await rp.createAuthorizationRequest({
      correlationId: '1234',
      nonce: { propertyValue: 'bcceb347-1374-49b8-ace0-b868162c122d', targets: PropertyTarget.REQUEST_OBJECT },
      state: { propertyValue: '8006b5fb-6e3b-42d1-a2be-55ed2a08073d', targets: PropertyTarget.REQUEST_OBJECT },
      claims: {
        propertyValue: {
          vp_token: {
            presentation_definition: {
              input_descriptors: [
                {
                  schema: [
                    {
                      uri: 'https://VerifiedEmployee',
                    },
                  ],
                  purpose: 'We need to verify that you have a valid VerifiedEmployee Verifiable Credential.',
                  name: 'VerifiedEmployeeVC',
                  id: 'VerifiedEmployeeVC',
                },
              ],
              id: '8006b5fb-6e3b-42d1-a2be-55ed2a08073d',
            },
          },
        },
        targets: PropertyTarget.REQUEST_OBJECT,
      },
    });

    const state = await replayRegistry.getRequestStateByCorrelationId('1234', true);
    expect(state.status).toBe('created');
  });

  it('should register authorization request on create with uri', async () => {
    const rpMockEntity = {
      hexPrivateKey: '2bbd6a78be9ab2193bcf74aa6d39ab59c1d1e2f7e9ef899a38fb4d94d8aa90e2',
      did: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024',
      didKey: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024#controllerKey',
    };
    const eventEmitter = new EventEmitter();
    const replayRegistry = new InMemoryRPSessionManager(eventEmitter);

    const rp = RP.builder({ requestVersion: SupportedVersion.SIOPv2_ID1 })
      .withClientId(WELL_KNOWN_OPENID_FEDERATION)
      .withScope('test')
      .withResponseType(ResponseType.ID_TOKEN)
      .withRedirectUri(EXAMPLE_REDIRECT_URL)
      .withPresentationVerification(presentationVerificationCallback)
      .withWellknownDIDVerifyCallback(verifyCallback)
      .withRevocationVerification(RevocationVerification.NEVER)
      .withRequestBy(PassBy.REFERENCE, EXAMPLE_REFERENCE_URL)
      .withIssuer(ResponseIss.SELF_ISSUED_V2)
      .withInternalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, `${rpMockEntity.did}#controller`, SigningAlgo.ES256K)
      .addDidMethod('ethr')
      .withClientMetadata({
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormatsSupported: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did', 'did:ethr'],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100317',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withSupportedVersions([SupportedVersion.SIOPv2_ID1])
      .withSessionManager(replayRegistry)
      .withEventEmitter(eventEmitter)
      .build();

    await rp.createAuthorizationRequestURI({
      correlationId: '1234',
      nonce: { propertyValue: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg' },
      state: { propertyValue: 'b32f0087fc9816eb813fd11f' },
    });

    const state = await replayRegistry.getRequestStateByCorrelationId('1234');
    expect(state.status).toBe('created');
  });

  it('should register authorization response on successful verification', async () => {
    await nock.cleanAll();
    const rpMockEntity = {
      hexPrivateKey: '2bbd6a78be9ab2193bcf74aa6d39ab59c1d1e2f7e9ef899a38fb4d94d8aa90e2',
      did: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024',
      didKey: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024#controllerKey',
    };
    const opMockEntity = {
      hexPrivateKey: '73d24dd0fb69abdc12e7a99d8f9a970fdc8ad90598cc64cff35b584220ace0c8',
      did: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca',
      didKey: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca#controllerKey',
    };

    const eventEmitter = new EventEmitter();
    const replayRegistry = new InMemoryRPSessionManager(eventEmitter);

    const rp = RP.builder({ requestVersion: SupportedVersion.SIOPv2_ID1 })
      .withClientId(rpMockEntity.did)
      .withScope('test')
      .withResponseType(ResponseType.ID_TOKEN)
      .withRedirectUri(EXAMPLE_REDIRECT_URL)
      .withPresentationVerification(presentationVerificationCallback)
      .withWellknownDIDVerifyCallback(verifyCallback)
      .withRevocationVerification(RevocationVerification.NEVER)
      .withRequestBy(PassBy.REFERENCE, EXAMPLE_REFERENCE_URL)
      .withIssuer(ResponseIss.SELF_ISSUED_V2)
      .withInternalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, `${rpMockEntity.didKey}`, SigningAlgo.ES256K)
      .addDidMethod('ethr')
      .withClientMetadata({
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormatsSupported: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did', 'did:ethr'],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100317',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withSupportedVersions([SupportedVersion.SIOPv2_ID1])
      .withEventEmitter(eventEmitter)
      .withSessionManager(replayRegistry)
      .build();
    const op = OP.builder()
      .withPresentationSignCallback(presentationSignCallback)
      .withExpiresIn(1000)
      .withWellknownDIDVerifyCallback(verifyCallback)
      .withIssuer(ResponseIss.SELF_ISSUED_V2)
      .withInternalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, `${opMockEntity.didKey}`, SigningAlgo.ES256K)
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      //FIXME: Move payload options to seperate property
      .withRegistration({
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        issuer: ResponseIss.SELF_ISSUED_V2,
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormats: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did:ethr'],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100318',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      .build();
    const requestURI = await rp.createAuthorizationRequestURI({
      correlationId: '12345',
      nonce: { propertyValue: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg' },
      state: { propertyValue: 'b32f0087fc9816eb813fd11f1' },
    });
    const reqStateCreated = await replayRegistry.getRequestStateByState('b32f0087fc9816eb813fd11f1', true);
    expect(reqStateCreated.status).toBe('created');
    nock('https://rp.acme.com').get('/siop/jwts').times(3).reply(200, requestURI.requestObjectJwt);
    const verifiedRequest = await op.verifyAuthorizationRequest(requestURI.encodedUri);
    const authenticationResponseWithJWT = await op.createAuthorizationResponse(verifiedRequest);
    nock(EXAMPLE_REDIRECT_URL).post(/.*/).times(3).reply(200, { result: 'ok' });
    await op.submitAuthorizationResponse(authenticationResponseWithJWT);
    await rp.verifyAuthorizationResponse(authenticationResponseWithJWT.response.payload, {
      // audience: EXAMPLE_REDIRECT_URL,
    });
    const reqStateAfterResponse = await replayRegistry.getRequestStateByState('incorrect', false);
    expect(reqStateAfterResponse).toBeUndefined();

    const resStateAfterResponse = await replayRegistry.getResponseStateByState('b32f0087fc9816eb813fd11f1', true);
    expect(resStateAfterResponse.status).toBe('verified');
  });

  it('should set error status on failed authorization response verification', async () => {
    const rpMockEntity = {
      hexPrivateKey: '2bbd6a78be9ab2193bcf74aa6d39ab59c1d1e2f7e9ef899a38fb4d94d8aa90e2',
      did: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024',
      didKey: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024#controllerKey',
    };
    const opMockEntity = await mockedGetEnterpriseAuthToken('ACME OP');
    const eventEmitter = new EventEmitter();
    const replayRegistry = new InMemoryRPSessionManager(eventEmitter);

    const rp = RP.builder({ requestVersion: SupportedVersion.SIOPv2_ID1 })
      .withClientId(rpMockEntity.did)
      .withScope('test')
      .withResponseType(ResponseType.ID_TOKEN)
      .withRedirectUri(EXAMPLE_REDIRECT_URL)
      .withPresentationVerification(presentationVerificationCallback)
      .withWellknownDIDVerifyCallback(verifyCallback)
      .withRevocationVerification(RevocationVerification.NEVER)
      .withRequestBy(PassBy.REFERENCE, EXAMPLE_REFERENCE_URL)
      .withIssuer(ResponseIss.SELF_ISSUED_V2)
      .withInternalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, `${rpMockEntity.did}#controller`, SigningAlgo.ES256K)
      .addDidMethod('ethr')
      .withClientMetadata({
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormatsSupported: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did', 'did:ethr'],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100317',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withSupportedVersions([SupportedVersion.SIOPv2_ID1])
      .withSessionManager(replayRegistry)
      .withEventEmitter(eventEmitter)
      .build();
    const op = OP.builder()
      .withPresentationSignCallback(presentationSignCallback)
      .withExpiresIn(1000)
      .withWellknownDIDVerifyCallback(verifyCallback)
      .withIssuer(ResponseIss.SELF_ISSUED_V2)
      .withInternalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, `${opMockEntity.did}#controller`, SigningAlgo.ES256K)
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      //FIXME: Move payload options to seperate property
      .withRegistration({
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        issuer: ResponseIss.SELF_ISSUED_V2,
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormats: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did:ethr'],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100318',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      .build();
    const requestURI = await rp.createAuthorizationRequestURI({
      correlationId: '1234',
      nonce: { propertyValue: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg' },
      state: { propertyValue: 'b32f0087fc9816eb813fd11f' },
    });
    const state = await replayRegistry.getRequestStateByCorrelationId('1234', true);
    expect(state.status).toBe('created');

    nock('https://rp.acme.com').get('/siop/jwts').times(3).reply(200, requestURI.requestObjectJwt);
    const verifiedRequest = await op.verifyAuthorizationRequest(requestURI.encodedUri);
    const authenticationResponseWithJWT = await op.createAuthorizationResponse(verifiedRequest);
    nock(EXAMPLE_REDIRECT_URL).post(/.*/).reply(200, { result: 'ok' });
    await op.submitAuthorizationResponse(authenticationResponseWithJWT);
    authenticationResponseWithJWT.response.payload.state = 'wrong_value';
    await rp.verifyAuthorizationResponse(authenticationResponseWithJWT.response.payload, { correlationId: '1234' }).catch(() => {
      //swallow this exception;
    });
    const reqState = await replayRegistry.getRequestStateByCorrelationId('1234', true);
    expect(reqState.status).toBe('created');

    const resState = await replayRegistry.getResponseStateByCorrelationId('1234', true);
    expect(resState.status).toBe('error');
  });
});
