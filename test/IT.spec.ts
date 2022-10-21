import { IPresentationDefinition } from '@sphereon/pex';
import { IProofType, IVerifiableCredential, IVerifiablePresentation } from '@sphereon/ssi-types';
import { IVerifyCallbackArgs, IVerifyCredentialResult, VerifyCallback, WDCErrors } from '@sphereon/wellknown-dids-client';
import nock from 'nock';

import {
  CheckLinkedDomain,
  KeyAlgo,
  OP,
  PassBy,
  PresentationDefinitionWithLocation,
  PresentationExchange,
  PresentationLocation,
  PresentationSignCallback,
  PresentationVerificationCallback,
  ResponseIss,
  ResponseType,
  RevocationStatus,
  RevocationVerification,
  RP,
  Scope,
  SigningAlgo,
  SubjectType,
  VerifiablePresentationTypeFormat,
  VerificationMode,
  verifyRevocation,
} from '../src/main';

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

const EXAMPLE_REDIRECT_URL = 'https://acme.com/hello';
const EXAMPLE_REFERENCE_URL = 'https://rp.acme.com/siop/jwts';

const HOLDER_DID = 'did:example:ebfeb1f712ebc6f1c276e12ec21';

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
      type: ['PermanentResidentCard', 'verifiableCredential'],
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

      const rp = RP.builder()
        .addClientId('test_client_id')
        .addScope('test')
        .addResponseType('id_token')
        .redirect(EXAMPLE_REDIRECT_URL)
        .withPresentationVerification(presentationVerificationCallback)
        .addVerifyCallback(verifyCallback)
        .withRevocationVerification(RevocationVerification.NEVER)
        .requestBy(PassBy.REFERENCE, EXAMPLE_REFERENCE_URL)
        .addIssuer(ResponseIss.SELF_ISSUED_V2)
        .internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, `${rpMockEntity.did}#controller`)
        .addDidMethod('ethr')
        .registrationBy({
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
          requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          responseTypesSupported: [ResponseType.ID_TOKEN],
          vpFormatsSupported: { jwt_vc: { alg: [KeyAlgo.EDDSA] } },
          scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
          subjectTypesSupported: [SubjectType.PAIRWISE],
          subjectSyntaxTypesSupported: ['did', 'did:ethr'],
          registrationBy: { type: PassBy.VALUE },
          logoUri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100317',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        })
        .build();
      const op = OP.builder()
        .withPresentationSignCallback(presentationSignCallback)
        .withExpiresIn(1000)
        .addVerifyCallback(verifyCallback)
        .addIssuer(ResponseIss.SELF_ISSUED_V2)
        .internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, `${opMockEntity.did}#controller`)
        .registrationBy({
          authorizationEndpoint: 'www.myauthorizationendpoint.com',
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
          issuer: ResponseIss.SELF_ISSUED_V2,
          requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          responseTypesSupported: [ResponseType.ID_TOKEN],
          vpFormats: { jwt_vc: { alg: [KeyAlgo.EDDSA] } },
          scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
          subjectTypesSupported: [SubjectType.PAIRWISE],
          subjectSyntaxTypesSupported: ['did:ethr'],
          registrationBy: { type: PassBy.VALUE },
          logoUri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100318',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        })
        .build();

      const requestURI = await rp.createAuthenticationRequest({
        nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
        state: 'b32f0087fc9816eb813fd11f',
      });

      nock('https://rp.acme.com/siop/jwts').get(/.*/).reply(200, requestURI.jwt);

      // The create method also calls the verifyRequest method, so no need to do it manually
      const verifiedRequest = await op.verifyAuthenticationRequest(requestURI.encodedUri);
      const authenticationResponseWithJWT = await op.createAuthenticationResponse(verifiedRequest);

      nock(EXAMPLE_REDIRECT_URL).post(/.*/).reply(200, { result: 'ok' });
      const response = await op.submitAuthenticationResponse(authenticationResponseWithJWT);
      await expect(response.json()).resolves.toMatchObject({ result: 'ok' });

      const verifiedAuthResponseWithJWT = await rp.verifyAuthenticationResponseJwt(authenticationResponseWithJWT.payload, {
        audience: EXAMPLE_REDIRECT_URL,
      });

      expect(verifiedAuthResponseWithJWT.jwt).toBeDefined();
      expect(verifiedAuthResponseWithJWT.payload.state).toMatch('b32f0087fc9816eb813fd11f');
      expect(verifiedAuthResponseWithJWT.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg');
      expect(verifiedAuthResponseWithJWT.payload.registration.client_name).toEqual(VERIFIER_NAME_FOR_CLIENT);
      expect(verifiedAuthResponseWithJWT.payload.registration['client_name#nl-NL']).toEqual(VERIFIER_NAME_FOR_CLIENT_NL + '2022100318');
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

    const rp = RP.builder()
      .addClientId('test_client_id')
      .addScope('test')
      .addResponseType('id_token')
      .redirect(EXAMPLE_REDIRECT_URL)
      .addVerifyCallback(verifyCallback)
      .withPresentationVerification(presentationVerificationCallback)
      .withRevocationVerification(RevocationVerification.NEVER)
      .requestBy(PassBy.VALUE)
      .internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey)
      .addDidMethod('ethr')
      .registrationBy({
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormatsSupported: { jwt_vc: { alg: [KeyAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subjectSyntaxTypesSupported: ['did', 'did:ethr'],
        registrationBy: { type: PassBy.VALUE },
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100319',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .build();
    const op = OP.builder()
      .withExpiresIn(1000)
      .addVerifyCallback(verifyCallback)
      .addDidMethod('ethr')
      .internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey)
      .registrationBy({
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        issuer: ResponseIss.SELF_ISSUED_V2,
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormats: { jwt_vc: { alg: [KeyAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subjectSyntaxTypesSupported: [],
        registrationBy: { type: PassBy.VALUE },
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100320',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .build();

    const requestURI = await rp.createAuthenticationRequest({
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      state: 'b32f0087fc9816eb813fd11f',
    });

    // Let's test the parsing
    const parsedAuthReqURI = await op.parseAuthenticationRequestURI(requestURI.encodedUri);
    expect(parsedAuthReqURI.requestPayload).toBeDefined();
    expect(parsedAuthReqURI.jwt).toBeDefined();
    expect(parsedAuthReqURI.registration).toBeDefined();

    const verifiedAuthReqWithJWT = await op.verifyAuthenticationRequest(parsedAuthReqURI.jwt);
    expect(verifiedAuthReqWithJWT.signer).toBeDefined();
    expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did);

    const authenticationResponseWithJWT = await op.createAuthenticationResponse(verifiedAuthReqWithJWT);
    expect(authenticationResponseWithJWT.payload).toBeDefined();

    const verifiedAuthResponseWithJWT = await rp.verifyAuthenticationResponseJwt(authenticationResponseWithJWT.payload, {
      audience: EXAMPLE_REDIRECT_URL,
    });

    expect(verifiedAuthResponseWithJWT.jwt).toBeDefined();
    expect(verifiedAuthResponseWithJWT.payload.state).toMatch('b32f0087fc9816eb813fd11f');
    expect(verifiedAuthResponseWithJWT.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg');
    expect(verifiedAuthResponseWithJWT.payload.registration.client_name).toEqual(VERIFIER_NAME_FOR_CLIENT);
    expect(verifiedAuthResponseWithJWT.payload.registration['client_name#nl-NL']).toEqual(VERIFIER_NAME_FOR_CLIENT_NL + '2022100320');
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

    const rp = RP.builder()
      .addClientId('test_client_id')
      .addScope('test')
      .addResponseType('id_token')
      .redirect(EXAMPLE_REDIRECT_URL)
      .addVerifyCallback(verifyCallback)
      .withPresentationVerification(presentationVerificationCallback)
      .withRevocationVerification(RevocationVerification.NEVER)
      .requestBy(PassBy.VALUE)
      .internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey)
      .addDidMethod('ethr')
      .registrationBy({
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormatsSupported: { jwt_vc: { alg: [KeyAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subjectSyntaxTypesSupported: ['did', 'did:ethr'],
        registrationBy: { type: PassBy.VALUE },
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100321',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .addPresentationDefinitionClaim({
        definition: getPresentationDefinition(),
        location: PresentationLocation.VP_TOKEN,
      })
      .build();
    const op = OP.builder()
      .withExpiresIn(1000)
      .addVerifyCallback(verifyCallback)
      .addDidMethod('ethr')
      .internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey)
      .registrationBy({
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        issuer: ResponseIss.SELF_ISSUED_V2,
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormats: { jwt_vc: { alg: [KeyAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subjectSyntaxTypesSupported: [],
        registrationBy: { type: PassBy.VALUE },
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100321',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .build();

    const requestURI = await rp.createAuthenticationRequest({
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      state: 'b32f0087fc9816eb813fd11f',
    });

    // Let's test the parsing
    const parsedAuthReqURI = await op.parseAuthenticationRequestURI(requestURI.encodedUri);
    expect(parsedAuthReqURI.requestPayload).toBeDefined();
    expect(parsedAuthReqURI.jwt).toBeDefined();
    expect(parsedAuthReqURI.registration).toBeDefined();

    const verifiedAuthReqWithJWT = await op.verifyAuthenticationRequest(parsedAuthReqURI.jwt);
    expect(verifiedAuthReqWithJWT.signer).toBeDefined();
    expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did);
    await expect(op.createAuthenticationResponse(verifiedAuthReqWithJWT)).rejects.toThrow(
      Error('authentication request expects a verifiable presentation in the response')
    );

    expect(verifiedAuthReqWithJWT.payload.registration.client_name).toEqual(VERIFIER_NAME_FOR_CLIENT);
    expect(verifiedAuthReqWithJWT.payload.registration['client_name#nl-NL']).toEqual(VERIFIER_NAME_FOR_CLIENT_NL + '2022100321');
  });

  it('succeed when calling with presentation definitions and right verifiable presentation', async () => {
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

    const rp = RP.builder()
      .addClientId('test_client_id')
      .addScope('test')
      .addResponseType('id_token')
      .redirect(EXAMPLE_REDIRECT_URL)
      .withPresentationVerification(presentationVerificationCallback)
      .addVerifyCallback(verifyCallback)
      .withRevocationVerification(RevocationVerification.NEVER)
      .requestBy(PassBy.VALUE)
      .internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey)
      .withAuthorizationEndpoint('www.myauthorizationendpoint.com')
      .addDidMethod('ethr')
      .registrationBy({
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormatsSupported: { jwt_vc: { alg: [KeyAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subjectSyntaxTypesSupported: ['did', 'did:ethr'],
        registrationBy: { type: PassBy.VALUE },
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100322',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .addPresentationDefinitionClaim({
        definition: getPresentationDefinition(),
        location: PresentationLocation.VP_TOKEN,
      })
      .build();
    const op = OP.builder()
      .withPresentationSignCallback(presentationSignCallback)
      .withExpiresIn(1000)
      .addVerifyCallback(verifyCallback)
      .addDidMethod('ethr')
      .internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey)
      .registrationBy({
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        issuer: ResponseIss.SELF_ISSUED_V2,
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormats: { jwt_vc: { alg: [KeyAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subjectSyntaxTypesSupported: [],
        registrationBy: { type: PassBy.VALUE },
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100323',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .build();

    const requestURI = await rp.createAuthenticationRequest({
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      state: 'b32f0087fc9816eb813fd11f',
    });

    // Let's test the parsing
    const parsedAuthReqURI = await op.parseAuthenticationRequestURI(requestURI.encodedUri);
    expect(parsedAuthReqURI.requestPayload).toBeDefined();
    expect(parsedAuthReqURI.jwt).toBeDefined();
    expect(parsedAuthReqURI.registration).toBeDefined();

    const verifiedAuthReqWithJWT = await op.verifyAuthenticationRequest(parsedAuthReqURI.jwt);
    expect(verifiedAuthReqWithJWT.signer).toBeDefined();
    expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did);
    const pex = new PresentationExchange({ did: HOLDER_DID, allVerifiableCredentials: getVCs() });
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(parsedAuthReqURI.requestPayload);
    await pex.selectVerifiableCredentialsForSubmission(pd[0].definition);
    const vp = (await pex.submissionFrom(pd[0].definition, getVCs(), {}, op.authResponseOpts.presentationSignCallback)) as IVerifiablePresentation;
    const authenticationResponseWithJWT = await op.createAuthenticationResponse(verifiedAuthReqWithJWT, {
      vp: [
        {
          presentation: vp,
          format: VerifiablePresentationTypeFormat.LDP_VP,
          location: PresentationLocation.VP_TOKEN,
        },
      ],
    });
    expect(authenticationResponseWithJWT.payload).toBeDefined();

    const verifiedAuthResponseWithJWT = await rp.verifyAuthenticationResponseJwt(authenticationResponseWithJWT.payload, {
      audience: EXAMPLE_REDIRECT_URL,
    });

    expect(verifiedAuthResponseWithJWT.jwt).toBeDefined();
    expect(verifiedAuthResponseWithJWT.payload.state).toMatch('b32f0087fc9816eb813fd11f');
    expect(verifiedAuthResponseWithJWT.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg');
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

      const rp = RP.builder()
        .addClientId('test_client_id')
        .addScope('test')
        .addResponseType('id_token')
        .withCheckLinkedDomain(CheckLinkedDomain.ALWAYS)
        .withPresentationVerification(presentationVerificationCallback)
        .addVerifyCallback(verifyCallback)
        .redirect(EXAMPLE_REDIRECT_URL)
        .requestBy(PassBy.VALUE)
        .internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey)
        .withAuthorizationEndpoint('www.myauthorizationendpoint.com')
        .registrationBy({
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
          requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          responseTypesSupported: [ResponseType.ID_TOKEN],
          vpFormatsSupported: { jwt_vc: { alg: [KeyAlgo.EDDSA] } },
          scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
          subjectTypesSupported: [SubjectType.PAIRWISE],
          subjectSyntaxTypesSupported: ['did', 'did:ethr'],
          registrationBy: { type: PassBy.VALUE },
          logoUri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100324',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        })
        .addPresentationDefinitionClaim({
          definition: getPresentationDefinition(),
          location: PresentationLocation.VP_TOKEN,
        })
        .build();
      const op = OP.builder()
        .withPresentationSignCallback(presentationSignCallback)
        .withExpiresIn(1000)
        .addVerifyCallback(verifyCallback)
        .internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey)
        .registrationBy({
          authorizationEndpoint: 'www.myauthorizationendpoint.com',
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
          issuer: ResponseIss.SELF_ISSUED_V2,
          requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          responseTypesSupported: [ResponseType.ID_TOKEN],
          vpFormats: { jwt_vc: { alg: [KeyAlgo.EDDSA] } },
          scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
          subjectTypesSupported: [SubjectType.PAIRWISE],
          subjectSyntaxTypesSupported: ['did'],
          registrationBy: { type: PassBy.VALUE },
          logoUri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100325',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        })
        .build();

      const requestURI = await rp.createAuthenticationRequest({
        nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
        state: 'b32f0087fc9816eb813fd11f',
      });

      // Let's test the parsing
      const parsedAuthReqURI = await op.parseAuthenticationRequestURI(requestURI.encodedUri);
      expect(parsedAuthReqURI.requestPayload).toBeDefined();
      expect(parsedAuthReqURI.jwt).toBeDefined();
      expect(parsedAuthReqURI.registration).toBeDefined();

      const verifiedAuthReqWithJWT = await op.verifyAuthenticationRequest(parsedAuthReqURI.jwt);
      expect(verifiedAuthReqWithJWT.signer).toBeDefined();
      expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did);
      const pex = new PresentationExchange({ did: HOLDER_DID, allVerifiableCredentials: getVCs() });
      const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(parsedAuthReqURI.requestPayload);
      await pex.selectVerifiableCredentialsForSubmission(pd[0].definition);
      const vp = (await pex.submissionFrom(pd[0].definition, getVCs(), {}, op.authResponseOpts.presentationSignCallback)) as IVerifiablePresentation;
      const authenticationResponseWithJWT = await op.createAuthenticationResponse(verifiedAuthReqWithJWT, {
        vp: [
          {
            presentation: vp,
            format: VerifiablePresentationTypeFormat.LDP_VP,
            location: PresentationLocation.VP_TOKEN,
          },
        ],
      });
      expect(authenticationResponseWithJWT.payload).toBeDefined();
      await expect(
        rp.verifyAuthenticationResponseJwt(authenticationResponseWithJWT.payload, {
          audience: EXAMPLE_REDIRECT_URL,
          verification: {
            mode: VerificationMode.INTERNAL,
            verifyUri: '',
            resolveOpts: {
              subjectSyntaxTypesSupported: ['did', 'did:eth'],
            },
            checkLinkedDomain: CheckLinkedDomain.ALWAYS,
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

    const rp = RP.builder()
      .addClientId('test_client_id')
      .addScope('test')
      .addResponseType('id_token')
      .withCheckLinkedDomain(CheckLinkedDomain.ALWAYS)
      .withPresentationVerification(presentationVerificationCallback)
      .addVerifyCallback(verifyCallback)
      .withRevocationVerification(RevocationVerification.NEVER)
      .redirect(EXAMPLE_REDIRECT_URL)
      .requestBy(PassBy.VALUE)
      .internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey)
      .withAuthorizationEndpoint('www.myauthorizationendpoint.com')
      .registrationBy({
        idTokenSigningAlgValuesSupported: [SigningAlgo.ES256K],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.ES256K],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormatsSupported: {
          jwt_vc: { alg: [KeyAlgo.EDDSA] },
          ldp_vc: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp_vp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
        },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subjectSyntaxTypesSupported: ['did', 'did:ion'],
        registrationBy: { type: PassBy.VALUE },
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100326',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .addPresentationDefinitionClaim({
        definition: getPresentationDefinition(),
        location: PresentationLocation.VP_TOKEN,
      })
      .build();
    const op = OP.builder()
      .withPresentationSignCallback(presentationSignCallback)
      .addVerifyCallback(verifyCallback)
      .withExpiresIn(1000)
      .internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey)
      .registrationBy({
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.ES256K],
        issuer: ResponseIss.SELF_ISSUED_V2,
        requestObjectSigningAlgValuesSupported: [SigningAlgo.ES256K],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormats: {
          jwt_vc: { alg: [KeyAlgo.EDDSA] },
          ldp_vc: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp_vp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
        },
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100327',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subjectSyntaxTypesSupported: ['did:ethr'],
        registrationBy: { type: PassBy.VALUE },
      })
      .build();

    const requestURI = await rp.createAuthenticationRequest({
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      state: 'b32f0087fc9816eb813fd11f',
    });

    // Let's test the parsing
    const parsedAuthReqURI = await op.parseAuthenticationRequestURI(requestURI.encodedUri);
    expect(parsedAuthReqURI.requestPayload).toBeDefined();
    expect(parsedAuthReqURI.jwt).toBeDefined();
    expect(parsedAuthReqURI.registration).toBeDefined();

    const verifiedAuthReqWithJWT = await op.verifyAuthenticationRequest(parsedAuthReqURI.jwt);
    expect(verifiedAuthReqWithJWT.signer).toBeDefined();
    expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did);
    const pex = new PresentationExchange({ did: HOLDER_DID, allVerifiableCredentials: getVCs() });
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(parsedAuthReqURI.requestPayload);
    await pex.selectVerifiableCredentialsForSubmission(pd[0].definition);
    const vp = (await pex.submissionFrom(pd[0].definition, getVCs(), {}, op.authResponseOpts.presentationSignCallback)) as IVerifiablePresentation;
    const authenticationResponseWithJWT = await op.createAuthenticationResponse(verifiedAuthReqWithJWT, {
      vp: [
        {
          presentation: vp,
          format: VerifiablePresentationTypeFormat.LDP_VP,
          location: PresentationLocation.VP_TOKEN,
        },
      ],
    });
    expect(authenticationResponseWithJWT.payload).toBeDefined();

    const DID_CONFIGURATION = {
      '@context': 'https://identity.foundation/.well-known/did-configuration/v1',
      linked_dids: [
        'eyJhbGciOiJSUzI1NiIsImtpZCI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNI3o2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSJ9.eyJleHAiOjE3NjQ4NzkxMzksImlzcyI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwibmJmIjoxNjA3MTEyNzM5LCJzdWIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9pZGVudGl0eS5mb3VuZGF0aW9uLy53ZWxsLWtub3duL2RpZC1jb25maWd1cmF0aW9uL3YxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1rb1RIc2dOTnJieThKekNOUTFpUkx5VzVRUTZSOFh1dTZBQThpZ0dyTVZQVU0iLCJvcmlnaW4iOiJodHRwczovL2lkZW50aXR5LmZvdW5kYXRpb24ifSwiZXhwaXJhdGlvbkRhdGUiOiIyMDI1LTEyLTA0VDE0OjEyOjE5LTA2OjAwIiwiaXNzdWFuY2VEYXRlIjoiMjAyMC0xMi0wNFQxNDoxMjoxOS0wNjowMCIsImlzc3VlciI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkRvbWFpbkxpbmthZ2VDcmVkZW50aWFsIl19fQ.YZnpPMAW3GdaPXC2YKoJ7Igt1OaVZKq09XZBkptyhxTAyHTkX2Ewtew-JKHKQjyDyabY3HAy1LUPoIQX0jrU0J82pIYT3k2o7nNTdLbxlgb49FcDn4czntt5SbY0m1XwrMaKEvV0bHQsYPxNTqjYsyySccgPfmvN9IT8gRS-M9a6MZQxuB3oEMrVOQ5Vco0bvTODXAdCTHibAk1FlvKz0r1vO5QMhtW4OlRrVTI7ibquf9Nim_ch0KeMMThFjsBDKetuDF71nUcL5sf7PCFErvl8ZVw3UK4NkZ6iM-XIRsLL6rXP2SnDUVovcldhxd_pyKEYviMHBOgBdoNP6fOgRQ',
        'eyJhbGciOiJSUzI1NiIsImtpZCI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNI3o2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSJ9.eyJleHAiOjE3NjQ4NzkxMzksImlzcyI6ImRpZDprZXk6b3RoZXIiLCJuYmYiOjE2MDcxMTI3MzksInN1YiI6ImRpZDprZXk6b3RoZXIiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vaWRlbnRpdHkuZm91bmRhdGlvbi8ud2VsbC1rbm93bi9kaWQtY29uZmlndXJhdGlvbi92MSJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDprZXk6b3RoZXIiLCJvcmlnaW4iOiJodHRwczovL2lkZW50aXR5LmZvdW5kYXRpb24ifSwiZXhwaXJhdGlvbkRhdGUiOiIyMDI1LTEyLTA0VDE0OjEyOjE5LTA2OjAwIiwiaXNzdWFuY2VEYXRlIjoiMjAyMC0xMi0wNFQxNDoxMjoxOS0wNjowMCIsImlzc3VlciI6ImRpZDprZXk6b3RoZXIiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRG9tYWluTGlua2FnZUNyZWRlbnRpYWwiXX19.rRuc-ojuEgyq8p_tBYK7BayuiNTBeXNyAnC14Rnjs-jsnhae4_E1Q12W99K2NGCGBi5KjNsBcZmdNJPxejiKPrjjcB99poFCgTY8tuRzDjVo0lIeBwfx9qqjKHTRTUR8FGM_imlOpVfBF4AHYxjkHvZn6c9lYvatYcDpB2UfH4BNXkdSVrUXy_kYjpMpAdRtyCAnD_isN1YpEHBqBmnfuVUbYcQK5kk6eiokRFDtWruL1OEeJMYPqjuBSd2m-H54tSM84Oic_pg2zXDjjBlXNelat6MPNT2QxmkwJg7oyewQWX2Ot2yyhSp9WyAQWMlQIe2x84R0lADUmZ1TPQchNw',
      ],
    };
    expect(rp.verifyAuthResponseOpts.verification.checkLinkedDomain).toBe(CheckLinkedDomain.ALWAYS);
    nock('https://ldtest.sphereon.com').get('/.well-known/did-configuration.json').times(3).reply(200, DID_CONFIGURATION);
    const verifiedAuthResponseWithJWT = await rp.verifyAuthenticationResponseJwt(authenticationResponseWithJWT.payload, {
      audience: EXAMPLE_REDIRECT_URL,
    });
    expect(verifiedAuthResponseWithJWT.jwt).toBeDefined();
    expect(verifiedAuthResponseWithJWT.payload.state).toMatch('b32f0087fc9816eb813fd11f');
    expect(verifiedAuthResponseWithJWT.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg');
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

      const rp = RP.builder()
        .addClientId('test_client_id')
        .addScope('test')
        .addResponseType('id_token')
        .withCheckLinkedDomain(CheckLinkedDomain.IF_PRESENT)
        .withPresentationVerification(presentationVerificationCallback)
        .withRevocationVerification(RevocationVerification.NEVER)
        .addVerifyCallback(verifyCallback)
        .redirect(EXAMPLE_REDIRECT_URL)
        .requestBy(PassBy.VALUE)
        .internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey)
        .withAuthorizationEndpoint('www.myauthorizationendpoint.com')
        .addDidMethod('ethr')
        .registrationBy({
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
          requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          responseTypesSupported: [ResponseType.ID_TOKEN],
          vpFormatsSupported: { jwt_vc: { alg: [KeyAlgo.EDDSA] } },
          scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
          subjectTypesSupported: [SubjectType.PAIRWISE],
          subjectSyntaxTypesSupported: ['did', 'did:ethr'],
          registrationBy: { type: PassBy.VALUE },
          logoUri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100328',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        })
        .addPresentationDefinitionClaim({
          definition: getPresentationDefinition(),
          location: PresentationLocation.VP_TOKEN,
        })
        .build();
      const op = OP.builder()
        .withPresentationSignCallback(presentationSignCallback)
        .withCheckLinkedDomain(CheckLinkedDomain.NEVER)
        .addVerifyCallback(verifyCallback)
        .withExpiresIn(1000)
        .addDidMethod('ethr')
        .internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey)
        .registrationBy({
          authorizationEndpoint: 'www.myauthorizationendpoint.com',
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
          issuer: ResponseIss.SELF_ISSUED_V2,
          requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          responseTypesSupported: [ResponseType.ID_TOKEN],
          vpFormats: { jwt_vc: { alg: [KeyAlgo.EDDSA] } },
          scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
          subjectTypesSupported: [SubjectType.PAIRWISE],
          subjectSyntaxTypesSupported: [],
          registrationBy: { type: PassBy.VALUE },
          logoUri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100329',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        })
        .build();

      const requestURI = await rp.createAuthenticationRequest({
        nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
        state: 'b32f0087fc9816eb813fd11f',
      });

      // Let's test the parsing
      const parsedAuthReqURI = await op.parseAuthenticationRequestURI(requestURI.encodedUri);
      expect(parsedAuthReqURI.requestPayload).toBeDefined();
      expect(parsedAuthReqURI.jwt).toBeDefined();
      expect(parsedAuthReqURI.registration).toBeDefined();

      const verifiedAuthReqWithJWT = await op.verifyAuthenticationRequest(parsedAuthReqURI.jwt);
      expect(verifiedAuthReqWithJWT.signer).toBeDefined();
      expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did);
      const pex = new PresentationExchange({ did: HOLDER_DID, allVerifiableCredentials: getVCs() });
      const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(parsedAuthReqURI.requestPayload);
      await pex.selectVerifiableCredentialsForSubmission(pd[0].definition);
      const vp = (await pex.submissionFrom(pd[0].definition, getVCs(), {}, op.authResponseOpts.presentationSignCallback)) as IVerifiablePresentation;
      const authenticationResponseWithJWT = await op.createAuthenticationResponse(verifiedAuthReqWithJWT, {
        vp: [
          {
            presentation: vp,
            format: VerifiablePresentationTypeFormat.LDP_VP,
            location: PresentationLocation.VP_TOKEN,
          },
        ],
      });
      expect(authenticationResponseWithJWT.payload).toBeDefined();

      const verifiedAuthResponseWithJWT = await rp.verifyAuthenticationResponseJwt(authenticationResponseWithJWT.payload, {
        audience: EXAMPLE_REDIRECT_URL,
      });
      expect(verifiedAuthResponseWithJWT.jwt).toBeDefined();
      expect(verifiedAuthResponseWithJWT.payload.state).toMatch('b32f0087fc9816eb813fd11f');
      expect(verifiedAuthResponseWithJWT.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg');
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
    const rp = RP.builder()
      .addClientId('test_client_id')
      .addScope('test')
      .addResponseType('id_token')
      .withRevocationVerification(RevocationVerification.ALWAYS)
      .withPresentationVerification(presentationVerificationCallback)
      .addVerifyCallback(verifyCallback)
      .withCheckLinkedDomain(CheckLinkedDomain.NEVER)
      .withRevocationVerificationCallback(async () => {
        return { status: RevocationStatus.VALID };
      })
      .redirect(EXAMPLE_REDIRECT_URL)
      .requestBy(PassBy.VALUE)
      .internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey)
      .withAuthorizationEndpoint('www.myauthorizationendpoint.com')
      .addDidMethod('ion')
      .registrationBy({
        idTokenSigningAlgValuesSupported: [SigningAlgo.ES256K],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.ES256K],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormatsSupported: {
          jwt_vc: { alg: [KeyAlgo.EDDSA] },
          jwt_vp: { alg: [KeyAlgo.EDDSA] },
          ldp_vc: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp_vp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
        },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subjectSyntaxTypesSupported: ['did', 'did:ion'],
        registrationBy: { type: PassBy.VALUE },
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100330',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .addPresentationDefinitionClaim({
        definition: getPresentationDefinition(),
        location: PresentationLocation.VP_TOKEN,
      })
      .build();

    const op = OP.builder()
      .withPresentationSignCallback(presentationSignCallback)
      .withExpiresIn(1000)
      .addDidMethod('ethr')
      .internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey)
      .withPresentationSignCallback(presentationSignCallback)
      .withCheckLinkedDomain(CheckLinkedDomain.NEVER)
      .addVerifyCallback(verifyCallback)
      .registrationBy({
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.ES256K],
        issuer: ResponseIss.SELF_ISSUED_V2,
        requestObjectSigningAlgValuesSupported: [SigningAlgo.ES256K],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormats: {
          jwt_vc: { alg: [KeyAlgo.EDDSA] },
          jwt_vp: { alg: [KeyAlgo.EDDSA] },
          ldp_vc: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp_vp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
        },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subjectSyntaxTypesSupported: [],
        registrationBy: { type: PassBy.VALUE },
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100331',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .build();

    const requestURI = await rp.createAuthenticationRequest({
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      state: 'b32f0087fc9816eb813fd11f',
    });

    // Let's test the parsing
    const parsedAuthReqURI = await op.parseAuthenticationRequestURI(requestURI.encodedUri);
    expect(parsedAuthReqURI.requestPayload).toBeDefined();
    expect(parsedAuthReqURI.jwt).toBeDefined();
    expect(parsedAuthReqURI.registration).toBeDefined();

    const verifiedAuthReqWithJWT = await op.verifyAuthenticationRequest(parsedAuthReqURI.jwt); //, rp.authRequestOpts
    expect(verifiedAuthReqWithJWT.signer).toBeDefined();
    expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did);

    const pex = new PresentationExchange({ did: HOLDER_DID, allVerifiableCredentials: getVCs() });
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(parsedAuthReqURI.requestPayload);
    await pex.selectVerifiableCredentialsForSubmission(pd[0].definition);
    const vp = (await pex.submissionFrom(pd[0].definition, getVCs(), {}, op.authResponseOpts.presentationSignCallback)) as IVerifiablePresentation;

    const authenticationResponseWithJWT = await op.createAuthenticationResponse(verifiedAuthReqWithJWT, {
      vp: [
        {
          presentation: vp,
          format: VerifiablePresentationTypeFormat.LDP_VP,
          location: PresentationLocation.VP_TOKEN,
        },
      ],
    });
    expect(authenticationResponseWithJWT.payload).toBeDefined();

    const DID_CONFIGURATION = {
      '@context': 'https://identity.foundation/.well-known/did-configuration/v1',
      linked_dids: [
        'eyJhbGciOiJSUzI1NiIsImtpZCI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNI3o2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSJ9.eyJleHAiOjE3NjQ4NzkxMzksImlzcyI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwibmJmIjoxNjA3MTEyNzM5LCJzdWIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9pZGVudGl0eS5mb3VuZGF0aW9uLy53ZWxsLWtub3duL2RpZC1jb25maWd1cmF0aW9uL3YxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1rb1RIc2dOTnJieThKekNOUTFpUkx5VzVRUTZSOFh1dTZBQThpZ0dyTVZQVU0iLCJvcmlnaW4iOiJodHRwczovL2lkZW50aXR5LmZvdW5kYXRpb24ifSwiZXhwaXJhdGlvbkRhdGUiOiIyMDI1LTEyLTA0VDE0OjEyOjE5LTA2OjAwIiwiaXNzdWFuY2VEYXRlIjoiMjAyMC0xMi0wNFQxNDoxMjoxOS0wNjowMCIsImlzc3VlciI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkRvbWFpbkxpbmthZ2VDcmVkZW50aWFsIl19fQ.YZnpPMAW3GdaPXC2YKoJ7Igt1OaVZKq09XZBkptyhxTAyHTkX2Ewtew-JKHKQjyDyabY3HAy1LUPoIQX0jrU0J82pIYT3k2o7nNTdLbxlgb49FcDn4czntt5SbY0m1XwrMaKEvV0bHQsYPxNTqjYsyySccgPfmvN9IT8gRS-M9a6MZQxuB3oEMrVOQ5Vco0bvTODXAdCTHibAk1FlvKz0r1vO5QMhtW4OlRrVTI7ibquf9Nim_ch0KeMMThFjsBDKetuDF71nUcL5sf7PCFErvl8ZVw3UK4NkZ6iM-XIRsLL6rXP2SnDUVovcldhxd_pyKEYviMHBOgBdoNP6fOgRQ',
        'eyJhbGciOiJSUzI1NiIsImtpZCI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNI3o2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSJ9.eyJleHAiOjE3NjQ4NzkxMzksImlzcyI6ImRpZDprZXk6b3RoZXIiLCJuYmYiOjE2MDcxMTI3MzksInN1YiI6ImRpZDprZXk6b3RoZXIiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vaWRlbnRpdHkuZm91bmRhdGlvbi8ud2VsbC1rbm93bi9kaWQtY29uZmlndXJhdGlvbi92MSJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDprZXk6b3RoZXIiLCJvcmlnaW4iOiJodHRwczovL2lkZW50aXR5LmZvdW5kYXRpb24ifSwiZXhwaXJhdGlvbkRhdGUiOiIyMDI1LTEyLTA0VDE0OjEyOjE5LTA2OjAwIiwiaXNzdWFuY2VEYXRlIjoiMjAyMC0xMi0wNFQxNDoxMjoxOS0wNjowMCIsImlzc3VlciI6ImRpZDprZXk6b3RoZXIiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRG9tYWluTGlua2FnZUNyZWRlbnRpYWwiXX19.rRuc-ojuEgyq8p_tBYK7BayuiNTBeXNyAnC14Rnjs-jsnhae4_E1Q12W99K2NGCGBi5KjNsBcZmdNJPxejiKPrjjcB99poFCgTY8tuRzDjVo0lIeBwfx9qqjKHTRTUR8FGM_imlOpVfBF4AHYxjkHvZn6c9lYvatYcDpB2UfH4BNXkdSVrUXy_kYjpMpAdRtyCAnD_isN1YpEHBqBmnfuVUbYcQK5kk6eiokRFDtWruL1OEeJMYPqjuBSd2m-H54tSM84Oic_pg2zXDjjBlXNelat6MPNT2QxmkwJg7oyewQWX2Ot2yyhSp9WyAQWMlQIe2x84R0lADUmZ1TPQchNw',
      ],
    };
    nock('https://ldtest.sphereon.com').get('/.well-known/did-configuration.json').times(3).reply(200, DID_CONFIGURATION);
    const verifiedAuthResponseWithJWT = await rp.verifyAuthenticationResponseJwt(authenticationResponseWithJWT.payload, {
      audience: EXAMPLE_REDIRECT_URL,
    });
    expect(verifiedAuthResponseWithJWT.jwt).toBeDefined();
    expect(verifiedAuthResponseWithJWT.payload.state).toMatch('b32f0087fc9816eb813fd11f');
    expect(verifiedAuthResponseWithJWT.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg');
  });

  it('should verify revocation ldp_vp with RevocationVerification.ALWAYS', async () => {
    const vpToken = {
      presentation: {
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
            type: ['PermanentResidentCard', 'verifiableCredential'],
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
      },
      format: VerifiablePresentationTypeFormat.LDP_VP,
    };

    await expect(
      verifyRevocation(
        vpToken,
        async () => {
          return { status: RevocationStatus.VALID };
        },
        RevocationVerification.ALWAYS
      )
    ).resolves.not.toThrow();
  });

  it('should verify revocation ldp_vp with RevocationVerification.IF_PRESENT', async () => {
    const vpToken = {
      presentation: {
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
            type: ['PermanentResidentCard', 'verifiableCredential'],
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
      },
      format: VerifiablePresentationTypeFormat.LDP_VP,
    };

    await expect(
      verifyRevocation(
        vpToken,
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

    const rp = RP.builder()
      .addClientId('test_client_id')
      .addScope('test')
      .addResponseType('id_token')
      .withCheckLinkedDomain(CheckLinkedDomain.NEVER)
      .withPresentationVerification(presentationVerificationCallback)
      .addVerifyCallback(verifyCallback)
      .withRevocationVerification(RevocationVerification.NEVER)
      .redirect(EXAMPLE_REDIRECT_URL)
      .requestBy(PassBy.VALUE)
      .internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey)
      .withAuthorizationEndpoint('www.myauthorizationendpoint.com')
      .registrationBy({
        idTokenSigningAlgValuesSupported: [SigningAlgo.ES256K],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.ES256K],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormatsSupported: {
          jwt_vc: { alg: [KeyAlgo.EDDSA] },
          ldp_vc: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp_vp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
        },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subjectSyntaxTypesSupported: ['did', 'did:ion'],
        registrationBy: { type: PassBy.VALUE },
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
      })
      .addPresentationDefinitionClaim({
        definition: getPresentationDefinition(),
        location: PresentationLocation.VP_TOKEN,
      })
      .build();
    const op = OP.builder()
      .withPresentationSignCallback(presentationSignCallback)
      .addVerifyCallback(verifyCallback)
      .withExpiresIn(1000)
      .internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey)
      .withCheckLinkedDomain(CheckLinkedDomain.NEVER)
      .registrationBy({
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.ES256K],
        issuer: ResponseIss.SELF_ISSUED_V2,
        requestObjectSigningAlgValuesSupported: [SigningAlgo.ES256K],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormats: {
          jwt_vc: { alg: [KeyAlgo.EDDSA] },
          ldp_vc: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp_vp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
        },
        logoUri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subjectSyntaxTypesSupported: ['did:ethr'],
        registrationBy: { type: PassBy.VALUE },
      })
      .build();

    const requestURI = await rp.createAuthenticationRequest({
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      state: 'b32f0087fc9816eb813fd11f',
    });

    // Let's test the parsing
    const parsedAuthReqURI = await op.parseAuthenticationRequestURI(requestURI.encodedUri);
    expect(parsedAuthReqURI.requestPayload).toBeDefined();
    expect(parsedAuthReqURI.jwt).toBeDefined();
    expect(parsedAuthReqURI.registration).toBeDefined();

    const verifiedAuthReqWithJWT = await op.verifyAuthenticationRequest(parsedAuthReqURI.jwt);
    expect(verifiedAuthReqWithJWT.signer).toBeDefined();
    expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did);
    const pex = new PresentationExchange({ did: HOLDER_DID, allVerifiableCredentials: getVCs() });
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(parsedAuthReqURI.requestPayload);
    await pex.selectVerifiableCredentialsForSubmission(pd[0].definition);
    const vp = (await pex.submissionFrom(pd[0].definition, getVCs(), {}, op.authResponseOpts.presentationSignCallback)) as IVerifiablePresentation;
    const authenticationResponseWithJWT = await op.createAuthenticationResponse(verifiedAuthReqWithJWT, {
      vp: [
        {
          presentation: vp,
          format: VerifiablePresentationTypeFormat.LDP_VP,
          location: PresentationLocation.ID_TOKEN,
        },
      ],
    });
    expect(authenticationResponseWithJWT.payload).toBeDefined();

    const verifiedAuthResponseWithJWT = await rp.verifyAuthenticationResponseJwt(authenticationResponseWithJWT.payload, {
      audience: EXAMPLE_REDIRECT_URL,
    });
    expect(verifiedAuthResponseWithJWT.jwt).toBeDefined();
    expect(verifiedAuthResponseWithJWT.payload.state).toMatch('b32f0087fc9816eb813fd11f');
    expect(verifiedAuthResponseWithJWT.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg');
  });
});
