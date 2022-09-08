import { IPresentationDefinition } from '@sphereon/pex';
import { IProofType, IVerifiableCredential } from '@sphereon/ssi-types';
import { WDCErrors } from '@sphereon/wellknown-dids-client';
import nock from 'nock';

import {
  CheckLinkedDomain,
  KeyAlgo,
  OP,
  PassBy,
  PresentationDefinitionWithLocation,
  PresentationExchange,
  PresentationLocation,
  ResponseIss,
  ResponseType,
  RP,
  Scope,
  SigningAlgo,
  SubjectType,
  validateLinkedDomainWithDid,
  VerifiablePresentationTypeFormat,
} from '../src/main';

import { mockedGetEnterpriseAuthToken } from './TestUtils';

const EXAMPLE_REDIRECT_URL = 'https://acme.com/hello';
const EXAMPLE_REFERENCE_URL = 'https://rp.acme.com/siop/jwts';

const HOLDER_DID = 'did:example:ebfeb1f712ebc6f1c276e12ec21';

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
  it('succeed when calling each other in the full flow', async () => {
    // expect.assertions(1);
    const rpMockEntity = await mockedGetEnterpriseAuthToken('ACME RP');
    const opMockEntity = await mockedGetEnterpriseAuthToken('ACME OP');

    const rp = RP.builder()
      .redirect(EXAMPLE_REDIRECT_URL)
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
      })
      .build();
    const op = OP.builder()
      .withExpiresIn(1000)
      .addDidMethod('ethr')
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
        subjectSyntaxTypesSupported: [],
        registrationBy: { type: PassBy.VALUE },
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

    const verifiedAuthResponseWithJWT = await rp.verifyAuthenticationResponseJwt(authenticationResponseWithJWT.jwt, {
      audience: EXAMPLE_REDIRECT_URL,
    });

    expect(verifiedAuthResponseWithJWT.jwt).toBeDefined();
    expect(verifiedAuthResponseWithJWT.payload.state).toMatch('b32f0087fc9816eb813fd11f');
    expect(verifiedAuthResponseWithJWT.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg');
  }, 10000);

  it('succeed when calling optional steps in the full flow', async () => {
    // expect.assertions(1);
    const rpMockEntity = {
      hexPrivateKey: 'a1458fac9ea502099f40be363ad3144d6d509aa5aa3d17158a9e6c3b67eb0397',
      did: 'did:ethr:ropsten:0x028360fb95417724cb7dd2ff217b15d6f17fc45e0ffc1b3dce6c2b8dd1e704fa98',
      didKey: 'did:ethr:ropsten:0x028360fb95417724cb7dd2ff217b15d6f17fc45e0ffc1b3dce6c2b8dd1e704fa98#controller',
    };

    const opMockEntity = {
      hexPrivateKey: '88a62d50de38dc22f5b4e7cc80d68a0f421ea489dda0e3bd5c165f08ce46e666',
      did: 'did:ethr:ropsten:0x03f8b96c88063da2b7f5cc90513560a7ec38b92616fff9c95ae95f46cc692a7c75',
      didKey: 'did:ethr:ropsten:0x03f8b96c88063da2b7f5cc90513560a7ec38b92616fff9c95ae95f46cc692a7c75#controller',
    };

    const rp = RP.builder()
      .redirect(EXAMPLE_REDIRECT_URL)
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
      })
      .build();
    const op = OP.builder()
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

    const verifiedAuthResponseWithJWT = await rp.verifyAuthenticationResponseJwt(authenticationResponseWithJWT.jwt, {
      audience: EXAMPLE_REDIRECT_URL,
    });

    expect(verifiedAuthResponseWithJWT.jwt).toBeDefined();
    expect(verifiedAuthResponseWithJWT.payload.state).toMatch('b32f0087fc9816eb813fd11f');
    expect(verifiedAuthResponseWithJWT.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg');
  });

  it('fail when calling with presentation definitions and without verifiable presentation', async () => {
    const rpMockEntity = {
      hexPrivateKey: 'a1458fac9ea502099f40be363ad3144d6d509aa5aa3d17158a9e6c3b67eb0397',
      did: 'did:ethr:ropsten:0x028360fb95417724cb7dd2ff217b15d6f17fc45e0ffc1b3dce6c2b8dd1e704fa98',
      didKey: 'did:ethr:ropsten:0x028360fb95417724cb7dd2ff217b15d6f17fc45e0ffc1b3dce6c2b8dd1e704fa98#controller',
    };

    const opMockEntity = {
      hexPrivateKey: '88a62d50de38dc22f5b4e7cc80d68a0f421ea489dda0e3bd5c165f08ce46e666',
      did: 'did:ethr:ropsten:0x03f8b96c88063da2b7f5cc90513560a7ec38b92616fff9c95ae95f46cc692a7c75',
      didKey: 'did:ethr:ropsten:0x03f8b96c88063da2b7f5cc90513560a7ec38b92616fff9c95ae95f46cc692a7c75#controller',
    };

    const rp = RP.builder()
      .redirect(EXAMPLE_REDIRECT_URL)
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
      })
      .addPresentationDefinitionClaim({
        definition: getPresentationDefinition(),
        location: PresentationLocation.VP_TOKEN,
      })
      .build();
    const op = OP.builder()
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
  });

  it('succeed when calling with presentation definitions and right verifiable presentation', async () => {
    const rpMockEntity = {
      hexPrivateKey: 'a1458fac9ea502099f40be363ad3144d6d509aa5aa3d17158a9e6c3b67eb0397',
      did: 'did:ethr:ropsten:0x028360fb95417724cb7dd2ff217b15d6f17fc45e0ffc1b3dce6c2b8dd1e704fa98',
      didKey: 'did:ethr:ropsten:0x028360fb95417724cb7dd2ff217b15d6f17fc45e0ffc1b3dce6c2b8dd1e704fa98#controller',
    };

    const opMockEntity = {
      hexPrivateKey: '88a62d50de38dc22f5b4e7cc80d68a0f421ea489dda0e3bd5c165f08ce46e666',
      did: 'did:ethr:ropsten:0x03f8b96c88063da2b7f5cc90513560a7ec38b92616fff9c95ae95f46cc692a7c75',
      didKey: 'did:ethr:ropsten:0x03f8b96c88063da2b7f5cc90513560a7ec38b92616fff9c95ae95f46cc692a7c75#controller',
    };

    const rp = RP.builder()
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
      })
      .addPresentationDefinitionClaim({
        definition: getPresentationDefinition(),
        location: PresentationLocation.VP_TOKEN,
      })
      .build();
    const op = OP.builder()
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
    const vp = await pex.submissionFrom(pd[0].definition, getVCs());
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

    const verifiedAuthResponseWithJWT = await rp.verifyAuthenticationResponseJwt(authenticationResponseWithJWT.jwt, {
      audience: EXAMPLE_REDIRECT_URL,
    });

    expect(verifiedAuthResponseWithJWT.jwt).toBeDefined();
    expect(verifiedAuthResponseWithJWT.payload.state).toMatch('b32f0087fc9816eb813fd11f');
    expect(verifiedAuthResponseWithJWT.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg');
  });

  it('fail when calling with LinkedDomainValidationMode.ALWAYS', async () => {
    const rpMockEntity = {
      hexPrivateKey: 'a1458fac9ea502099f40be363ad3144d6d509aa5aa3d17158a9e6c3b67eb0397',
      did: 'did:ethr:ropsten:0x028360fb95417724cb7dd2ff217b15d6f17fc45e0ffc1b3dce6c2b8dd1e704fa98',
      didKey: 'did:ethr:ropsten:0x028360fb95417724cb7dd2ff217b15d6f17fc45e0ffc1b3dce6c2b8dd1e704fa98#controller',
    };

    const opMockEntity = {
      hexPrivateKey: '88a62d50de38dc22f5b4e7cc80d68a0f421ea489dda0e3bd5c165f08ce46e666',
      did: 'did:ethr:ropsten:0x03f8b96c88063da2b7f5cc90513560a7ec38b92616fff9c95ae95f46cc692a7c75',
      didKey: 'did:ethr:ropsten:0x03f8b96c88063da2b7f5cc90513560a7ec38b92616fff9c95ae95f46cc692a7c75#controller',
    };

    const rp = RP.builder()
      .withCheckLinkedDomain(CheckLinkedDomain.ALWAYS)
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
      })
      .addPresentationDefinitionClaim({
        definition: getPresentationDefinition(),
        location: PresentationLocation.VP_TOKEN,
      })
      .build();
    const op = OP.builder()
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
    const vp = await pex.submissionFrom(pd[0].definition, getVCs());
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
      rp.verifyAuthenticationResponseJwt(authenticationResponseWithJWT.jwt, {
        audience: EXAMPLE_REDIRECT_URL,
      })
    ).rejects.toThrow(new Error(WDCErrors.PROPERTY_SERVICE_NOT_PRESENT));
  }, 10000);

  it('succeed when calling with LinkedDomainValidationMode.ALWAYS', async () => {
    const rpMockEntity = {
      hexPrivateKey: 'a1458fac9ea502099f40be363ad3144d6d509aa5aa3d17158a9e6c3b67eb0397',
      did: 'did:ethr:ropsten:0x028360fb95417724cb7dd2ff217b15d6f17fc45e0ffc1b3dce6c2b8dd1e704fa98',
      didKey: 'did:ethr:ropsten:0x028360fb95417724cb7dd2ff217b15d6f17fc45e0ffc1b3dce6c2b8dd1e704fa98#controller',
    };

    const opMockEntity = {
      hexPrivateKey: '88a62d50de38dc22f5b4e7cc80d68a0f421ea489dda0e3bd5c165f08ce46e666',
      did: 'did:ion:EiCMvVdXv6iL3W8i4n-LmqUhE614kX4TYxVR5kTY2QGOjg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXkxIiwicHVibGljS2V5SndrIjp7ImNydiI6InNlY3AyNTZrMSIsImt0eSI6IkVDIiwieCI6Ii1MbHNpQVk5b3JmMXpKQlJOV0NuN0RpNUpoYl8tY2xhNlY5R3pHa3FmSFUiLCJ5IjoiRXBIU25GZHQ2ZU5lRkJEZzNVNVFIVDE0TVRsNHZIc0h5NWRpWU9DWEs1TSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiIsImFzc2VydGlvbk1ldGhvZCJdLCJ0eXBlIjoiRWNkc2FTZWNwMjU2azFWZXJpZmljYXRpb25LZXkyMDE5In1dLCJzZXJ2aWNlcyI6W3siaWQiOiJsZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vbGR0ZXN0LnNwaGVyZW9uLmNvbSIsInR5cGUiOiJMaW5rZWREb21haW5zIn1dfX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlBem8wTVVZUW5HNWM0VFJKZVFsNFR5WVRrSmRyeTJoeXlQUlpENzdFQm1CdyJ9LCJzdWZmaXhEYXRhIjp7ImRlbHRhSGFzaCI6IkVpQUwtaEtrLUVsODNsRVJiZkFDUk1kSWNQVjRXWGJqZ3dsZ1ZDWTNwbDhhMGciLCJyZWNvdmVyeUNvbW1pdG1lbnQiOiJFaUItT2NSbTlTNXdhU3QxbU4zSG4zM2RnMzJKN25MOEdBVHpGQ2ZXaWdIXzh3In19',
      didKey:
        'did:ion:EiCMvVdXv6iL3W8i4n-LmqUhE614kX4TYxVR5kTY2QGOjg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXkxIiwicHVibGljS2V5SndrIjp7ImNydiI6InNlY3AyNTZrMSIsImt0eSI6IkVDIiwieCI6Ii1MbHNpQVk5b3JmMXpKQlJOV0NuN0RpNUpoYl8tY2xhNlY5R3pHa3FmSFUiLCJ5IjoiRXBIU25GZHQ2ZU5lRkJEZzNVNVFIVDE0TVRsNHZIc0h5NWRpWU9DWEs1TSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiIsImFzc2VydGlvbk1ldGhvZCJdLCJ0eXBlIjoiRWNkc2FTZWNwMjU2azFWZXJpZmljYXRpb25LZXkyMDE5In1dLCJzZXJ2aWNlcyI6W3siaWQiOiJsZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vbGR0ZXN0LnNwaGVyZW9uLmNvbSIsInR5cGUiOiJMaW5rZWREb21haW5zIn1dfX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlBem8wTVVZUW5HNWM0VFJKZVFsNFR5WVRrSmRyeTJoeXlQUlpENzdFQm1CdyJ9LCJzdWZmaXhEYXRhIjp7ImRlbHRhSGFzaCI6IkVpQUwtaEtrLUVsODNsRVJiZkFDUk1kSWNQVjRXWGJqZ3dsZ1ZDWTNwbDhhMGciLCJyZWNvdmVyeUNvbW1pdG1lbnQiOiJFaUItT2NSbTlTNXdhU3QxbU4zSG4zM2RnMzJKN25MOEdBVHpGQ2ZXaWdIXzh3In19#key1',
    };

    const rp = RP.builder()
      .withCheckLinkedDomain(CheckLinkedDomain.ALWAYS)
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
          ldp_vc: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp_vp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
          ldp: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
        },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subjectSyntaxTypesSupported: ['did', 'did:ion'],
        registrationBy: { type: PassBy.VALUE },
      })
      .addPresentationDefinitionClaim({
        definition: getPresentationDefinition(),
        location: PresentationLocation.VP_TOKEN,
      })
      .build();
    const op = OP.builder()
      .withExpiresIn(1000)
      .addDidMethod('ethr')
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
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subjectSyntaxTypesSupported: [],
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
    const vp = await pex.submissionFrom(pd[0].definition, getVCs());
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
    const verifiedAuthResponseWithJWT = await rp.verifyAuthenticationResponseJwt(authenticationResponseWithJWT.jwt, {
      audience: EXAMPLE_REDIRECT_URL,
    });
    expect(verifiedAuthResponseWithJWT.jwt).toBeDefined();
    expect(verifiedAuthResponseWithJWT.payload.state).toMatch('b32f0087fc9816eb813fd11f');
    expect(verifiedAuthResponseWithJWT.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg');
  });

  it('succeed with ion did', async () => {
    const did =
      'did:ion:EiCMvVdXv6iL3W8i4n-LmqUhE614kX4TYxVR5kTY2QGOjg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXkxIiwicHVibGljS2V5SndrIjp7ImNydiI6InNlY3AyNTZrMSIsImt0eSI6IkVDIiwieCI6Ii1MbHNpQVk5b3JmMXpKQlJOV0NuN0RpNUpoYl8tY2xhNlY5R3pHa3FmSFUiLCJ5IjoiRXBIU25GZHQ2ZU5lRkJEZzNVNVFIVDE0TVRsNHZIc0h5NWRpWU9DWEs1TSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiIsImFzc2VydGlvbk1ldGhvZCJdLCJ0eXBlIjoiRWNkc2FTZWNwMjU2azFWZXJpZmljYXRpb25LZXkyMDE5In1dLCJzZXJ2aWNlcyI6W3siaWQiOiJsZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vbGR0ZXN0LnNwaGVyZW9uLmNvbSIsInR5cGUiOiJMaW5rZWREb21haW5zIn1dfX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlBem8wTVVZUW5HNWM0VFJKZVFsNFR5WVRrSmRyeTJoeXlQUlpENzdFQm1CdyJ9LCJzdWZmaXhEYXRhIjp7ImRlbHRhSGFzaCI6IkVpQUwtaEtrLUVsODNsRVJiZkFDUk1kSWNQVjRXWGJqZ3dsZ1ZDWTNwbDhhMGciLCJyZWNvdmVyeUNvbW1pdG1lbnQiOiJFaUItT2NSbTlTNXdhU3QxbU4zSG4zM2RnMzJKN25MOEdBVHpGQ2ZXaWdIXzh3In19';
    const DID_CONFIGURATION = {
      '@context': 'https://identity.foundation/.well-known/did-configuration/v1',
      linked_dids: [
        'eyJhbGciOiJSUzI1NiIsImtpZCI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNI3o2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSJ9.eyJleHAiOjE3NjQ4NzkxMzksImlzcyI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwibmJmIjoxNjA3MTEyNzM5LCJzdWIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9pZGVudGl0eS5mb3VuZGF0aW9uLy53ZWxsLWtub3duL2RpZC1jb25maWd1cmF0aW9uL3YxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1rb1RIc2dOTnJieThKekNOUTFpUkx5VzVRUTZSOFh1dTZBQThpZ0dyTVZQVU0iLCJvcmlnaW4iOiJodHRwczovL2lkZW50aXR5LmZvdW5kYXRpb24ifSwiZXhwaXJhdGlvbkRhdGUiOiIyMDI1LTEyLTA0VDE0OjEyOjE5LTA2OjAwIiwiaXNzdWFuY2VEYXRlIjoiMjAyMC0xMi0wNFQxNDoxMjoxOS0wNjowMCIsImlzc3VlciI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkRvbWFpbkxpbmthZ2VDcmVkZW50aWFsIl19fQ.YZnpPMAW3GdaPXC2YKoJ7Igt1OaVZKq09XZBkptyhxTAyHTkX2Ewtew-JKHKQjyDyabY3HAy1LUPoIQX0jrU0J82pIYT3k2o7nNTdLbxlgb49FcDn4czntt5SbY0m1XwrMaKEvV0bHQsYPxNTqjYsyySccgPfmvN9IT8gRS-M9a6MZQxuB3oEMrVOQ5Vco0bvTODXAdCTHibAk1FlvKz0r1vO5QMhtW4OlRrVTI7ibquf9Nim_ch0KeMMThFjsBDKetuDF71nUcL5sf7PCFErvl8ZVw3UK4NkZ6iM-XIRsLL6rXP2SnDUVovcldhxd_pyKEYviMHBOgBdoNP6fOgRQ',
        'eyJhbGciOiJSUzI1NiIsImtpZCI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNI3o2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSJ9.eyJleHAiOjE3NjQ4NzkxMzksImlzcyI6ImRpZDprZXk6b3RoZXIiLCJuYmYiOjE2MDcxMTI3MzksInN1YiI6ImRpZDprZXk6b3RoZXIiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vaWRlbnRpdHkuZm91bmRhdGlvbi8ud2VsbC1rbm93bi9kaWQtY29uZmlndXJhdGlvbi92MSJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDprZXk6b3RoZXIiLCJvcmlnaW4iOiJodHRwczovL2lkZW50aXR5LmZvdW5kYXRpb24ifSwiZXhwaXJhdGlvbkRhdGUiOiIyMDI1LTEyLTA0VDE0OjEyOjE5LTA2OjAwIiwiaXNzdWFuY2VEYXRlIjoiMjAyMC0xMi0wNFQxNDoxMjoxOS0wNjowMCIsImlzc3VlciI6ImRpZDprZXk6b3RoZXIiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRG9tYWluTGlua2FnZUNyZWRlbnRpYWwiXX19.rRuc-ojuEgyq8p_tBYK7BayuiNTBeXNyAnC14Rnjs-jsnhae4_E1Q12W99K2NGCGBi5KjNsBcZmdNJPxejiKPrjjcB99poFCgTY8tuRzDjVo0lIeBwfx9qqjKHTRTUR8FGM_imlOpVfBF4AHYxjkHvZn6c9lYvatYcDpB2UfH4BNXkdSVrUXy_kYjpMpAdRtyCAnD_isN1YpEHBqBmnfuVUbYcQK5kk6eiokRFDtWruL1OEeJMYPqjuBSd2m-H54tSM84Oic_pg2zXDjjBlXNelat6MPNT2QxmkwJg7oyewQWX2Ot2yyhSp9WyAQWMlQIe2x84R0lADUmZ1TPQchNw',
      ],
    };
    nock('https://ldtest.sphereon.com').get('/.well-known/did-configuration.json').times(3).reply(200, DID_CONFIGURATION);
    await expect(validateLinkedDomainWithDid(did, CheckLinkedDomain.ALWAYS)).resolves.not.toThrow();
  });

  it('succeed when calling with LinkedDomainValidationMode.OPTIONAL', async () => {
    const rpMockEntity = {
      hexPrivateKey: 'a1458fac9ea502099f40be363ad3144d6d509aa5aa3d17158a9e6c3b67eb0397',
      did: 'did:ethr:ropsten:0x028360fb95417724cb7dd2ff217b15d6f17fc45e0ffc1b3dce6c2b8dd1e704fa98',
      didKey: 'did:ethr:ropsten:0x028360fb95417724cb7dd2ff217b15d6f17fc45e0ffc1b3dce6c2b8dd1e704fa98#controller',
    };

    const opMockEntity = {
      hexPrivateKey: '88a62d50de38dc22f5b4e7cc80d68a0f421ea489dda0e3bd5c165f08ce46e666',
      did: 'did:ethr:ropsten:0x03f8b96c88063da2b7f5cc90513560a7ec38b92616fff9c95ae95f46cc692a7c75',
      didKey: 'did:ethr:ropsten:0x03f8b96c88063da2b7f5cc90513560a7ec38b92616fff9c95ae95f46cc692a7c75#controller',
    };

    const rp = RP.builder()
      .withCheckLinkedDomain(CheckLinkedDomain.IF_PRESENT)
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
      })
      .addPresentationDefinitionClaim({
        definition: getPresentationDefinition(),
        location: PresentationLocation.VP_TOKEN,
      })
      .build();
    const op = OP.builder()
      .withCheckLinkedDomain(CheckLinkedDomain.NEVER)
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
    const vp = await pex.submissionFrom(pd[0].definition, getVCs());
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

    const verifiedAuthResponseWithJWT = await rp.verifyAuthenticationResponseJwt(authenticationResponseWithJWT.jwt, {
      audience: EXAMPLE_REDIRECT_URL,
    });
    expect(verifiedAuthResponseWithJWT.jwt).toBeDefined();
    expect(verifiedAuthResponseWithJWT.payload.state).toMatch('b32f0087fc9816eb813fd11f');
    expect(verifiedAuthResponseWithJWT.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg');
  }, 10000);
});
