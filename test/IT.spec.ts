import { IPresentationDefinition } from '@sphereon/pex';
import { IVerifiableCredential } from '@sphereon/ssi-types';
import nock from 'nock';

import { OP, PresentationExchange, RP } from '../src/main';
import { PresentationDefinitionWithLocation } from '../src/main/types/SIOP.types';
import { CredentialFormat, PassBy, PresentationLocation, VerifiablePresentationTypeFormat } from '../src/main/types/SIOP.types';

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
      .internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, `${rpMockEntity.did}#controller`)
      .addDidMethod('ethr')
      .registrationBy(PassBy.VALUE)
      .addCredentialFormat(CredentialFormat.JWT)
      .build();
    const op = OP.builder()
      .withExpiresIn(1000)
      .addDidMethod('ethr')
      .internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, `${opMockEntity.did}#controller`)
      .registrationBy(PassBy.VALUE)
      .addCredentialFormat(CredentialFormat.JWT)
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
      hexPrivateKey: '2bbd6a78be9ab2193bcf74aa6d39ab59c1d1e2f7e9ef899a38fb4d94d8aa90e2',
      did: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024',
      didKey: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024#controllerKey',
    };

    const opMockEntity = {
      hexPrivateKey: '73d24dd0fb69abdc12e7a99d8f9a970fdc8ad90598cc64cff35b584220ace0c8',
      did: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca',
      didKey: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca#controllerKey',
    };

    const rp = RP.builder()
      .redirect(EXAMPLE_REDIRECT_URL)
      .requestBy(PassBy.VALUE)
      .internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey)
      .addDidMethod('ethr')
      .registrationBy(PassBy.VALUE)
      .build();
    const op = OP.builder()
      .withExpiresIn(1000)
      .addDidMethod('ethr')
      .internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey)
      .registrationBy(PassBy.VALUE)
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
      hexPrivateKey: '2bbd6a78be9ab2193bcf74aa6d39ab59c1d1e2f7e9ef899a38fb4d94d8aa90e2',
      did: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024',
      didKey: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024#controllerKey',
    };

    const opMockEntity = {
      hexPrivateKey: '73d24dd0fb69abdc12e7a99d8f9a970fdc8ad90598cc64cff35b584220ace0c8',
      did: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca',
      didKey: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca#controllerKey',
    };

    const rp = RP.builder()
      .redirect(EXAMPLE_REDIRECT_URL)
      .requestBy(PassBy.VALUE)
      .internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey)
      .addDidMethod('ethr')
      .registrationBy(PassBy.VALUE)
      .addPresentationDefinitionClaim({
        definition: getPresentationDefinition(),
        location: PresentationLocation.VP_TOKEN,
      })
      .build();
    const op = OP.builder()
      .withExpiresIn(1000)
      .addDidMethod('ethr')
      .internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey)
      .registrationBy(PassBy.VALUE)
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
      hexPrivateKey: '2bbd6a78be9ab2193bcf74aa6d39ab59c1d1e2f7e9ef899a38fb4d94d8aa90e2',
      did: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024',
      didKey: 'did:ethr:goerli:0x038f8d21b0446c46b05aecdc603f73831578e28857adba14de569f31f3e569c024#controllerKey',
    };

    const opMockEntity = {
      hexPrivateKey: '73d24dd0fb69abdc12e7a99d8f9a970fdc8ad90598cc64cff35b584220ace0c8',
      did: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca',
      didKey: 'did:ethr:goerli:0x03a1370d4dd249eabb23245aeb4aec988fbca598ff83db59144d89b3835371daca#controllerKey',
    };

    const rp = RP.builder()
      .redirect(EXAMPLE_REDIRECT_URL)
      .requestBy(PassBy.VALUE)
      .internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey)
      .addDidMethod('ethr')
      .registrationBy(PassBy.VALUE)
      .addPresentationDefinitionClaim({
        definition: getPresentationDefinition(),
        location: PresentationLocation.VP_TOKEN,
      })
      .build();
    const op = OP.builder()
      .withExpiresIn(1000)
      .addDidMethod('ethr')
      .internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey)
      .registrationBy(PassBy.VALUE)
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
    const pd: PresentationDefinitionWithLocation[] = PresentationExchange.findValidPresentationDefinitions(parsedAuthReqURI.requestPayload);
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
});
