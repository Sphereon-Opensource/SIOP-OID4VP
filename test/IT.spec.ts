import nock from "nock";

import { OP } from '../src';
import { RP } from '../src/RP';
import { CredentialFormat, PassBy } from '../src/types/SIOP.types';

import { mockedGetEnterpriseAuthToken } from './TestUtils';


const EXAMPLE_REDIRECT_URL = "https://acme.com/hello";
const EXAMPLE_REFERENCE_URL = "https://rp.acme.com/siop/jwts";



describe("RP and OP interaction should", () => {
    it("succeed when calling each other in the full flow", async () => {
        // expect.assertions(1);
        const rpMockEntity = await mockedGetEnterpriseAuthToken("ACME RP");
        const opMockEntity = await mockedGetEnterpriseAuthToken("ACME OP");

        const rp = RP.builder()
            .redirect(EXAMPLE_REDIRECT_URL)
            .requestBy(PassBy.REFERENCE, EXAMPLE_REFERENCE_URL)
            .internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, `${rpMockEntity.did}#controller`)
            .addDidMethod("ethr")
            .registrationBy(PassBy.VALUE)
            .addCredentialFormat(CredentialFormat.JWT)
            .build();
        const op = OP.builder()
            .withExpiresIn(1000)
            .addDidMethod("ethr")
            .internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, `${opMockEntity.did}#controller`)
            .registrationBy(PassBy.VALUE)
            .addCredentialFormat(CredentialFormat.JWT)
            .build();

        const requestURI = await rp.createAuthenticationRequest({
            nonce: "qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg",
            state: "b32f0087fc9816eb813fd11f"
        });

        nock("https://rp.acme.com/siop/jwts").get(/.*/).reply( 200, requestURI.jwt);

        // The create method also calls the verifyRequest method, so no need to do it manually
        const authenticationResponseWithJWT = await op.createAuthenticationResponse(requestURI.encodedUri);

        const verifiedAuthResponseWithJWT = await rp.verifyAuthenticationResponseJwt(authenticationResponseWithJWT.jwt, {
            audience: EXAMPLE_REDIRECT_URL,
        })

        expect(verifiedAuthResponseWithJWT.jwt).toBeDefined();
        expect(verifiedAuthResponseWithJWT.payload.state).toMatch("b32f0087fc9816eb813fd11f");
        expect(verifiedAuthResponseWithJWT.payload.nonce).toMatch("qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg");
    });
});



describe("RP and OP interaction should", () => {
    it("succeed when calling optional steps in the full flow", async () => {
        // expect.assertions(1);
        const rpMockEntity = {hexPrivateKey: 'a1458fac9ea502099f40be363ad3144d6d509aa5aa3d17158a9e6c3b67eb0397', did: 'did:ethr:ropsten:0x028360fb95417724cb7dd2ff217b15d6f17fc45e0ffc1b3dce6c2b8dd1e704fa98', didKey: 'did:ethr:ropsten:0x028360fb95417724cb7dd2ff217b15d6f17fc45e0ffc1b3dce6c2b8dd1e704fa98#controller'}

        const opMockEntity = {hexPrivateKey: '88a62d50de38dc22f5b4e7cc80d68a0f421ea489dda0e3bd5c165f08ce46e666', did: 'did:ethr:ropsten:0x03f8b96c88063da2b7f5cc90513560a7ec38b92616fff9c95ae95f46cc692a7c75', didKey: 'did:ethr:ropsten:0x03f8b96c88063da2b7f5cc90513560a7ec38b92616fff9c95ae95f46cc692a7c75#controller'}

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

        const requestURI = await rp.createAuthenticationRequest({
            nonce: "qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg",
            state: "b32f0087fc9816eb813fd11f"
        });


        // Let's test the parsing
        const parsedAuthReqURI = await op.parseAuthenticationRequestURI(requestURI.encodedUri);
        expect(parsedAuthReqURI.requestPayload).toBeDefined();
        expect(parsedAuthReqURI.jwt).toBeDefined();
        expect(parsedAuthReqURI.registration).toBeDefined();

        const verifiedAuthReqWithJWT = await op.verifyAuthenticationRequest(parsedAuthReqURI.jwt);
        expect(verifiedAuthReqWithJWT.signer).toBeDefined();
        expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did);

        const authenticationResponseWithJWT = await op.createAuthenticationResponseFromVerifiedRequest(verifiedAuthReqWithJWT);
        expect(authenticationResponseWithJWT.payload).toBeDefined();



        const verifiedAuthResponseWithJWT = await rp.verifyAuthenticationResponseJwt(authenticationResponseWithJWT.jwt, {
            audience: EXAMPLE_REDIRECT_URL,
        })

        expect(verifiedAuthResponseWithJWT.jwt).toBeDefined();
        expect(verifiedAuthResponseWithJWT.payload.state).toMatch("b32f0087fc9816eb813fd11f");
        expect(verifiedAuthResponseWithJWT.payload.nonce).toMatch("qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg");
    });
});