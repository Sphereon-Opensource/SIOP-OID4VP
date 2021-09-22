import {OP} from "../src";
import {RP} from "../src/RP";
import {PassBy} from "../src/types/SIOP.types";

import {mockedGetEnterpriseAuthToken} from "./TestUtils";


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
            .build();
        const op = OP.builder()
            .withDid(opMockEntity.did)
            .withExpiresIn(1000)
            .addDidMethod("ethr")
            .internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did)
            .registrationBy(PassBy.VALUE)
            .build();

        const requestURI = await rp.createAuthenticationRequest({
            nonce: "qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg",
            state: "b32f0087fc9816eb813fd11f"
        });

        // The create method also calls the verifyRequest method, so no need to do it manually
        const authenticationResponseWithJWT = await op.createAuthenticationResponse(requestURI.jwt);

        const verifiedAuthResponseWithJWT = await rp.verifyAuthenticationResponseJwt(authenticationResponseWithJWT.jwt, {
            audience: EXAMPLE_REDIRECT_URL,
        })

        expect(verifiedAuthResponseWithJWT.jwt).toBeDefined();
        expect(verifiedAuthResponseWithJWT.payload.state).toMatch("b32f0087fc9816eb813fd11f");
        expect(verifiedAuthResponseWithJWT.payload.nonce).toMatch("qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg");
    });
});
