import {getResolver as getUniResolver} from "@sphereon/did-uni-client/dist/resolver/Resolver";
import {Resolver} from "did-resolver";

import {SIOP} from "../src";
import {RP} from "../src/RP";
import RPBuilder from "../src/RPBuilder";
import {PassBy, ResponseMode, SubjectIdentifierType} from "../src/types/SIOP.types";


const EXAMPLE_REDIRECT_URL = "https://acme.com/hello";
const EXAMPLE_REFERENCE_URL = "https://rp.acme.com/siop/jwts";
const HEX_KEY = "f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f";
const DID = "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0";
const KID = "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#keys-1";


describe("RP Builder should", () => {
    it("throw Error when no arguments are passed", async () => {
        expect.assertions(1);
        await expect(() => new RPBuilder().build()).toThrowError(Error);
    });
    it("build an RP when all arguments are set", async () => {
        expect.assertions(1);

        expect(RP.builder()
            .addDidMethod('factom')
            .addResolver('ethr', new Resolver(getUniResolver('ethr')))
            .redirect('https://redirect.me')
            .requestBy(PassBy.VALUE)
            .response(ResponseMode.POST)
            .registrationBy(PassBy.REFERENCE, 'https://registration.here')
            .internalSignature('myprivatekye', 'did:example:123', 'did:example:123#key')
            .build()
        )
            .toBeInstanceOf(RP);
    });


});

describe("RP should", () => {
    it("throw Error when build from request opts without enough params", async () => {
        expect.assertions(1);
        await expect(() => RP.fromRequestOpts({} as never)).toThrowError(Error);
    });
    it("return an RP when all request arguments are set", async () => {
        expect.assertions(1);

        const opts = {
            redirectUri: EXAMPLE_REDIRECT_URL,
            requestBy: {
                type: SIOP.PassBy.REFERENCE,
                referenceUri: EXAMPLE_REFERENCE_URL,
            },
            signatureType: {
                hexPrivateKey: HEX_KEY,
                did: DID,
                kid: KID,
            },
            registration: {
                didMethodsSupported: ['did:ethr:'],
                subjectIdentifiersSupported: SubjectIdentifierType.DID,
                registrationBy: {
                    type: SIOP.PassBy.VALUE,
                },
            }
        };

        expect(RP.fromRequestOpts(opts)).toBeInstanceOf(RP);
    });

    it("succeed from request opts when all params are set", async () => {
        // expect.assertions(1);
        const opts = {
            redirectUri: EXAMPLE_REDIRECT_URL,
            requestBy: {
                type: SIOP.PassBy.REFERENCE,
                referenceUri: EXAMPLE_REFERENCE_URL,
            },
            signatureType: {
                hexPrivateKey: HEX_KEY,
                did: DID,
                kid: KID,
            },
            registration: {
                didMethodsSupported: ['did:ethr:'],
                subjectIdentifiersSupported: SubjectIdentifierType.DID,
                registrationBy: {
                    type: SIOP.PassBy.VALUE,
                },
            },

        };


        const expectedPayloadWithoutRequest = {
            "response_type": "id_token",
            "scope": "openid",
            "client_id": "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
            "redirect_uri": "https://acme.com/hello",
            "iss": "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
            "response_mode": "post",
            "response_context": "rp",
            "nonce": "qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg",
            "state": "b32f0087fc9816eb813fd11f",
            "registration": {"did_methods_supported": ["did:ethr:"], "subject_identifiers_supported": "did"}
        };

        const expectedUri = "openid://?response_type=id_token&scope=openid&client_id=did%3Aethr%3A0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0&redirect_uri=https%3A%2F%2Facme.com%2Fhello&iss=did%3Aethr%3A0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0&response_mode=post&response_context=rp&nonce=qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg&state=b32f0087fc9816eb813fd11f&registration=%5Bobject%20Object%5D&request_uri=https%3A%2F%2Frp.acme.com%2Fsiop%2Fjwts";
        const expectedJwtRegex = /^eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXRocjoweDAxMDZhMmU5.*nN1YmplY3RfaWRlbnRpZmllcnNfc3VwcG9ydGVkIjoiZGlkIn19\..*$/;

        const request = await RP.fromRequestOpts(opts).createAuthenticationRequest({
            state: "b32f0087fc9816eb813fd11f",
            nonce: "qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg"
        });
        // console.log(request.jwt);
        expect(request.requestPayload).toMatchObject(expectedPayloadWithoutRequest);
        expect(request.encodedUri).toMatch(expectedUri);
        expect(request.jwt).toMatch(expectedJwtRegex);
    });

    it("succeed from builder when all params are set", async () => {
        const expectedPayloadWithoutRequest = {
            "response_type": "id_token",
            "scope": "openid",
            "client_id": "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
            "redirect_uri": "https://acme.com/hello",
            "iss": "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
            "response_mode": "post",
            "response_context": "rp",
            "nonce": "qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg",
            "state": "b32f0087fc9816eb813fd11f",
            "registration": {"did_methods_supported": ["did:ethr:"], "subject_identifiers_supported": "did"}
        };

        const expectedUri = "openid://?response_type=id_token&scope=openid&client_id=did%3Aethr%3A0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0&redirect_uri=https%3A%2F%2Facme.com%2Fhello&iss=did%3Aethr%3A0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0&response_mode=post&response_context=rp&nonce=qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg&state=b32f0087fc9816eb813fd11f&registration=%5Bobject%20Object%5D&request_uri=https%3A%2F%2Frp.acme.com%2Fsiop%2Fjwts";
        const expectedJwtRegex = /^eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXRocjoweDAxMDZhMmU5.*nN1YmplY3RfaWRlbnRpZmllcnNfc3VwcG9ydGVkIjoiZGlkIn19\..*$/;

        const request = await RP.builder()
            .redirect(EXAMPLE_REDIRECT_URL)
            .requestBy(PassBy.REFERENCE, EXAMPLE_REFERENCE_URL)
            .internalSignature(HEX_KEY, DID, KID)
            .registrationBy(PassBy.VALUE)
            .addDidMethod('ethr')
            .build()

            .createAuthenticationRequest({
            state: "b32f0087fc9816eb813fd11f",
            nonce: "qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg"
        });
        // console.log(request.jwt);
        expect(request.requestPayload).toMatchObject(expectedPayloadWithoutRequest);
        expect(request.encodedUri).toMatch(expectedUri);
        expect(request.jwt).toMatch(expectedJwtRegex);
    });

});
