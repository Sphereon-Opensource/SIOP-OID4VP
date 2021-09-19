import {getResolver as getUniResolver} from "@sphereon/did-uni-client/dist/resolver/Resolver";
import {Resolver} from "did-resolver";

import {RP} from "../src/RP";
import {PassBy, ResponseMode, SubjectIdentifierType} from "../src/types/SIOP.types";
import {SIOP} from "../src";


const EXAMPLE_REDIRECT_URL = "https://acme.com/hello";
const EXAMPLE_REFERENCE_URL = "https://rp.acme.com/siop/jwts";
const HEX_KEY = "f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f";
const DID = "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0";
const KID = "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#keys-1";


describe("RP Builder should", () => {
    it("throw Error when no arguments are passed", async () => {
        expect.assertions(1);
        await expect(() => new RP.Builder().build()).toThrowError(Error);
    });
    it("build an RP when all arguments are set", async () => {
        expect.assertions(1);

        expect(new RP.Builder()
            .addDidMethod('factom')
            .addResolver('ethr', new Resolver(getUniResolver('ethr')))
            .redirect('https://redirect.me')
            .requestRef(PassBy.VALUE)
            .response(ResponseMode.POST)
            .registrationRef(PassBy.REFERENCE, 'https://registration.here')
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

    it("succeed when all params are set", async () => {
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


        const expected = {
            "encodedUri": "openid://?response_type=id_token&scope=openid&client_id=did%3Aethr%3A0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0&redirect_uri=https%3A%2F%2Facme.com%2Fhello&iss=did%3Aethr%3A0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0&response_mode=post&response_context=rp&nonce=qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg&state=b32f0087fc9816eb813fd11f&registration=%5Bobject%20Object%5D&request_uri=https%3A%2F%2Frp.acme.com%2Fsiop%2Fjwts",
            "encodingFormat": "application/x-www-form-urlencoded",
            "opts": {
                "redirectUri": "https://acme.com/hello",
                "requestBy": {"type": "REFERENCE", "referenceUri": "https://rp.acme.com/siop/jwts"},
                "signatureType": {
                    "hexPrivateKey": "f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f",
                    "did": "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
                    "kid": "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#keys-1"
                },
                "registration": {
                    "didMethodsSupported": ["did:ethr:"],
                    "subjectIdentifiersSupported": "did",
                    "registrationBy": {"type": "VALUE"}
                },
                "state": "b32f0087fc9816eb813fd11f",
                "nonce": "qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg"
            },
        };

        await expect(RP.fromRequestOpts(opts).createAuthenticationRequest({
            state: "b32f0087fc9816eb813fd11f",
            nonce: "qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg"
        })).resolves.toMatchObject(expected);
    });

});
