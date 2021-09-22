import {parse} from "querystring";

import {AuthenticationRequest, SIOP} from "../src";
import SIOPErrors from "../src/types/Errors";
import {SubjectIdentifierType} from "../src/types/SIOP.types";

const EXAMPLE_REDIRECT_URL = "https://acme.com/hello";
const EXAMPLE_REFERENCE_URL = "https://rp.acme.com/siop/jwts";
const HEX_KEY = "f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f";
const DID = "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0";
const KID = "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#keys-1";

describe("create Request Uri should", () => {
    it("throw BAD_PARAMS when no responseOpts is passed", async () => {
        expect.assertions(1);
        await expect(AuthenticationRequest.createURI(undefined as never)).rejects.toThrow(
            SIOPErrors.BAD_PARAMS
        );
    });

    it("throw BAD_PARAMS when no responseOpts.redirectUri is passed", async () => {
        expect.assertions(1);
        const opts = {};
        await expect(AuthenticationRequest.createURI(opts as never)).rejects.toThrow(
            SIOPErrors.BAD_PARAMS
        );
    });

    it("throw BAD_PARAMS when no responseOpts.requestBy is passed", async () => {
        expect.assertions(1);
        const opts = {
            redirectUri: EXAMPLE_REDIRECT_URL,
        };
        await expect(AuthenticationRequest.createURI(opts as never)).rejects.toThrow(
            SIOPErrors.BAD_PARAMS
        );
    });

    it("throw REQUEST_OBJECT_TYPE_NOT_SET when responseOpts.requestBy type is different from REFERENCE or VALUE", async () => {
        expect.assertions(1);
        const opts = {
            redirectUri: EXAMPLE_REDIRECT_URL,
            requestBy: {
                type: "other type",
            },
        };
        await expect(AuthenticationRequest.createURI(opts as never)).rejects.toThrow(
            SIOPErrors.REQUEST_OBJECT_TYPE_NOT_SET
        );
    });

    it("throw NO_REFERENCE_URI when responseOpts.requestBy type is REFERENCE and no referenceUri is passed", async () => {
        expect.assertions(1);
        const opts = {
            redirectUri: EXAMPLE_REDIRECT_URL,
            requestBy: {
                type: SIOP.PassBy.REFERENCE,
            },
        };
        await expect(AuthenticationRequest.createURI(opts as never)).rejects.toThrow(
            SIOPErrors.NO_REFERENCE_URI
        );
    });

    it("return a reference url", async () => {
        expect.assertions(11);
        const opts: SIOP.AuthenticationRequestOpts = {
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

        const uriRequest = await AuthenticationRequest.createURI(opts);
        expect(uriRequest).toBeDefined();
        expect(uriRequest).toHaveProperty("encodedUri");
        expect(uriRequest).toHaveProperty("encodingFormat");

        const uriDecoded = decodeURIComponent(uriRequest.encodedUri);
        expect(uriDecoded).toContain(`openid://`);
        expect(uriDecoded).toContain(`?response_type=${SIOP.ResponseType.ID_TOKEN}`);
        expect(uriDecoded).toContain(`&redirect_uri=${opts.redirectUri}`);
        expect(uriDecoded).toContain(`&scope=${SIOP.Scope.OPENID}`);
        expect(uriDecoded).toContain(`&request_uri=`);

        const data = parse(uriDecoded);
        expect(data.request_uri).toStrictEqual(opts.requestBy.referenceUri);
        expect(uriRequest).toHaveProperty("jwt");
        expect(uriRequest.jwt).toBeDefined();
    });

    it("return a reference url when using did:key", async () => {
        expect.assertions(3);
        const opts: SIOP.AuthenticationRequestOpts = {
            redirectUri: EXAMPLE_REDIRECT_URL,
            requestBy: {
                type: SIOP.PassBy.REFERENCE,
                referenceUri: EXAMPLE_REFERENCE_URL,
            },
            signatureType: {
                hexPrivateKey:
                    "d474ffdb3ea75fbb3f07673e67e52002a3b7eb42767f709f4100acf493c7fc8743017577997b72e7a8b4bce8c32c8e78fd75c1441e95d6aaa888056d1200beb3",
                did: "did:key:z6MkixpejjET5qJK4ebN5m3UcdUPmYV4DPSCs1ALH8x2UCfc",
                kid: "did:key:z6MkixpejjET5qJK4ebN5m3UcdUPmYV4DPSCs1ALH8x2UCfc#keys-1",
            },
            registration: {
                didMethodsSupported: ['did:ethr:'],
                subjectIdentifiersSupported: SubjectIdentifierType.DID,
                registrationBy: {
                    type: SIOP.PassBy.VALUE,
                },
            }
        };

        const uriRequest = await AuthenticationRequest.createURI(opts);
        const uriDecoded = decodeURIComponent(uriRequest.encodedUri);


        const data = parse(uriDecoded);
        expect(data.request_uri).toStrictEqual(opts.requestBy.referenceUri);
        expect(uriRequest).toHaveProperty("jwt");
        expect(uriRequest.jwt).toBeDefined();
    });

    it("return an url with an embedded token value", async () => {
        expect.assertions(2);
        const opts: SIOP.AuthenticationRequestOpts = {
            redirectUri: EXAMPLE_REDIRECT_URL,
            requestBy: {
                type: SIOP.PassBy.VALUE,
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

        const uriRequest = await AuthenticationRequest.createURI(opts);


        const uriDecoded = decodeURIComponent(uriRequest.encodedUri);
        expect(uriDecoded).toContain(`&request=`);

        const data = parse(uriDecoded);
        expect(data.request).toBeDefined();
    });
});

describe("create Request JWT should", () => {
    it("throw REQUEST_OBJECT_TYPE_NOT_SET when requestBy type is different from REFERENCE and VALUE", async () => {
        expect.assertions(1);
        const opts = {
            redirectUri: EXAMPLE_REDIRECT_URL,
            requestBy: {
                type: "other type",
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
        await expect(AuthenticationRequest.createJWT(opts as never)).rejects.toThrow(
            SIOPErrors.REQUEST_OBJECT_TYPE_NOT_SET
        );
    });

    it("throw NO_REFERENCE_URI when no referenceUri is passed with REFERENCE requestBy type is set", async () => {
        expect.assertions(1);
        const opts = {
            redirectUri: EXAMPLE_REDIRECT_URL,
            requestBy: {
                type: SIOP.PassBy.REFERENCE,
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
        await expect(AuthenticationRequest.createJWT(opts as never)).rejects.toThrow(
            SIOPErrors.NO_REFERENCE_URI
        );
    });

    it("throw BAD_SIGNATURE_PARAMS when signature Type is neither internal nor external", async () => {
        expect.assertions(1);
        const opts = {
            redirectUri: EXAMPLE_REDIRECT_URL,
            requestBy: {
                type: SIOP.PassBy.REFERENCE,
                referenceUri: EXAMPLE_REFERENCE_URL,
            },
            signatureType: {},
            registration: {
                didMethodsSupported: ['did:ethr:'],
                subjectIdentifiersSupported: SubjectIdentifierType.DID,
                registrationBy: {
                    type: SIOP.PassBy.VALUE,
                },
            }
        };
        await expect(AuthenticationRequest.createJWT(opts as never)).rejects.toThrow(
            SIOPErrors.BAD_SIGNATURE_PARAMS
        );
    });

    it("throw REGISTRATION_OBJECT_TYPE_NOT_SET when registrationBy type is neither REFERENCE nor VALUE", async () => {
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
                    type: 'FAILURE'
                }
            }
        };
        await expect(AuthenticationRequest.createJWT(opts as never)).rejects.toThrow(
            SIOPErrors.REGISTRATION_OBJECT_TYPE_NOT_SET
        );
    });

    it("throw NO_REFERENCE_URI when registrationBy type is REFERENCE and no referenceUri is passed", async () => {
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
                    type: SIOP.PassBy.REFERENCE,
                },
            }
        };
        await expect(AuthenticationRequest.createJWT(opts as never)).rejects.toThrow(
            SIOPErrors.NO_REFERENCE_URI
        );
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
            }
        };


        const expected = {
            "payload": {
                "response_type": "id_token",
                "scope": "openid",
                "client_id": "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
                "redirect_uri": "https://acme.com/hello",
                "iss": "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
                "response_mode": "post",
                "response_context": "rp",
                "registration": {"did_methods_supported": ["did:ethr:"], "subject_identifiers_supported": "did"}
            },
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
                }
            }
        };

        AuthenticationRequest.createURI(opts)
            .then(uri => console.log(uri.encodedUri));
        await expect(AuthenticationRequest.createJWT(opts)).resolves.toMatchObject(expected);
    });
});
