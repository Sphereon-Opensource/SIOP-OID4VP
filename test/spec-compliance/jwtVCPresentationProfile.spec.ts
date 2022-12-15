import * as jose from 'jose';
import { KeyLike } from 'jose';
import * as u8a from 'uint8arrays';

import { PassBy, PropertyTarget, ResponseMode, ResponseType, RP, SigningAlgo, SupportedVersion } from '../../src/main';

class TestVectors {
  public static issuerJwk = {
    kty: 'OKP',
    d: 'CflJV2c1K-02KpESNMWGkVruE04F4KXiZcnCV0CDgQM',
    crv: 'Ed25519',
    kid: 'key-1',
    x: 'bsSpFHabZFrOBUO-UrXiVcUcdpae8XotdXgVqomaZ5Y',
  };
  public static request_uri = 'https://example/service/api/v1/presentation-request/8006b5fb-6e3b-42d1-a2be-55ed2a08073d';
  public static did =
    'did:ion:EiDXRE6GPp716GZvx404LFygQoWshiIqhOFNFBZqoZtD3g:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkFzMXNXd3RsTHdRUTgwMElLdC00aEZTMXRKcV9jeDBkSGFmODJUTTJMWUUiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUJRWHBqSk9vQ0dpVFp6NVd3ZkE3Y3BqNzFaeG9ZUTQ0cjI1S1NGSEFtZHFRIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlDcEt6cEdrWlNadnRVMG1ETE1QZUZSNHJ4SzlralJVaWFLenluZ3JZd2xVZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQ3NfQjVHdEczemR4Vm9wNTdxWlRjb3AzMVRDRDFuVFVXWmxfVFJ5VXlMNncifX0';
  public static kid = `${TestVectors.did}#key-1`;
}

const privateKey = u8a.toString(u8a.fromString(TestVectors.issuerJwk.d, 'base64url'), 'hex');
const publicKey = u8a.toString(u8a.fromString(TestVectors.issuerJwk.x, 'base64url'), 'hex');

const hexPrivateKey = `${privateKey}${publicKey}`;
describe('RP', () => {
  it('should create auth request URI', async () => {
    const key = (await jose.importJWK(TestVectors.issuerJwk, 'ES256', true)) as KeyLike;
    console.log(JSON.stringify(key));

    // expect.assertions(1);

    const rp = RP.builder({ requestVersion: SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1 })
      .withResponseType(ResponseType.ID_TOKEN, PropertyTarget.REQUEST_OBJECT)
      .withClientId(TestVectors.did, PropertyTarget.REQUEST_OBJECT)
      .withScope('openid', PropertyTarget.REQUEST_OBJECT)
      .withResponseMode(ResponseMode.POST, PropertyTarget.REQUEST_OBJECT)
      .withClientMetadata(
        {
          passBy: PassBy.VALUE,
          logoUri: 'https://example.com/verifier-icon.png',
          tos_uri: 'https://example.com/verifier-info',
          clientName: 'Example Verifier',
          vp_formats: {
            jwt_vc: {
              alg: ['EdDSA', 'ES256K'],
            },
            jwt_vp: {
              alg: ['EdDSA', 'ES256K'],
            },
          },
          subjectSyntaxTypesSupported: ['did:ion'],
        },
        PropertyTarget.REQUEST_OBJECT
      )
      .withRedirectUri('https://example.com/siop-response', PropertyTarget.REQUEST_OBJECT)
      .withRequestBy(PassBy.REFERENCE, TestVectors.request_uri)
      .addDidMethod('ion')
      .withInternalSignature(hexPrivateKey, TestVectors.did, TestVectors.kid, SigningAlgo.EDDSA)

      .build();
    console.log(rp);

    const authRequuest = await rp.createAuthorizationRequest({
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
    console.log(JSON.stringify(authRequuest.payload, null, 2));

    const uri = await authRequuest.uri();

    console.log(JSON.stringify(uri.encodedUri));
  });
});
