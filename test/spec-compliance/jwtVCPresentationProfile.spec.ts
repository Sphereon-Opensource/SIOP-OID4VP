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
    'did:ion:EiBWe9RtHT7VZ-Juff8OnnJAyFJtCokcYHx1CQkFtpl7pw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkNfT1VKeEg2aUljQzZYZE5oN0ptQy1USFhBVmFYbnZ1OU9FRVo4dHE5TkkiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUNYTkJqSWZMVGZOV0NHMFQ2M2VaYmJEZFZoSmJUTjgtSmZlaUx4dW1oZW53In0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlCZVZ5RXBDb0NPeXJ6VDhDSHlvQW1acU1CT1o0VTZqcm1sdUt1SjlxS0pkZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQnhkcHlyamlVSFZ1akNRWTBKMkhBUFFYZnNwWFBKYWluV21mV3RNcFhneFEifX0';
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
          // targets: [PropertyTarget.REQUEST_OBJECT],
          logo_uri: 'https://example.com/verifier-icon.png',
          tos_uri: 'https://example.com/verifier-info',
          clientName: 'Example Verifier',
          vpFormatsSupported: {
            jwt_vc: {
              alg: ['EdDSA', 'ES256K'],
            },
            jwt_vp: {
              alg: ['EdDSA', 'ES256K'],
            },
          },
          subject_syntax_types_supported: ['did:ion'],
        },
        PropertyTarget.REQUEST_OBJECT
      )
      .withRedirectUri('https://example.com/siop-response', PropertyTarget.REQUEST_OBJECT)
      .withRequestBy(PassBy.REFERENCE, TestVectors.request_uri)
      .addDidMethod('ion')
      .withInternalSignature(hexPrivateKey, TestVectors.did, TestVectors.kid, SigningAlgo.EDDSA)

      .build();
    console.log(JSON.stringify(rp, null, 2));

    const authRequest = await rp.createAuthorizationRequest({
      nonce: { propertyValue: '40252afc-6a82-4a2e-905f-e41f122ef575', targets: PropertyTarget.REQUEST_OBJECT },
      state: { propertyValue: '649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9', targets: PropertyTarget.REQUEST_OBJECT },
      claims: {
        propertyValue: {
          vp_token: {
            presentation_definition: {
              input_descriptors: [
                {
                  schema: [
                    {
                      uri: 'VerifiedEmployee',
                    },
                  ],
                  purpose: 'We need to verify that you have a valid VerifiedEmployee Verifiable Credential.',
                  name: 'VerifiedEmployeeVC',
                  id: 'VerifiedEmployeeVC',
                },
              ],
              id: '649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9',
            },
          },
        },
        targets: PropertyTarget.REQUEST_OBJECT,
      },
    });
    console.log('AuthReq Payload: ' + JSON.stringify(authRequest.payload, null, 2));

    console.log('Request Object Payload: ' + JSON.stringify(await authRequest.requestObject.getPayload(), null, 2));

    expect(await authRequest.requestObject.getPayload()).toEqual({
      response_type: 'id_token',
      nonce: '40252afc-6a82-4a2e-905f-e41f122ef575',
      client_id:
        'did:ion:EiBWe9RtHT7VZ-Juff8OnnJAyFJtCokcYHx1CQkFtpl7pw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkNfT1VKeEg2aUljQzZYZE5oN0ptQy1USFhBVmFYbnZ1OU9FRVo4dHE5TkkiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUNYTkJqSWZMVGZOV0NHMFQ2M2VaYmJEZFZoSmJUTjgtSmZlaUx4dW1oZW53In0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlCZVZ5RXBDb0NPeXJ6VDhDSHlvQW1acU1CT1o0VTZqcm1sdUt1SjlxS0pkZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQnhkcHlyamlVSFZ1akNRWTBKMkhBUFFYZnNwWFBKYWluV21mV3RNcFhneFEifX0',
      response_mode: 'post',
      // "nbf" : 1674772063,
      scope: 'openid',
      claims: {
        vp_token: {
          presentation_definition: {
            input_descriptors: [
              {
                schema: [
                  {
                    uri: 'VerifiedEmployee',
                  },
                ],
                purpose: 'We need to verify that you have a valid VerifiedEmployee Verifiable Credential.',
                name: 'VerifiedEmployeeVC',
                id: 'VerifiedEmployeeVC',
              },
            ],
            id: '649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9',
          },
        },
      },
      registration: {
        logo_uri: 'https://example.com/verifier-icon.png',
        tos_uri: 'https://example.com/verifier-info',
        client_name: 'Example Verifier',
        vp_formats: {
          jwt_vc: {
            alg: ['EdDSA', 'ES256K'],
          },
          jwt_vp: {
            alg: ['EdDSA', 'ES256K'],
          },
        },
        subject_syntax_types_supported: ['did:ion'],
      },
      state: '649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9',
      redirect_uri: 'https://example.com/siop-response' /*,
        "exp" : 1674775663,
        "iat" : 1674772063,
        "jti" : "f0e6dcf5-3fe6-4507-adc9-b496daf34512"*/,
    });

    const uri = await authRequest.uri();

    console.log(JSON.stringify(uri.encodedUri));
  });
});
