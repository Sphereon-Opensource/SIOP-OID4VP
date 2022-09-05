import { getUniResolver } from '@sphereon/did-uni-client';
import { IProofType } from '@sphereon/ssi-types';
import { Resolver } from 'did-resolver';

import {
  AuthenticationRequestOpts,
  CheckLinkedDomain,
  PassBy,
  ResponseMode,
  ResponseType,
  RP,
  RPBuilder,
  Scope,
  SigningAlgo,
  SubjectIdentifierType,
  SubjectType,
} from '../src/main';

const EXAMPLE_REDIRECT_URL = 'https://acme.com/hello';
const EXAMPLE_REFERENCE_URL = 'https://rp.acme.com/siop/jwts';
const HEX_KEY = 'f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f';
const DID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0';
const KID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#keys-1';

describe('RP Builder should', () => {
  it('throw Error when no arguments are passed', async () => {
    expect.assertions(1);
    await expect(() => new RPBuilder().build()).toThrowError(Error);
  });

  it('build an RP when all arguments are set', async () => {
    expect.assertions(1);

    expect(
      RP.builder()
        .withCheckLinkedDomain(CheckLinkedDomain.NEVER)
        .addDidMethod('factom')
        .addResolver('ethr', new Resolver(getUniResolver('ethr')))
        .redirect('https://redirect.me')
        .requestBy(PassBy.VALUE)
        .response(ResponseMode.POST)
        .registrationBy({
          registrationBy: {
            type: PassBy.REFERENCE,
            referenceUri: 'https://registration.here',
          },
        })
        .internalSignature('myprivatekye', 'did:example:123', 'did:example:123#key')
        .build()
    ).toBeInstanceOf(RP);
  });
});

describe('RP should', () => {
  it('throw Error when build from request opts without enough params', async () => {
    expect.assertions(1);
    await expect(() => RP.fromRequestOpts({} as never)).toThrowError(Error);
  });
  it('return an RP when all request arguments are set', async () => {
    expect.assertions(1);

    const opts: AuthenticationRequestOpts = {
      checkLinkedDomain: CheckLinkedDomain.NEVER,
      redirectUri: EXAMPLE_REDIRECT_URL,
      requestBy: {
        type: PassBy.REFERENCE,
        referenceUri: EXAMPLE_REFERENCE_URL,
      },
      signatureType: {
        hexPrivateKey: HEX_KEY,
        did: DID,
        kid: KID,
      },
      registration: {
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        vpFormatsSupported: {
          jwt_vc: { alg: [SigningAlgo.EDDSA, SigningAlgo.ES256K, SigningAlgo.ES256] },
          jwt_vp: { alg: [SigningAlgo.EDDSA, SigningAlgo.ES256K, SigningAlgo.ES256] },
          jwt: { alg: [SigningAlgo.EDDSA, SigningAlgo.ES256K, SigningAlgo.ES256] },
        },
        registrationBy: {
          type: PassBy.VALUE,
        },
      },
    };

    expect(RP.fromRequestOpts(opts)).toBeInstanceOf(RP);
  });

  it('succeed from request opts when all params are set', async () => {
    // expect.assertions(1);
    const opts: AuthenticationRequestOpts = {
      checkLinkedDomain: CheckLinkedDomain.NEVER,
      redirectUri: EXAMPLE_REDIRECT_URL,
      requestBy: {
        type: PassBy.REFERENCE,
        referenceUri: EXAMPLE_REFERENCE_URL,
      },
      signatureType: {
        hexPrivateKey: HEX_KEY,
        did: DID,
        kid: KID,
      },
      registration: {
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        subjectSyntaxTypesSupported: ['did:ethr:', SubjectIdentifierType.DID],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        vpFormatsSupported: {
          jwt_vc: { alg: [SigningAlgo.EDDSA, SigningAlgo.ES256K, SigningAlgo.ES256] },
          jwt_vp: { alg: [SigningAlgo.EDDSA, SigningAlgo.ES256K, SigningAlgo.ES256] },
          jwt: { alg: [SigningAlgo.EDDSA, SigningAlgo.ES256K, SigningAlgo.ES256] },
          ldp_vc: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
        },
        registrationBy: {
          type: PassBy.VALUE,
        },
      },
    };

    const expectedPayloadWithoutRequest = {
      response_type: 'id_token',
      scope: 'openid',
      client_id: 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0',
      redirect_uri: 'https://acme.com/hello',
      iss: 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0',
      response_mode: 'post',
      response_context: 'rp',
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      state: 'b32f0087fc9816eb813fd11f',
      registration: {
        id_token_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        request_object_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        response_types_supported: [ResponseType.ID_TOKEN],
        scopes_supported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subject_syntax_types_supported: ['did:ethr:', 'did'],
        subject_types_supported: [SubjectType.PAIRWISE],
        vp_formats: {
          jwt: {
            alg: ['EdDSA', 'ES256K', 'ES256'],
          },
          jwt_vc: {
            alg: ['EdDSA', 'ES256K', 'ES256'],
          },
        },
      },
    };

    const expectedUri =
      'openid://?response_type=id_token&scope=openid&client_id=did%3Aethr%3A0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0&redirect_uri=https%3A%2F' +
      '%2Facme.com%2Fhello&iss=did%3Aethr%3A0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0&response_mode=post&response_context=rp&nonce=qBrR7mqnY' +
      '3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg&state=b32f0087fc9816eb813fd11f&registration=%7B%22id_token_signing_alg_values_supported%22%3A%5B%22' +
      'EdDSA%22%2C%22ES256%22%5D%2C%22request_object_signing_alg_values_supported%22%3A%5B%22EdDSA%22%2C%22ES256%22%5D%2C%22response_types_su' +
      'pported%22%3A%5B%22id_token%22%5D%2C%22scopes_supported%22%3A%5B%22openid%20did_authn%22%2C%22openid%22%5D%2C%22subject_types_supporte' +
      'd%22%3A%5B%22pairwise%22%5D%2C%22subject_syntax_types_supported%22%3A%5B%22did%3Aethr%3A%22%2C%22did%22%5D%2C%22vp_formats%22%3A%7B%22' +
      'jwt_vc%22%3A%7B%22alg%22%3A%5B%22EdDSA%22%2C%22ES256K%22%2C%22ES256%22%5D%7D%2C%22jwt_vp%22%3A%7B%22alg%22%3A%5B%22EdDSA%22%2C%22ES256' +
      'K%22%2C%22ES256%22%5D%7D%2C%22jwt%22%3A%7B%22alg%22%3A%5B%22EdDSA%22%2C%22ES256K%22%2C%22ES256%22%5D%7D%2C%22ldp_vc%22%3A%7B%22proof_t' +
      'ype%22%3A%5B%22EcdsaSecp256k1Signature2019%22%2C%22EcdsaSecp256k1Signature2019%22%5D%7D%7D%7D&request_uri=https%3A%2F%2Frp.acme.com%2F' +
      'siop%2Fjwts';
    const expectedJwtRegex =
      /^eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXRocjoweDAxMDZhMmU5ODViMUUxRGU5QjVkZGI0YUY2ZEM5ZTkyOEY0ZTk5RDAja2V5cy0xIiwidHlwIjoiSldUIn0\.ey.*$/;

    const request = await RP.fromRequestOpts(opts).createAuthenticationRequest({
      state: 'b32f0087fc9816eb813fd11f',
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
    });
    expect(request.requestPayload).toMatchObject(expectedPayloadWithoutRequest);
    expect(request.encodedUri).toMatch(expectedUri);
    expect(request.jwt).toMatch(expectedJwtRegex);
  });

  it('succeed from builder when all params are set', async () => {
    const expectedPayloadWithoutRequest = {
      claims: undefined,
      client_id: 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0',
      iss: 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0',
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      redirect_uri: 'https://acme.com/hello',
      registration: {
        id_token_signing_alg_values_supported: [SigningAlgo.EDDSA],
        request_object_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        response_types_supported: [ResponseType.ID_TOKEN],
        scopes_supported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subject_syntax_types_supported: ['did:ethr:'],
        subject_types_supported: [SubjectType.PAIRWISE],
        vp_formats: {
          jwt: {
            alg: ['EdDSA', 'ES256K', 'ES256'],
          },
          jwt_vc: {
            alg: ['EdDSA', 'ES256K', 'ES256'],
          },
          jwt_vp: {
            alg: ['EdDSA', 'ES256K', 'ES256'],
          },
        },
      },
    };

    const expectedUri =
      'openid://?response_type=id_token&scope=openid&client_id=did%3Aethr%3A0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0&redirect_uri=https%3A%2F%2F' +
      'acme.com%2Fhello&iss=did%3Aethr%3A0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0&response_mode=post&response_context=rp&nonce=qBrR7mqnY3Qr49d' +
      'AZycPF8FzgE83m6H0c2l0bzP4xSg&state=b32f0087fc9816eb813fd11f&registration=%7B%22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%' +
      '5D%2C%22request_object_signing_alg_values_supported%22%3A%5B%22EdDSA%22%2C%22ES256%22%5D%2C%22response_types_supported%22%3A%5B%22id_toke' +
      'n%22%5D%2C%22scopes_supported%22%3A%5B%22openid%20did_authn%22%2C%22openid%22%5D%2C%22subject_types_supported%22%3A%5B%22pairwise%22%5D%2' +
      'C%22subject_syntax_types_supported%22%3A%5B%22did%3Aethr%3A%22%5D%2C%22vp_formats%22%3A%7B%22jwt%22%3A%7B%22alg%22%3A%5B%22EdDSA%22%2C%22' +
      'ES256K%22%2C%22ES256%22%5D%7D%2C%22jwt_vc%22%3A%7B%22alg%22%3A%5B%22EdDSA%22%2C%22ES256K%22%2C%22ES256%22%5D%7D%2C%22jwt_vp%22%3A%7B%22al' +
      'g%22%3A%5B%22EdDSA%22%2C%22ES256K%22%2C%22ES256%22%5D%7D%7D%7D&request_uri=https%3A%2F%2Frp.acme.com%2Fsiop%2Fjwts';
    const expectedJwtRegex =
      /^eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXRocjoweDAxMDZhMmU5ODViMUUxRGU5QjVkZGI0YUY2ZEM5ZTkyOEY0ZTk5RDAja2V5cy0xIiwidHlwIjoiSldUIn0\.eyJpYXQiO.*$/;

    const request = await RP.builder()
      .withCheckLinkedDomain(CheckLinkedDomain.NEVER)
      .redirect(EXAMPLE_REDIRECT_URL)
      .requestBy(PassBy.REFERENCE, EXAMPLE_REFERENCE_URL)
      .internalSignature(HEX_KEY, DID, KID)
      .registrationBy({
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormatsSupported: {
          jwt: {
            alg: ['EdDSA', 'ES256K', 'ES256'],
          },
          jwt_vc: {
            alg: ['EdDSA', 'ES256K', 'ES256'],
          },
          jwt_vp: {
            alg: ['EdDSA', 'ES256K', 'ES256'],
          },
        },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subjectSyntaxTypesSupported: [],
        registrationBy: { type: PassBy.VALUE },
      })
      .addDidMethod('ethr')
      .build()

      .createAuthenticationRequest({
        state: 'b32f0087fc9816eb813fd11f',
        nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      });
    expect(request.requestPayload).toMatchObject(expectedPayloadWithoutRequest);
    expect(request.encodedUri).toMatch(expectedUri);
    expect(request.jwt).toMatch(expectedJwtRegex);
  });
});
