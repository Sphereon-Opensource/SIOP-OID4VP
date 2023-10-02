import * as ed25519 from '@transmute/did-key-ed25519';
import * as u8a from 'uint8arrays';
import { fetch } from 'cross-fetch';
import { JWK } from 'jose';

import { AuthorizationRequest, OP, VerificationMode } from '../../src';

export interface InitiateOfferRequest {
  types: string[];
}

export interface InitiateOfferResponse {
  authorizeRequestUri: string;
  state: string;
  nonce: string;
}

export const UNIT_TEST_TIMEOUT = 30000;

export const VP_CREATE_URL = 'https://launchpad.mattrlabs.com/api/vp/create';

export const jwk: JWK = {
  crv: 'Ed25519',
  d: 'kTRm0aONHYwNPA-w_DtjMHUIWjE3K70qgCIhWojZ0eU',
  x: 'NeA0d8sp86xRh3DczU4m5wPNIbl0HCSwOBcMN3sNmdk',
  kty: 'OKP'
};

// pub  hex: 35e03477cb29f3ac518770dccd4e26e703cd21b9741c24b038170c377b0d99d9
// priv hex: 913466d1a38d1d8c0d3c0fb0fc3b633075085a31372bbd2a8022215a88d9d1e5

const didStr = `did:key:z6Mki5ZwZKN1dBQprfJTikUvkDxrHijiiQngkWviMF5gw2Hv`;
const kid = `${didStr}#z6Mki5ZwZKN1dBQprfJTikUvkDxrHijiiQngkWviMF5gw2Hv`;
console.log(kid);
export const generateDid = async (opts?: { seed?: Uint8Array }) => {
  const { didDocument, keys } = await ed25519.generate(
    {
      secureRandom: () => {
        return opts?.seed ?? '913466d1a38d1d8c0d3c0fb0fc3b633075085a31372bbd2a8022215a88d9d1e5';
      }
    },
    { accept: 'application/did+json' }
  );

  return { keys, didDocument };
};


describe('OID4VCI-Client using Mattr issuer should', () => {
  async function test(format: string | string[]) {
    const did = await generateDid({ seed: u8a.fromString('913466d1a38d1d8c0d3c0fb0fc3b633075085a31372bbd2a8022215a88d9d1e5', 'base16') });
    expect(did).toBeDefined();
    expect(did.didDocument).toBeDefined();

    const offer = await getOffer(format);
    const { authorizeRequestUri, state, nonce } = offer;
    expect(authorizeRequestUri).toBeDefined();
    expect(state).toBeDefined();
    expect(nonce).toBeDefined();

    const auth = await AuthorizationRequest.verify(authorizeRequestUri, {
      correlationId: 'test', verification: {
        mode: VerificationMode.INTERNAL,
        resolveOpts: {}
      }
    });
    expect(auth).toBeDefined()
    expect(auth.presentationDefinitions).toHaveLength(1)


    OP.builder().addDidMethod('key');
  }

  it(
    'succeed in a full flow with the client using OpenID4VCI version 11 and ldp_vc',
    async () => {
      await test('OpenBadgeCredential');
    },
    UNIT_TEST_TIMEOUT
  );
  xit(
    'succeed in a full flow with the client using OpenID4VCI version 11 and jwt_vc_json',
    async () => {
      await test('jwt_vc_json');
    },
    UNIT_TEST_TIMEOUT
  );
});


async function getOffer(types: string | string[]): Promise<InitiateOfferResponse> {
  const credentialOffer = await fetch(VP_CREATE_URL, {
    method: 'post',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json'
    },

    //make sure to serialize your JSON body
    body: JSON.stringify({
      types: Array.isArray(types) ? types : [types]
    })
  });

  return (await credentialOffer.json()) as InitiateOfferResponse;
}

/*
async function proofOfPossessionCallbackFunction(args: Jwt, kid?: string): Promise<string> {
  const importedJwk = await importJWK(jwk, 'EdDSA');
  return await new SignJWT({ ...args.payload })
    .setProtectedHeader({ ...args.header })
    .setIssuedAt()
    .setExpirationTime('2h')
    .sign(importedJwk);
}
*/
