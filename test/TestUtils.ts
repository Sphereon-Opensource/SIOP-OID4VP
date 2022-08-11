import crypto from 'crypto';

// import { DidKeyDriver } from '@digitalcredentials/did-method-key'
import { ProofType } from '@sphereon/pex';
import base58 from 'bs58';
import { DIDDocument } from 'did-resolver';
import { ethers } from 'ethers';
import fromKeyLike from 'jose/jwk/from_key_like';
import parseJwk from 'jose/jwk/parse';
import SignJWT from 'jose/jwt/sign';
import { JWK, JWTPayload } from 'jose/types';
import jwt_decode from 'jwt-decode';
import moment from 'moment';
import { v4 as uuidv4 } from 'uuid';

import { SIOP } from '../src/main';
import { assertValidMetadata } from '../src/main/functions/DidSiopMetadata';
import { base64ToHexString } from '../src/main/functions/Encodings';
import SIOPErrors from '../src/main/types/Errors';
import {
  DiscoveryMetadataPayload,
  ResponseIss,
  ResponseType,
  RPRegistrationMetadataPayload,
  Scope,
  SigningAlgo,
  SubjectIdentifierType,
  SubjectType,
} from '../src/main/types/SIOP.types';

import { DID_DOCUMENT_PUBKEY_B58, DID_DOCUMENT_PUBKEY_JWK } from './data/mockedData';

export interface TESTKEY {
  key: JWK;
  did: string;
  didDoc?: DIDDocument;
}

export async function generateTestKey(kty: string): Promise<TESTKEY> {
  if (kty !== SIOP.KeyType.EC) throw new Error(SIOPErrors.NO_ALG_SUPPORTED);
  const key = crypto.generateKeyPairSync('ec', {
    namedCurve: SIOP.KeyCurve.SECP256k1,
  });
  const privateJwk = await fromKeyLike(key.privateKey);

  const did = getDIDFromKey(privateJwk);

  return {
    key: privateJwk,
    did,
  };
}

function getDIDFromKey(key: JWK): string {
  return `did:ethr:${getEthAddress(key)}`;
}

function getEthAddress(key: JWK): string {
  return getEthWallet(key).address;
}

function getEthWallet(key: JWK): ethers.Wallet {
  return new ethers.Wallet(prefixWith0x(base64ToHexString(key.d)));
}

export const prefixWith0x = (key: string): string => (key.startsWith('0x') ? key : `0x${key}`);

export interface IEnterpriseAuthZToken extends JWTPayload {
  sub?: string;
  did: string;
  aud: string;
  nonce: string;
}

export interface LegalEntityTestAuthN {
  iss: string; // legal entity name identifier
  aud: string; // RP Application Name.
  iat: number;
  exp: number;
  nonce: string;
  callbackUrl?: string; // Entity url to send notifications
  image?: string; // base64 encoded image data
  icon?: string; // base64 encoded image icon data
}

export const mockedKeyAndDid = async (): Promise<{
  hexPrivateKey: string;
  did: string;
  jwk: JWK;
  hexPublicKey: string;
}> => {
  // generate a new keypair
  const key = crypto.generateKeyPairSync('ec', {
    namedCurve: SIOP.KeyCurve.SECP256k1,
  });
  const privateJwk = await fromKeyLike(key.privateKey);
  const hexPrivateKey = base64ToHexString(privateJwk.d);
  const wallet: ethers.Wallet = new ethers.Wallet(prefixWith0x(hexPrivateKey));
  const did = `did:ethr:${wallet.address}`;
  const hexPublicKey = wallet.publicKey;

  return {
    hexPrivateKey,
    did,
    jwk: privateJwk,
    hexPublicKey,
  };
};

const mockedEntityAuthNToken = async (
  enterpiseName?: string
): Promise<{
  jwt: string;
  jwk: JWK;
  did: string;
  hexPrivateKey: string;
  hexPublicKey: string;
}> => {
  // generate a new keypair
  const { did, jwk, hexPrivateKey, hexPublicKey } = await mockedKeyAndDid();

  const payload: LegalEntityTestAuthN = {
    iss: enterpiseName || 'Test Entity',
    aud: 'test',
    iat: moment().unix(),
    exp: moment().add(15, 'minutes').unix(),
    nonce: uuidv4(),
  };

  const privateKey = await parseJwk(jwk, SIOP.KeyAlgo.ES256K);
  const jwt = await new SignJWT(payload as unknown as JWTPayload)
    .setProtectedHeader({
      alg: 'ES256K',
      typ: 'JWT',
    })
    .sign(privateKey);
  return { jwt, jwk, did, hexPrivateKey, hexPublicKey };
};

export async function mockedGetEnterpriseAuthToken(enterpriseName?: string): Promise<{
  jwt: string;
  did: string;
  jwk: JWK;
  hexPrivateKey: string;
  hexPublicKey: string;
}> {
  const testAuth = await mockedEntityAuthNToken(enterpriseName);
  const payload = jwt_decode(testAuth.jwt);

  const inputPayload: IEnterpriseAuthZToken = {
    did: testAuth.did,

    aud: (payload as JWTPayload)?.iss ? (payload as JWTPayload).iss : 'Test Entity',
    nonce: (payload as IEnterpriseAuthZToken).nonce,
  };

  const testApiPayload = {
    ...inputPayload,
    ...{
      sub: (payload as JWTPayload).iss, // Should be the id of the app that is requesting the token
      iat: moment().unix(),
      exp: moment().add(15, 'minutes').unix(),
      aud: 'test',
    },
  };

  const privateKey = await parseJwk(testAuth.jwk, SIOP.KeyAlgo.ES256K);
  const jwt = await new SignJWT(testApiPayload)
    .setProtectedHeader({
      alg: 'ES256K',
      typ: 'JWT',
    })
    .sign(privateKey);

  return {
    jwt,
    did: testAuth.did,
    jwk: testAuth.jwk,
    hexPrivateKey: testAuth.hexPrivateKey,
    hexPublicKey: testAuth.hexPublicKey,
  };
}

export interface DidKey {
  did: string;
  publicKeyHex?: string;
  jwk?: JWK;
}

interface FixJwk extends JWK {
  kty: string;
}

export const getParsedDidDocument = (didKey: DidKey): DIDDocument => {
  if (didKey.publicKeyHex) {
    const didDocB58 = DID_DOCUMENT_PUBKEY_B58;
    didDocB58.id = didKey.did;
    didDocB58.controller = didKey.did;
    didDocB58.verificationMethod[0].id = `${didKey.did}#keys-1`;
    didDocB58.verificationMethod[0].controller = didKey.did;
    didDocB58.verificationMethod[0].publicKeyBase58 = base58.encode(Buffer.from(didKey.publicKeyHex.replace('0x', ''), 'hex'));
    return didDocB58;
  }
  // then didKey jws public key
  const didDocJwk = DID_DOCUMENT_PUBKEY_JWK;
  const { jwk } = didKey;
  jwk.kty = didKey.jwk.kty || 'EC';
  didDocJwk.id = didKey.did;
  didDocJwk.controller = didKey.did;
  didDocJwk.verificationMethod[0].id = `${didKey.did}#keys-1`;
  didDocJwk.verificationMethod[0].controller = didKey.did;
  didDocJwk.verificationMethod[0].publicKeyJwk = jwk as FixJwk;
  return didDocJwk;
};

/*
export const resolveDidKey = async (did: string): Promise<DIDResolutionResult> => {
  return (await DidKeyDriver.get(did, {
    accept: 'application/did+ld+json',
  })) as DIDResolutionResult;
};
*/

export const metadata: {
  opMetadata: DiscoveryMetadataPayload;
  rpMetadata: RPRegistrationMetadataPayload;
  verify(): unknown;
} = {
  opMetadata: {
    issuer: ResponseIss.SELF_ISSUED_V2,
    authorization_endpoint: 'http://test.com',
    subject_syntax_types_supported: ['did:web', SubjectIdentifierType.DID],
    id_token_signing_alg_values_supported: undefined,
    request_object_signing_alg_values_supported: [SigningAlgo.EDDSA],
    response_types_supported: ResponseType.ID_TOKEN,
    scopes_supported: [Scope.OPENID_DIDAUTHN],
    subject_types_supported: [SubjectType.PAIRWISE],
    vp_formats: {
      ldp_vc: {
        proof_type: [ProofType.EcdsaSecp256k1Signature2019, ProofType.EcdsaSecp256k1Signature2019],
      },
      jwt_vc: {
        alg: [SigningAlgo.ES256, SigningAlgo.ES256K],
      },
    },
  },
  rpMetadata: {
    authorization_endpoint: 'http://test.com',
    id_token_signing_alg_values_supported: [],
    request_object_signing_alg_values_supported: [SigningAlgo.EDDSA],
    response_types_supported: [ResponseType.ID_TOKEN],
    scopes_supported: [Scope.OPENID, Scope.OPENID_DIDAUTHN],
    subject_syntax_types_supported: [SubjectIdentifierType.DID, 'did:web', 'did:key'],
    subject_types_supported: [SubjectType.PAIRWISE],
    vp_formats: {
      ldp_vc: {
        proof_type: [ProofType.EcdsaSecp256k1Signature2019, ProofType.EcdsaSecp256k1Signature2019],
      },
      jwt_vc: {
        alg: [SigningAlgo.ES256, SigningAlgo.ES256K],
      },
    },
  },
  verify() {
    return assertValidMetadata(this.opMetadata, this.rpMetadata);
  },
};
