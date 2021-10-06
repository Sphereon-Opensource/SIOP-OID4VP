import { DIDDocument as DIFDIDDocument, Resolvable } from 'did-resolver';
import { JWK } from 'jose/types';

export interface ResolveOpts {
  resolver?: Resolvable;
  resolveUrl?: string;
  didMethods?: string[];
}

export interface CredentialSubject {
  [x: string]: unknown;
}

export interface Proof {
  type: string;
  created: string;
  proofPurpose: string;
  verificationMethod: string;
  jws: string;
  [x: string]: string;
}

export interface CredentialStatus {
  id: string;
  type: string;
}

export interface Credential {
  '@context': string[];
  id: string;
  type: string[];
  credentialSubject: CredentialSubject;
  issuer: string;
  issuanceDate?: string;
  expirationDate?: string;
  credentialStatus?: CredentialStatus;
  [x: string]: unknown;
}

export interface VerifiableCredential extends Credential {
  issuer: string;
  issuanceDate: string;
  proof: Proof;
}

export interface Presentation {
  '@context': string[];
  type: string;
  verifiableCredential: string[] | VerifiableCredential[];
}

export interface VerifiablePresentation extends Presentation {
  proof: Proof;
}
export interface DIDDocument extends DIFDIDDocument {
  owner?: string;
  created?: string;
  updated?: string;
  proof?: LinkedDataProof;
}
/*export interface PublicKey {
    id: string;
    type: string;
    controller: string;
    ethereumAddress?: string;
    publicKeyBase64?: string;
    publicKeyBase58?: string;
    publicKeyHex?: string;
    publicKeyPem?: string;
    publicKeyJwk?: JWK;
}*/
export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyHex?: string;
  publicKeyMultibase?: string;
  publicKeyBase58?: string;
  publicKeyJwk?: JWK;
}
/*
export interface Authentication {
    type: string;
    publicKey: string;
}*/
export interface LinkedDataProof {
  type: string;
  created: string;
  creator: string;
  nonce: string;
  signatureValue: string;
}
/*
export interface ServiceEndpoint {
    id: string;
    type: string;
    serviceEndpoint: string;
    description?: string;
}
*/
