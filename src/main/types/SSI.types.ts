import {
  ICredential,
  ICredentialStatus,
  ICredentialSubject,
  IPresentation,
  IProof,
  IVerifiableCredential,
  IVerifiablePresentation,
} from '@sphereon/pex';
import { DIDDocument as DIFDIDDocument, Resolvable } from 'did-resolver';
import { JWK } from 'jose/types';

// Here because we previously had these interfaces in this file
export { IProof, ICredentialSubject, ICredentialStatus, ICredential, IVerifiableCredential, IPresentation, IVerifiablePresentation };

export interface ResolveOpts {
  resolver?: Resolvable;
  resolveUrl?: string;
  didMethods?: string[];
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
