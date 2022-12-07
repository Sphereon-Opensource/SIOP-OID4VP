import { PresentationSignCallBackParams } from '@sphereon/pex';
import { PresentationDefinitionV1, PresentationDefinitionV2 } from '@sphereon/pex-models';
import { PresentationSubmission, W3CVerifiablePresentation } from '@sphereon/ssi-types';
import { VerifyCallback } from '@sphereon/wellknown-dids-client';

import {
  CheckLinkedDomain,
  ExternalSignature,
  ExternalVerification,
  IDTokenPayload,
  InternalSignature,
  InternalVerification,
  ResponseMode,
  ResponseRegistrationOpts,
  SuppliedSignature,
  VerifiablePresentationPayload,
} from '../types';

export interface AuthorizationResponseOpts {
  redirectUri?: string; // It's typically comes from the request opts as a measure to prevent hijacking.
  registration: ResponseRegistrationOpts;
  checkLinkedDomain?: CheckLinkedDomain;

  signatureType: InternalSignature | ExternalSignature | SuppliedSignature;
  nonce?: string;
  state?: string;
  responseMode?: ResponseMode;
  did: string;
  expiresIn?: number;
  accessToken?: string;
  tokenType?: string;
  refreshToken?: string;
  presentationExchange?: PresentationExchangeOpts;
}

export interface PresentationExchangeOpts {
  presentationVerificationCallback?: PresentationVerificationCallback;
  presentationSignCallback?: PresentationSignCallback;
  vps?: VerifiablePresentationWithLocation[];
  _vp_token?: { presentation_submission: PresentationSubmission };
}

export interface VpTokenClaimOpts {
  presentationDefinition?: PresentationDefinitionV1 | PresentationDefinitionV2;
  presentationDefinitionUri?: string;
}

export interface ClaimOpts {
  idToken?: IDTokenPayload;
  vpToken?: VpTokenClaimOpts;
}

export interface PresentationDefinitionWithLocation {
  location: PresentationLocation;
  definition: PresentationDefinitionV1 | PresentationDefinitionV2;
}

export interface VerifiablePresentationWithLocation extends VerifiablePresentationPayload {
  location: PresentationLocation;
}

export enum PresentationLocation {
  VP_TOKEN = 'vp_token',
  ID_TOKEN = 'id_token',
}

export type PresentationVerificationResult = { verified: boolean };

export type PresentationVerificationCallback = (args: VerifiablePresentationPayload) => Promise<PresentationVerificationResult>;

export type PresentationSignCallback = (args: PresentationSignCallBackParams) => Promise<W3CVerifiablePresentation>;

export interface VerifyAuthorizationResponseOpts {
  verification: InternalVerification | ExternalVerification;
  // didDocument?: DIDDocument; // If not provided the DID document will be resolved from the request
  nonce?: string; // mandatory? // To verify the response against the supplied nonce
  state?: string; // mandatory? // To verify the response against the supplied state
  audience: string; // The audience/redirect_uri
  claims?: ClaimOpts; // The claims, typically the same values used during request creation
  verifyCallback?: VerifyCallback;
  presentationVerificationCallback?: PresentationVerificationCallback;
}
