import { IPresentationDefinition, PresentationSignCallBackParams } from '@sphereon/pex';
import { PresentationSubmission, W3CVerifiablePresentation } from '@sphereon/ssi-types';

import {
  CheckLinkedDomain,
  ExternalSignature,
  ExternalVerification,
  InternalSignature,
  InternalVerification,
  NoSignature,
  ResponseMode,
  ResponseRegistrationOpts,
  SuppliedSignature,
  SupportedVersion,
  VerifiablePresentationPayload,
} from '../types';

export interface AuthorizationResponseOpts {
  redirectUri?: string; // It's typically comes from the request opts as a measure to prevent hijacking.
  registration: ResponseRegistrationOpts;
  checkLinkedDomain?: CheckLinkedDomain;

  signatureType: InternalSignature | ExternalSignature | SuppliedSignature | NoSignature;
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

export interface PresentationDefinitionPayloadOpts {
  presentation_definition?: IPresentationDefinition;
  presentation_definition_uri?: string;
}

export interface PresentationDefinitionWithLocation {
  version?: SupportedVersion;
  location: PresentationDefinitionLocation;
  definition: IPresentationDefinition;
}

export interface VerifiablePresentationWithLocation extends VerifiablePresentationPayload {
  location: PresentationLocation;
}

export enum PresentationDefinitionLocation {
  CLAIMS_VP_TOKEN = 'claims.vp_token',
  TOPLEVEL_PRESENTATION_DEF = 'presentation_definition',
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

  presentationDefinitions?: PresentationDefinitionWithLocation | PresentationDefinitionWithLocation[]; // The presentation definitions to match against VPs in the response
  audience: string; // The audience/redirect_uri
  // claims?: ClaimPayloadCommonOpts; // The claims, typically the same values used during request creation
  // verifyCallback?: VerifyCallback;
  // presentationVerificationCallback?: PresentationVerificationCallback;
}
