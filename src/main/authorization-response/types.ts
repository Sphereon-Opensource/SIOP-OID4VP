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
  VerifiablePresentationWithFormat,
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
  presentationExchange?: PresentationExchangeResponseOpts;
}

export interface PresentationExchangeResponseOpts {
  /* presentationSignCallback?: PresentationSignCallback;
  signOptions?: PresentationSignOptions,
*/
  /*  credentialsAndDefinitions: {
    presentationDefinition: IPresentationDefinition,
    selectedCredentials: W3CVerifiableCredential[]
  }[],*/

  verifiablePresentations: W3CVerifiablePresentation[];
  vpTokenLocation?: VPTokenLocation;
  submissionData?: PresentationSubmission;
}

export interface PresentationExchangeRequestOpts {
  presentationVerificationCallback?: PresentationVerificationCallback;
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

export interface VerifiablePresentationWithSubmissionData extends VerifiablePresentationWithFormat {
  vpTokenLocation: VPTokenLocation;

  submissionData: PresentationSubmission;
}

export enum PresentationDefinitionLocation {
  CLAIMS_VP_TOKEN = 'claims.vp_token',
  TOPLEVEL_PRESENTATION_DEF = 'presentation_definition',
}

export enum VPTokenLocation {
  AUTHORIZATION_RESPONSE = 'authorization_response',
  ID_TOKEN = 'id_token',
  TOKEN_RESPONSE = 'token_response',
}

export type PresentationVerificationResult = { verified: boolean };

export type PresentationVerificationCallback = (args: W3CVerifiablePresentation) => Promise<PresentationVerificationResult>;

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
