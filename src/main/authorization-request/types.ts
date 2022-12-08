import { VerifyCallback } from '@sphereon/wellknown-dids-client';

import { ClaimOpts } from '../authorization-response';
import { RequestObjectOpts } from '../request-object';
import {
  CheckLinkedDomain,
  ClientMetadataOpts,
  ExternalVerification,
  InternalVerification,
  ResponseMode,
  ResponseType,
  Scope,
  SigningAlgo,
  SubjectType,
} from '../types';

export type AuthorizationRequestPayloadOpts = RequestObjectPayloadOpts;
export interface RequestObjectPayloadOpts {
  scope: string; // from openid-connect-self-issued-v2-1_0-ID1
  response_type: string; // from openid-connect-self-issued-v2-1_0-ID1
  client_id: string; // from openid-connect-self-issued-v2-1_0-ID1
  redirect_uri: string; // from openid-connect-self-issued-v2-1_0-ID1
  id_token_hint?: string; // from openid-connect-self-issued-v2-1_0-ID1
  claims?: ClaimOpts; // from openid-connect-self-issued-v2-1_0-ID1 look at https://openid.net/specs/openid-connect-core-1_0.html#Claims
  nonce?: string; // An optional nonce, will be generated if not provided
  state?: string; // An optional state, will be generated if not provided
  authorization_endpoint?: string;
  response_mode?: ResponseMode; // How the URI should be returned. This is not being used by the library itself, allows an implementor to make a decision
  response_types_supported?: ResponseType[] | ResponseType;
  scopes_supported?: Scope[] | Scope;
  subject_types_supported?: SubjectType[] | SubjectType;
  request_object_signing_alg_values_supported?: SigningAlgo[] | SigningAlgo;
}

interface AuthorizationRequestCommonOpts {
  // Yes, this includes the payload properties both at the payload level as well as in the requestObject.payload property. That is to support OAuth2 with or without a signed OpenID requestObject  {

  clientMetadata?: ClientMetadataOpts; // this maps to 'registration' for older SIOPv2 specs! OPTIONAL. This parameter is used by the RP to provide information about itself to a Self-Issued OP that would normally be provided to an OP during Dynamic RP Registration, as specified in {#rp-registration-parameter}.
  payload: AuthorizationRequestPayloadOpts;
  requestObject: RequestObjectOpts;

  uriScheme?: string; // Use a custom scheme for the URI. By default openid:// will be used

  // FIXME: Doesn't make sense. We are the RP, why would we check ourselves? Should be on the Verify Opts
  checkLinkedDomain?: CheckLinkedDomain; // determines how we'll handle the linked domains for this RP
  // revocationVerificationCallback?: RevocationVerificationCallback;
}

export type AuthorizationRequestOptsVD1 = AuthorizationRequestCommonOpts;

export interface AuthorizationRequestOptsVD11 extends AuthorizationRequestCommonOpts {
  // clientMetadata?: ClientMetadataOpts; // from openid-connect-self-issued-v2-1_0-11 look at https://openid.net/specs/openid-connect-registration-1_0.html
  // clientMetadataUri?: string; // from openid-connect-self-issued-v2-1_0-11
  idTokenType?: string; // OPTIONAL. Space-separated string that specifies the types of ID token the RP wants to obtain, with the values appearing in order of preference. The allowed individual values are subject_signed and attester_signed (see Section 8.2). The default value is attester_signed.
}

export type AuthorizationRequestOpts = AuthorizationRequestOptsVD1 | AuthorizationRequestOptsVD11;

export interface VerifyAuthorizationRequestOpts {
  verification: InternalVerification | ExternalVerification; // To use internal verification or external hosted verification
  // didDocument?: DIDDocument; // If not provided the DID document will be resolved from the request
  nonce?: string; // If provided the nonce in the request needs to match
  // redirectUri?: string;
  verifyCallback?: VerifyCallback;
}
