import Ajv from 'ajv';

import { AuthorizationRequestPayloadSchemaVD11, AuthorizationRequestPayloadSchemaVID1 } from '../schemas';
import { AuthorizationRequestPayload, SupportedVersion } from '../types';
import errors from '../types/Errors';

// TODO: Probably wise to return an array in case a request adheres to multiple schema's
export function authorizationRequestVersionDiscovery(authorizationRequest: AuthorizationRequestPayload): SupportedVersion {
  const authorizationRequestCopy: AuthorizationRequestPayload = JSON.parse(JSON.stringify(authorizationRequest));
  const ajv = new Ajv({ verbose: true, allowUnionTypes: true, strict: false, allErrors: true });
  const validateID1 = ajv.compile(AuthorizationRequestPayloadSchemaVID1);
  let result = validateID1(authorizationRequestCopy);
  if (result) {
    return SupportedVersion.SIOPv2_ID1;
  }
  const validateJWTVCPresentationProfile = ajv.compile(AuthorizationRequestPayloadSchemaVID1);
  result = validateJWTVCPresentationProfile(authorizationRequestCopy);
  if (result) {
    return SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1;
  }
  const validateD11 = ajv.compile(AuthorizationRequestPayloadSchemaVD11);
  result = validateD11(authorizationRequestCopy);
  if (result) {
    return SupportedVersion.SIOPv2_D11;
  }
  throw new Error(errors.SIOP_VERSION_NOT_SUPPORTED);
}
