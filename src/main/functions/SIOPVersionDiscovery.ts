import Ajv from 'ajv';

import { AuthenticationRequestPayloadSchemaVD11, AuthenticationRequestPayloadSchemaVID1 } from '../schemas';
import { AuthenticationRequestPayload, SupportedVersion } from '../types';
import errors from '../types/Errors';

export function authenticationRequestVersionDiscovery(authenticationRequest: AuthenticationRequestPayload): SupportedVersion {
  const authenticationRequestCopy: AuthenticationRequestPayload = JSON.parse(JSON.stringify(authenticationRequest));
  const ajv = new Ajv({ verbose: true, allowUnionTypes: true, allErrors: true });
  const validateID1 = ajv.compile(AuthenticationRequestPayloadSchemaVID1);
  let result = validateID1(authenticationRequestCopy);
  if (result) {
    return SupportedVersion.SIOPv2_ID1;
  }
  const validateJWTVCPresentationProfile = ajv.compile(AuthenticationRequestPayloadSchemaVID1);
  result = validateJWTVCPresentationProfile(authenticationRequestCopy);
  if (result) {
    return SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1;
  }
  const validateD11 = ajv.compile(AuthenticationRequestPayloadSchemaVD11);
  result = validateD11(authenticationRequestCopy);
  if (result) {
    return SupportedVersion.SIOPv2_D11;
  }
  throw new Error(errors.SIOP_VERSION_NOT_SUPPORTED);
}
