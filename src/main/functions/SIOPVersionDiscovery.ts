import Ajv from 'ajv';

import { D11AuthenticationRequestPayloadSchema, ID1AuthenticationRequestPayloadSchema } from '../schemas';
import { AuthenticationRequestPayload, SupportedVersion } from '../types';
import errors from '../types/Errors';

export function authenticationRequestVersionDiscovery(authenticationRequestPayload: AuthenticationRequestPayload): SupportedVersion {
  const authenticationRequestPayloadCopy: AuthenticationRequestPayload = JSON.parse(JSON.stringify(authenticationRequestPayload));
  const ajv = new Ajv({ verbose: true, allowUnionTypes: true, allErrors: true });
  const validateID1 = ajv.compile(ID1AuthenticationRequestPayloadSchema);
  let result = validateID1(authenticationRequestPayloadCopy);
  if (result) {
    return SupportedVersion.SIOPv2_ID1;
  }
  const validateJWTVCPresentationProfile = ajv.compile(ID1AuthenticationRequestPayloadSchema);
  result = validateJWTVCPresentationProfile(authenticationRequestPayloadCopy);
  if (result) {
    return SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1;
  }
  const validateD11 = ajv.compile(D11AuthenticationRequestPayloadSchema);
  result = validateD11(authenticationRequestPayloadCopy);
  if (result) {
    return SupportedVersion.SIOPv2_D11;
  }
  throw new Error(errors.SIOP_VERSION_NOT_SUPPORTED);
}
