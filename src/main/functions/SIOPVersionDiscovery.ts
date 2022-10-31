import Ajv from 'ajv';

import { D11AuthenticationRequestPayloadSchema, ID1AuthenticationRequestPayloadSchema } from '../schemas';
import { AuthenticationRequestPayload, SupportedVersion } from '../types';

// Need to remove the JWT fields to verify the request against the schema
function removeJWTPropertiesFromAuthRequest(authenticationRequestPayload: AuthenticationRequestPayload) {
  delete authenticationRequestPayload['iat'];
  delete authenticationRequestPayload['exp'];
  delete authenticationRequestPayload['iss'];
}

export function authenticationRequestVersionDiscovery(authenticationRequestPayload: AuthenticationRequestPayload): {
  version?: SupportedVersion;
  error?: string;
} {
  const authenticationRequestPayloadCopy: AuthenticationRequestPayload = JSON.parse(JSON.stringify(authenticationRequestPayload));
  const ajv = new Ajv({ verbose: true, allowUnionTypes: true, allErrors: true });
  removeJWTPropertiesFromAuthRequest(authenticationRequestPayloadCopy);
  const validateID1 = ajv.compile(ID1AuthenticationRequestPayloadSchema);
  let result = validateID1(authenticationRequestPayloadCopy);
  if (result) {
    return { version: SupportedVersion.SIOPv2_ID1 };
  }
  const validateJWTVCPresentationProfile = ajv.compile(ID1AuthenticationRequestPayloadSchema);
  result = validateJWTVCPresentationProfile(authenticationRequestPayloadCopy);
  if (result) {
    return { version: SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1 };
  }
  const validateD11 = ajv.compile(D11AuthenticationRequestPayloadSchema);
  result = validateD11(authenticationRequestPayloadCopy);
  if (result) {
    return { version: SupportedVersion.SIOPv2_D11 };
  }
  return { error: 'This is not a valid request' };
}
