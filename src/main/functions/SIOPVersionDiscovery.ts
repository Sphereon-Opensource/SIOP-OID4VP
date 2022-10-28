import Ajv from 'ajv';

import { D11AuthenticationRequestSchema, ID1AuthenticationRequestSchema } from '../schemas';
import { AuthenticationRequestPayload, SupportedVersion } from '../types';

export function definitionVersionDiscovery(authenticationRequestPayload: AuthenticationRequestPayload): {
  version?: SupportedVersion;
  error?: string;
} {
  const authenticationRequestPayloadCopy: AuthenticationRequestPayload = JSON.parse(JSON.stringify(authenticationRequestPayload));
  const ajv = new Ajv({ verbose: true, allowUnionTypes: true, allErrors: true });
  const validateID1 = ajv.compile(ID1AuthenticationRequestSchema);
  let result = validateID1(authenticationRequestPayloadCopy);
  if (result) {
    return { version: SupportedVersion.SIOPv2_ID1 };
  }
  const validateJWTVCPresentationProfile = ajv.compile(ID1AuthenticationRequestSchema);
  result = validateJWTVCPresentationProfile(authenticationRequestPayloadCopy);
  if (result) {
    return { version: SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1 };
  }
  const validateD11 = ajv.compile(D11AuthenticationRequestSchema);
  result = validateD11(authenticationRequestPayloadCopy);
  if (result) {
    return { version: SupportedVersion.SIOPv2_D11 };
  }
  return { error: 'This is not a valid request' };
}
