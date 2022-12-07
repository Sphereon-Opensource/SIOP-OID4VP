import { getState, signDidJwtPayload } from '../functions';
import { RequestObject } from '../request-object/RequestObject';
import {
  AuthorizationRequestPayload,
  AuthorizationResponseOpts,
  AuthorizationResponsePayload,
  IDTokenPayload,
  SIOPErrors,
  VerifiedAuthorizationRequest,
} from '../types';

import { extractPresentations } from './OpenID4VP';
import { assertValidResponseOpts } from './Opts';

export const createResponsePayload = async (
  authorizationRequest: VerifiedAuthorizationRequest,
  idToken: IDTokenPayload,
  responseOpts: AuthorizationResponseOpts
): Promise<AuthorizationResponsePayload> => {
  assertValidResponseOpts(responseOpts);
  if (!authorizationRequest || !authorizationRequest.jwt) {
    throw new Error(SIOPErrors.VERIFY_BAD_PARAMS);
  }
  const state = responseOpts.state || getState(authorizationRequest.payload.state);
  const { vp_token, verifiable_presentations } = extractPresentations(responseOpts);
  return {
    access_token: responseOpts.accessToken,
    token_type: responseOpts.tokenType,
    refresh_token: responseOpts.refreshToken,
    expires_in: responseOpts.expiresIn,
    // fixme: The or definitely is wrong. The verifiable_presentations should end up in the ID token if present
    vp_token: vp_token || verifiable_presentations,
    id_token: await signDidJwtPayload(idToken, responseOpts),
    state,
  };
};

/**
 * Properties can be in oAUth2 and OpenID (JWT) style. If they are in both the OpenID prop takes precedence as they are signed.
 * @param payload
 * @param requestObject
 */
export const mergeOAuth2AndOpenIdInRequestPayload = async (
  payload: AuthorizationRequestPayload,
  requestObject?: RequestObject
): Promise<AuthorizationRequestPayload> => {
  const payloadCopy = JSON.parse(JSON.stringify(payload));

  const requestObj = requestObject ? requestObject : await RequestObject.fromAuthorizationRequestPayload(payload);
  if (!requestObj) {
    return payloadCopy;
  }
  const requestObjectPayload = await requestObj.getPayload();
  return { ...payloadCopy, ...requestObjectPayload };
};