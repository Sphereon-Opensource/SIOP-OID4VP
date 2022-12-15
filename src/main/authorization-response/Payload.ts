import { AuthorizationRequest } from '../authorization-request';
import { signDidJwtPayload } from '../did';
import { getState } from '../helpers';
import { RequestObject } from '../request-object';
import { AuthorizationRequestPayload, AuthorizationResponsePayload, IDTokenPayload, SIOPErrors } from '../types';

import { extractPresentations } from './OpenID4VP';
import { assertValidResponseOpts } from './Opts';
import { AuthorizationResponseOpts } from './types';

export const createResponsePayload = async (
  authorizationRequest: AuthorizationRequest,
  responseOpts: AuthorizationResponseOpts,
  idTokenPayload?: IDTokenPayload
): Promise<AuthorizationResponsePayload | undefined> => {
  assertValidResponseOpts(responseOpts);
  if (!authorizationRequest) {
    throw new Error(SIOPErrors.NO_REQUEST);
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
    ...(idTokenPayload ? { id_token: await signDidJwtPayload(idTokenPayload, responseOpts) } : {}),
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
