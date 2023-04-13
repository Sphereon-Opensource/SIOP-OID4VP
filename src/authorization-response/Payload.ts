import { AuthorizationRequest } from '../authorization-request';
import { signDidJwtPayload } from '../did';
import { RequestObject } from '../request-object';
import { AuthorizationRequestPayload, AuthorizationResponsePayload, IDTokenPayload, SIOPErrors } from '../types';

import { putPresentationsInResponse } from './OpenID4VP';
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
  const state: string = await authorizationRequest.getMergedProperty('state');
  if (!state) {
    throw Error('No state');
  }

  const responsePayload: AuthorizationResponsePayload = {
    ...(responseOpts.accessToken ? { access_token: responseOpts.accessToken } : {}),
    token_type: responseOpts.tokenType,
    refresh_token: responseOpts.refreshToken,
    expires_in: responseOpts.expiresIn,
    state,
  };

  await putPresentationsInResponse(authorizationRequest, responsePayload, responseOpts, idTokenPayload);
  if (idTokenPayload) {
    responsePayload.id_token = await signDidJwtPayload(idTokenPayload, responseOpts);
  }

  return responsePayload;
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
