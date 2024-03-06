import { AuthorizationRequest } from '../authorization-request';
import { IDToken } from '../id-token';
import { RequestObject } from '../request-object';
import { AuthorizationRequestPayload, AuthorizationResponsePayload, IDTokenPayload, SIOPErrors } from '../types';

import { putPresentationSubmissionInLocation } from './OpenID4VP';
import { assertValidResponseOpts } from './Opts';
import { AuthorizationResponseOpts } from './types';

export const createResponsePayload = async (
  authorizationRequest: AuthorizationRequest,
  responseOpts: AuthorizationResponseOpts,
  idTokenPayload?: IDTokenPayload
): Promise<AuthorizationResponsePayload | undefined> => {
  await assertValidResponseOpts(responseOpts);
  if (!authorizationRequest) {
    throw new Error(SIOPErrors.NO_REQUEST);
  }

  // If state was in request, it must be in response
  const state: string | undefined = await authorizationRequest.getMergedProperty('state');

  const responsePayload: AuthorizationResponsePayload = {
    ...(responseOpts.accessToken && { access_token: responseOpts.accessToken }),
    ...(responseOpts.tokenType && { token_type: responseOpts.tokenType }),
    ...(responseOpts.refreshToken && { refresh_token: responseOpts.refreshToken }),
    expires_in: responseOpts.expiresIn || 3600,
    state,
  };

  // vp tokens
  await putPresentationSubmissionInLocation(authorizationRequest, responsePayload, responseOpts, idTokenPayload);
  if (idTokenPayload) {
    responsePayload.id_token = await IDToken.fromIDTokenPayload(idTokenPayload, responseOpts).then((id) => id.jwt());
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
