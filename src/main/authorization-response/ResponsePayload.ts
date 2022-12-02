import { getNonce, getState, signDidJwtPayload } from '../functions';
import {
  AuthorizationResponseOpts,
  AuthorizationResponsePayload,
  IDTokenPayload,
  ResponseIss,
  SIOPErrors,
  SubjectSyntaxTypesSupportedValues,
  VerifiedAuthorizationRequest,
} from '../types';

import { createThumbprintAndJWK } from './AuthorizationResponse';
import { extractPresentations } from './OpenID4VP';
import { assertValidResponseOpts } from './ResponseOpts';

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

export const createIDTokenPayload = async (
  authorizationRequest: VerifiedAuthorizationRequest,
  responseOpts: AuthorizationResponseOpts
): Promise<IDTokenPayload> => {
  assertValidResponseOpts(responseOpts);
  if (!authorizationRequest || !authorizationRequest.jwt) {
    throw new Error(SIOPErrors.VERIFY_BAD_PARAMS);
  }
  const supportedDidMethods = authorizationRequest.payload['registration']?.subject_syntax_types_supported?.filter((sst) =>
    sst.includes(SubjectSyntaxTypesSupportedValues.DID.valueOf())
  );
  const state = responseOpts.state || getState(authorizationRequest.payload.state);
  const nonce = authorizationRequest.payload.nonce || responseOpts.nonce || getNonce(state);
  const idToken: IDTokenPayload = {
    iss: ResponseIss.SELF_ISSUED_V2,
    aud: authorizationRequest.payload.redirect_uri,
    iat: Date.now() / 1000,
    exp: Date.now() / 1000 + (responseOpts.expiresIn || 600),
    sub: responseOpts.did,
    auth_time: authorizationRequest.payload.auth_time,
    nonce,
    ...(responseOpts.presentationExchange?._vp_token ? { _vp_token: responseOpts.presentationExchange._vp_token } : {}),
  };
  if (supportedDidMethods.indexOf(SubjectSyntaxTypesSupportedValues.JWK_THUMBPRINT) != -1 && !responseOpts.did) {
    const { thumbprint, subJwk } = await createThumbprintAndJWK(responseOpts);
    idToken['sub_jwk'] = subJwk;
    idToken.sub = thumbprint;
  }
  return idToken;
};
