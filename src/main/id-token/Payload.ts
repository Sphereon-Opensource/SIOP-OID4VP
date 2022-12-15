import { JWK } from 'jose';

import { AuthorizationResponseOpts } from '../authorization-response';
import { mergeOAuth2AndOpenIdInRequestPayload } from '../authorization-response';
import { assertValidResponseOpts } from '../authorization-response/Opts';
import { getNonce, getPublicJWKFromHexPrivateKey, getState, getThumbprint } from '../helpers';
import {
  AuthorizationRequestPayload,
  IDTokenPayload,
  isInternalSignature,
  isSuppliedSignature,
  ResponseIss,
  SIOPErrors,
  SubjectSyntaxTypesSupportedValues,
} from '../types';

export const createIDTokenPayload = async (
  authorizationRequestPayload: AuthorizationRequestPayload,
  responseOpts: AuthorizationResponseOpts
): Promise<IDTokenPayload> => {
  assertValidResponseOpts(responseOpts);
  if (!authorizationRequestPayload) {
    throw new Error(SIOPErrors.VERIFY_BAD_PARAMS);
  }
  const payload = await mergeOAuth2AndOpenIdInRequestPayload(authorizationRequestPayload);

  //fixme: client_metadata and fetch
  const supportedDidMethods = payload['registration']?.subject_syntax_types_supported?.filter((sst) =>
    sst.includes(SubjectSyntaxTypesSupportedValues.DID.valueOf())
  );
  const state = responseOpts.state || getState(payload.state);
  const nonce = payload.nonce || responseOpts.nonce || getNonce(state);
  const SEC_IN_MS = 1000;
  const idToken: IDTokenPayload = {
    // fixme: ID11 does not use this static value anymore
    iss: ResponseIss.SELF_ISSUED_V2,
    aud: payload.redirect_uri,
    iat: Date.now() / SEC_IN_MS - 60 * SEC_IN_MS,
    exp: Date.now() / SEC_IN_MS + (responseOpts.expiresIn || 600),
    sub: responseOpts.did,
    auth_time: payload.auth_time,
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

const createThumbprintAndJWK = async (resOpts: AuthorizationResponseOpts): Promise<{ thumbprint: string; subJwk: JWK }> => {
  let thumbprint;
  let subJwk;
  if (isInternalSignature(resOpts.signatureType)) {
    thumbprint = await getThumbprint(resOpts.signatureType.hexPrivateKey, resOpts.did);
    subJwk = getPublicJWKFromHexPrivateKey(
      resOpts.signatureType.hexPrivateKey,
      resOpts.signatureType.kid || `${resOpts.signatureType.did}#key-1`,
      resOpts.did
    );
  } else if (isSuppliedSignature(resOpts.signatureType)) {
    // fixme: These are uninitialized. Probably we have to extend the supplied signature to provide these.
    return { thumbprint, subJwk };
  } else {
    throw new Error(SIOPErrors.SIGNATURE_OBJECT_TYPE_NOT_SET);
  }
  return { thumbprint, subJwk };
};
