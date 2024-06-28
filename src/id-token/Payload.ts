import { AuthorizationResponseOpts, mergeOAuth2AndOpenIdInRequestPayload } from '../authorization-response';
import { assertValidResponseOpts } from '../authorization-response/Opts';
import { authorizationRequestVersionDiscovery } from '../helpers/SIOPSpecVersion';
import { IDTokenPayload, ResponseIss, SIOPErrors, SupportedVersion, VerifiedAuthorizationRequest } from '../types';

export const createIDTokenPayload = async (
  verifiedAuthorizationRequest: VerifiedAuthorizationRequest,
  responseOpts: AuthorizationResponseOpts,
): Promise<IDTokenPayload> => {
  await assertValidResponseOpts(responseOpts);
  const authorizationRequestPayload = await verifiedAuthorizationRequest.authorizationRequest.mergedPayloads();
  const requestObject = verifiedAuthorizationRequest.requestObject;
  if (!authorizationRequestPayload) {
    throw new Error(SIOPErrors.VERIFY_BAD_PARAMS);
  }
  const payload = await mergeOAuth2AndOpenIdInRequestPayload(authorizationRequestPayload, requestObject);

  const state = payload.state;
  const nonce = payload.nonce;
  const SEC_IN_MS = 1000;

  const rpSupportedVersions = authorizationRequestVersionDiscovery(payload);
  const maxRPVersion = rpSupportedVersions.reduce(
    (previous, current) => (current.valueOf() > previous.valueOf() ? current : previous),
    SupportedVersion.SIOPv2_D12_OID4VP_D18,
  );
  if (responseOpts.version && rpSupportedVersions.length > 0 && !rpSupportedVersions.includes(responseOpts.version)) {
    throw Error(`RP does not support spec version ${responseOpts.version}, supported versions: ${rpSupportedVersions.toString()}`);
  }
  const opVersion = responseOpts.version ?? maxRPVersion;

  const jwtIssuer = responseOpts.jwtIssuer;
  let sub: string | undefined;

  if (!jwtIssuer) {
    sub = undefined;
  } else if (jwtIssuer.method === 'did') {
    const did = jwtIssuer.didUrl.split('#')[0];
    sub = did;
  } else if (jwtIssuer.method === 'x5c') {
    sub = jwtIssuer.issuer;
  } else if (jwtIssuer.method === 'jwk') {
    sub = jwtIssuer.jwkThumbprint;
  } else {
    throw new Error(`JwtIssuer method '${jwtIssuer.method}' not implemented`);
  }

  const idToken: IDTokenPayload = {
    // fixme: ID11 does not use this static value anymore
    iss:
      responseOpts?.registration?.issuer ??
      (opVersion === SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1 ? ResponseIss.JWT_VC_PRESENTATION_V1 : ResponseIss.SELF_ISSUED_V2),
    aud: responseOpts.audience || payload.client_id,
    iat: Math.round(Date.now() / SEC_IN_MS - 60 * SEC_IN_MS),
    exp: Math.round(Date.now() / SEC_IN_MS + (responseOpts.expiresIn || 600)),
    sub,
    ...(payload.auth_time && { auth_time: payload.auth_time }),
    nonce,
    state,
    // ...(responseOpts.presentationExchange?._vp_token ? { _vp_token: responseOpts.presentationExchange._vp_token } : {}),
  };
  return idToken;
};
