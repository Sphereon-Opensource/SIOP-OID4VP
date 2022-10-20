import { ObjectUtils, PresentationSubmission } from '@sphereon/ssi-types';
import { JWTHeader } from 'did-jwt';
import { JWK } from 'jose';

import AuthenticationRequest from './AuthenticationRequest';
import { createDiscoveryMetadataPayload } from './AuthenticationResponseRegistration';
import { PresentationExchange } from './PresentationExchange';
import {
  getIssuerDidFromPayload,
  getNonce,
  getPublicJWKFromHexPrivateKey,
  getResolver,
  getState,
  getThumbprint,
  parseJWT,
  signDidJwtPayload,
  validateLinkedDomainWithDid,
  verifyDidJWT,
  verifyRevocation,
} from './functions';
import {
  AuthenticationResponseOpts,
  AuthenticationResponsePayload,
  AuthenticationResponseWithJWT,
  CheckLinkedDomain,
  IdToken,
  isExternalSignature,
  isExternalVerification,
  isInternalSignature,
  isInternalVerification,
  isSuppliedSignature,
  JWTPayload,
  PresentationDefinitionWithLocation,
  PresentationLocation,
  PresentationVerificationCallback,
  ResponseIss,
  RevocationVerification,
  SIOPErrors,
  SubjectIdentifierType,
  SubjectSyntaxTypesSupportedValues,
  VerifiablePresentationPayload,
  VerifiedAuthenticationRequestWithJWT,
  VerifiedAuthenticationResponseWithJWT,
  VerifyAuthenticationRequestOpts,
  VerifyAuthenticationResponseOpts,
} from './types';

export default class AuthenticationResponse {
  /**
   * Creates a SIOP Response Object
   *
   * @param requestJwt
   * @param responseOpts
   * @param verifyOpts
   */
  static async createJWTFromRequestJWT(
    requestJwt: string,
    responseOpts: AuthenticationResponseOpts,
    verifyOpts: VerifyAuthenticationRequestOpts
  ): Promise<AuthenticationResponseWithJWT> {
    assertValidResponseOpts(responseOpts);
    if (!requestJwt || !requestJwt.startsWith('ey')) {
      throw new Error(SIOPErrors.NO_JWT);
    }
    const verifiedJWT = await AuthenticationRequest.verifyJWT(requestJwt, verifyOpts);
    return AuthenticationResponse.createJWTFromVerifiedRequest(verifiedJWT, responseOpts);
  }

  // TODO SK Can you please put some documentation on it?
  static async createJWTFromVerifiedRequest(
    verifiedJwt: VerifiedAuthenticationRequestWithJWT,
    responseOpts: AuthenticationResponseOpts
  ): Promise<AuthenticationResponseWithJWT> {
    const idToken = await createSIOPIDToken(verifiedJwt, responseOpts);
    const payload = await createSIOPResponsePayload(verifiedJwt, responseOpts);
    payload.id_token = await signDidJwtPayload(idToken, responseOpts);
    await assertValidVerifiablePresentations({
      definitions: verifiedJwt.presentationDefinitions,
      vps: payload.vp_token ? [payload.vp_token]: undefined,
      presentationVerificationCallback: responseOpts.presentationVerificationCallback,
    });

    return {
      jwt: payload.id_token,
      state: payload.state,
      nonce: payload.nonce,
      idToken,
      payload,
      responseOpts,
    };

    // todo add uri generation support in separate method, like in the AuthRequest class
  }

  /**
   * Verifies a SIOP ID Response JWT on the RP Side
   *
   * @param jwt ID token to be validated
   * @param verifyOpts
   */
  static async verifyJWT(jwt: string, verifyOpts: VerifyAuthenticationResponseOpts): Promise<VerifiedAuthenticationResponseWithJWT> {
    if (!jwt) {
      throw new Error(SIOPErrors.NO_JWT);
    }
    assertValidVerifyOpts(verifyOpts);

    const { header, payload } = parseJWT(jwt);
    assertValidResponseJWT({ header, payload });

    const verifiedJWT = await verifyDidJWT(jwt, getResolver(verifyOpts.verification.resolveOpts), {
      audience: verifyOpts.audience,
    });

    const issuerDid = getIssuerDidFromPayload(payload);
    if (verifyOpts.verification.checkLinkedDomain && verifyOpts.verification.checkLinkedDomain !== CheckLinkedDomain.NEVER) {
      await validateLinkedDomainWithDid(issuerDid, verifyOpts.verifyCallback, verifyOpts.verification.checkLinkedDomain);
    } else if (!verifyOpts.verification.checkLinkedDomain) {
      await validateLinkedDomainWithDid(issuerDid, verifyOpts.verifyCallback, CheckLinkedDomain.IF_PRESENT);
    }
    const verPayload = verifiedJWT.payload as IdToken;
    assertValidResponseJWT({ header, verPayload: verPayload, audience: verifyOpts.audience });
    // Enforces verifyPresentationCallback function on the RP side,
    if (!verifyOpts?.presentationVerificationCallback) {
      throw new Error(SIOPErrors.VERIFIABLE_PRESENTATION_VERIFICATION_FUNCTION_MISSING);
    }

    return {
      signer: verifiedJWT.signer,
      didResolutionResult: verifiedJWT.didResolutionResult,
      jwt,
      verifyOpts,
      issuer: issuerDid,
      payload: {
        ...verPayload,
      },
    };
  }
  static async verifyVPs(payload: AuthenticationResponsePayload, verifyOpts: VerifyAuthenticationResponseOpts) {
    await assertValidVerifiablePresentations({
      definitions: verifyOpts?.claims?.presentationDefinitions,
      vps: payload.vp_token ? [payload.vp_token]: undefined,
      presentationVerificationCallback: verifyOpts?.presentationVerificationCallback,
    });

    const revocationVerification = verifyOpts.verification.revocationOpts
      ? verifyOpts.verification.revocationOpts.revocationVerification
      : RevocationVerification.IF_PRESENT;
    if (revocationVerification !== RevocationVerification.NEVER) {
      // TODO check if this shouldn't be an array
      await verifyRevocation(payload.vp_token, verifyOpts.verification.revocationOpts.revocationVerificationCallback, revocationVerification);
    }
  }
}

function assertValidResponseJWT(opts: { header: JWTHeader; payload?: JWTPayload; verPayload?: IdToken; audience?: string }) {
  if (!opts.header) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  }
  if (opts.payload) {
    if (opts.payload.iss !== ResponseIss.SELF_ISSUED_V2) {
      throw new Error(`${SIOPErrors.NO_SELFISSUED_ISS}, got: ${opts.payload.iss}`);
    }
  }

  if (opts.verPayload) {
    if (!opts.verPayload.nonce) {
      throw Error(SIOPErrors.NO_NONCE);
    } else if (!opts.verPayload.sub_type) {
      throw Error(SIOPErrors.NO_SUB_TYPE);
    } else if (!opts.verPayload.exp || opts.verPayload.exp < Date.now() / 1000) {
      throw Error(SIOPErrors.EXPIRED);
      /*} else if (!opts.verPayload.iat || opts.verPayload.iat > (Date.now() / 1000)) {
                        throw Error(SIOPErrors.EXPIRED);*/
      // todo: Add iat check
    }
    if ((opts.verPayload.aud && !opts.audience) || (!opts.verPayload.aud && opts.audience)) {
      throw Error(SIOPErrors.BAD_PARAMS);
    } else if (opts.audience && opts.audience != opts.verPayload.aud) {
      throw Error(SIOPErrors.INVALID_AUDIENCE);
    }
  }
}

async function createThumbprintAndJWK(resOpts: AuthenticationResponseOpts): Promise<{ thumbprint: string; subJwk: JWK }> {
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
}

function extractPresentations(resOpts: AuthenticationResponseOpts) {
  const presentationPayloads =
    resOpts.vp && resOpts.vp.length > 0
      ? resOpts.vp
          .filter((vp) => vp.location === PresentationLocation.ID_TOKEN)
          .map<VerifiablePresentationPayload>((vp) => vp as VerifiablePresentationPayload)
      : undefined;
  const vp_tokens =
    resOpts.vp && resOpts.vp.length > 0
      ? resOpts.vp
          .filter((vp) => vp.location === PresentationLocation.VP_TOKEN)
          .map<VerifiablePresentationPayload>((vp) => vp as VerifiablePresentationPayload)
      : undefined;
  let vp_token;
  if (vp_tokens) {
    if (vp_tokens.length == 1) {
      vp_token = vp_tokens[0];
    } else if (vp_tokens.length > 1) {
      throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
    }
  }
  const verifiable_presentations = presentationPayloads && presentationPayloads.length > 0 ? presentationPayloads : undefined;
  return {
    verifiable_presentations,
    vp_token,
  };
}

async function createSIOPIDToken(verifiedJwt: VerifiedAuthenticationRequestWithJWT, resOpts: AuthenticationResponseOpts): Promise<IdToken> {
  assertValidResponseOpts(resOpts);
  if (!verifiedJwt || !verifiedJwt.jwt) {
    throw new Error(SIOPErrors.VERIFY_BAD_PARAMS);
  }
  const supportedDidMethods = verifiedJwt.payload.registration?.subject_syntax_types_supported?.filter((sst) =>
    sst.includes(SubjectSyntaxTypesSupportedValues.DID.valueOf())
  );
  const state = resOpts.state || getState(verifiedJwt.payload.state);
  const nonce = verifiedJwt.payload.nonce || resOpts.nonce || getNonce(state);
  const { verifiable_presentations } = extractPresentations(resOpts);
  const id_token: IdToken = {
    iss: ResponseIss.SELF_ISSUED_V2,
    aud: verifiedJwt.payload.redirect_uri,
    iat: Date.now() / 1000,
    exp: Date.now() / 1000 + (resOpts.expiresIn || 600),
    sub: resOpts.did,
    auth_time: verifiedJwt.payload.auth_time,
    nonce,
    _vp_token: {
      // right now pex doesn't support presentation_submission for multiple VPs (as well as multiple VPs)
      presentation_submission: verifiable_presentations ? verifiable_presentations[0].presentation.presentation_submission : undefined,
    },
    //not officially in the specs
    state,
    did: resOpts.did,
    sub_type: supportedDidMethods.length && resOpts.did ? SubjectIdentifierType.DID : SubjectIdentifierType.JKT,
  };
  if (supportedDidMethods.indexOf(SubjectSyntaxTypesSupportedValues.JWK_THUMBPRINT) != -1 && !resOpts.did) {
    const { thumbprint, subJwk } = await createThumbprintAndJWK(resOpts);
    id_token['sub_jwk'] = subJwk;
    id_token.sub = thumbprint;
  }
  return id_token;
}

async function createSIOPResponsePayload(
  verifiedJwt: VerifiedAuthenticationRequestWithJWT,
  resOpts: AuthenticationResponseOpts
): Promise<AuthenticationResponsePayload> {
  assertValidResponseOpts(resOpts);
  if (!verifiedJwt || !verifiedJwt.jwt) {
    throw new Error(SIOPErrors.VERIFY_BAD_PARAMS);
  }
  const registration = createDiscoveryMetadataPayload(resOpts.registration);

  const { vp_token } = extractPresentations(resOpts);
  const authenticationResponsePayload: Partial<AuthenticationResponsePayload> = {
    registration,
    access_token: resOpts.accessToken,
    token_type: resOpts.tokenType,
    refresh_token: resOpts.refreshToken,
    expires_in: resOpts.expiresIn,
  };
  // add support for multiple VPs (VDX-158)
  if (resOpts.vp && resOpts.vp[0].location === PresentationLocation.ID_TOKEN) {
    let vp_token;
    if (resOpts.vp.length > 1) {
      vp_token = [];
      for (const vptPayload of resOpts.vp) {
        if (ObjectUtils.isString(vptPayload.presentation)) {
          vp_token.push({
            presentation: vptPayload.presentation,
          });
        } else {
          vp_token.push(vptPayload.presentation);
        }
      }
    } else if (resOpts.vp.length === 1) {
      if (ObjectUtils.isString(resOpts.vp)) {
        vp_token = { presentation: resOpts.vp };
      } else {
        vp_token = resOpts.vp;
      }
    }
    authenticationResponsePayload.vp_token = vp_token;
  } else {
    authenticationResponsePayload.vp_token = vp_token;
  }
  return authenticationResponsePayload as AuthenticationResponsePayload;
}

function assertValidResponseOpts(opts: AuthenticationResponseOpts) {
  if (!opts /*|| !opts.redirectUri*/ || !opts.signatureType /*|| !opts.nonce*/ || !opts.did) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  } else if (!(isInternalSignature(opts.signatureType) || isExternalSignature(opts.signatureType) || isSuppliedSignature(opts.signatureType))) {
    throw new Error(SIOPErrors.SIGNATURE_OBJECT_TYPE_NOT_SET);
  }
}

function assertValidVerifyOpts(opts: VerifyAuthenticationResponseOpts) {
  if (!opts || !opts.verification || (!isExternalVerification(opts.verification) && !isInternalVerification(opts.verification))) {
    throw new Error(SIOPErrors.VERIFY_BAD_PARAMS);
  }
}

async function assertValidVerifiablePresentations(args: {
  definitions: PresentationDefinitionWithLocation[];
  vps: VerifiablePresentationPayload[];
  presentationVerificationCallback?: PresentationVerificationCallback;
}) {
  if ((!args.definitions || args.definitions.length == 0) && !args.vps) {
    return;
  }

  // const definitions: PresentationDefinitionWithLocation[] = verifyOpts?.claims?.presentationDefinitions;
  PresentationExchange.assertValidPresentationDefinitionWithLocations(args.definitions);
  const presentationPayloads: VerifiablePresentationPayload[] = [];
  let presentationSubmission: PresentationSubmission;
  if (args.vps && args.vps.length > 0) {
    presentationPayloads.push(...args.vps);
    // TODO check how to handle multiple VPs
    if (args.vps[0].presentation?.presentation_submission) {
      presentationSubmission = args.vps[0].presentation.presentation_submission;
    }
  }

  if (args.definitions && args.definitions.length && !presentationPayloads) {
    throw new Error(SIOPErrors.AUTH_REQUEST_EXPECTS_VP);
  } else if (!args.definitions && presentationPayloads) {
    throw new Error(SIOPErrors.AUTH_REQUEST_DOESNT_EXPECT_VP);
  } else if (args.definitions && presentationPayloads && args.definitions.length != presentationPayloads.length) {
    throw new Error(SIOPErrors.AUTH_REQUEST_EXPECTS_VP);
  } else if (args.definitions && presentationPayloads) {
    await PresentationExchange.validatePayloadsAgainstDefinitions(
      args.definitions,
      presentationPayloads,
      presentationSubmission,
      args.presentationVerificationCallback
    );
  }
}
