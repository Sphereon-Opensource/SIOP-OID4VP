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
    const payload = await createSIOPResponsePayload(verifiedJwt, responseOpts);
    await assertValidVerifiablePresentations({
      definitions: verifiedJwt.presentationDefinitions,
      verPayload: payload,
      presentationVerificationCallback: responseOpts.presentationVerificationCallback,
    });
    const jwt = await signDidJwtPayload(payload, responseOpts);
    return {
      jwt,
      state: payload.state,
      nonce: payload.nonce,
      payload,
      responseOpts,
    };

    // todo add uri generation support in separate method, like in the AuthRequest class

    /*if (isInternalSignature(responseOpts.signatureType)) {
                                                    return DIDJwt.signDidJwtInternal(payload, ResponseIss.SELF_ISSUED_V2, responseOpts.signatureType.hexPrivateKey, responseOpts.signatureType.kid);
                                                } else if (isExternalSignature(responseOpts.signatureType)) {
                                                    return DIDJwt.signDidJwtExternal(payload, responseOpts.signatureType.signatureUri, responseOpts.signatureType.authZToken, responseOpts.signatureType.kid);
                                                } else {
                                                    throw new Error("INVALID_SIGNATURE_TYPE");
                                                }*/
    /*const params = `id_token=${JWT}`;
                                                const uriResponse = {
                                                    encodedUri: "",
                                                    bodyEncoded: "",
                                                    encodingFormat: UrlEncodingFormat.FORM_URL_ENCODED,
                                                    responseMode: didAuthResponseCall.responseMode
                                                        ? didAuthResponseCall.responseMode
                                                        : ResponseMode.FRAGMENT, // FRAGMENT is the default
                                                };

                                                if (didAuthResponseCall.responseMode === ResponseMode.FORM_POST) {
                                                    uriResponse.encodedUri = encodeURI(didAuthResponseCall.redirectUri);
                                                    uriResponse.bodyEncoded = encodeURI(params);
                                                } else if (didAuthResponseCall.responseMode === ResponseMode.QUERY) {
                                                    uriResponse.encodedUri = encodeURI(`${didAuthResponseCall.redirectUri}?${params}`);
                                                } else {
                                                    uriResponse.responseMode = ResponseMode.FRAGMENT;
                                                    uriResponse.encodedUri = encodeURI(`${didAuthResponseCall.redirectUri}#${params}`);
                                                }
                                                return uriResponse;*/
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
    const verPayload = verifiedJWT.payload as AuthenticationResponsePayload;
    assertValidResponseJWT({ header, verPayload: verPayload, audience: verifyOpts.audience });
    // Enforces verifyPresentationCallback function on the RP side,
    if (!verifyOpts?.presentationVerificationCallback) {
      throw new Error(SIOPErrors.VERIFIABLE_PRESENTATION_VERIFICATION_FUNCTION_MISSING);
    }
    await assertValidVerifiablePresentations({
      definitions: verifyOpts?.claims?.presentationDefinitions,
      verPayload,
      presentationVerificationCallback: verifyOpts?.presentationVerificationCallback,
    });

    const revocationVerification = verifyOpts.verification.revocationOpts
      ? verifyOpts.verification.revocationOpts.revocationVerification
      : RevocationVerification.IF_PRESENT;
    if (revocationVerification !== RevocationVerification.NEVER) {
      await verifyRevocation(verPayload.vp_token, verifyOpts.verification.revocationOpts.revocationVerificationCallback, revocationVerification);
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
}

function assertValidResponseJWT(opts: { header: JWTHeader; payload?: JWTPayload; verPayload?: AuthenticationResponsePayload; audience?: string }) {
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
    /*  } else if (isExternalSignature(resOpts.signatureType)) {
                    const didDocument = await fetchDidDocument(resOpts.registration.registrationBy.referenceUri as string);
                    if (!didDocument.verificationMethod || didDocument.verificationMethod.length == 0) {
                      throw Error(SIOPErrors.VERIFY_BAD_PARAMS);
                    }
                    thumbprint = getThumbprintFromJwk(didDocument.verificationMethod[0].publicKeyJwk as JWK, resOpts.did);
                    subJwk = didDocument.verificationMethod[0].publicKeyJwk as JWK;*/
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

async function createSIOPResponsePayload(
  verifiedJwt: VerifiedAuthenticationRequestWithJWT,
  resOpts: AuthenticationResponseOpts
): Promise<AuthenticationResponsePayload> {
  assertValidResponseOpts(resOpts);
  if (!verifiedJwt || !verifiedJwt.jwt) {
    throw new Error(SIOPErrors.VERIFY_BAD_PARAMS);
  }
  const supportedDidMethods = verifiedJwt.payload.registration?.subject_syntax_types_supported?.filter((sst) =>
    sst.includes(SubjectSyntaxTypesSupportedValues.DID.valueOf())
  );

  const state = resOpts.state || getState(verifiedJwt.payload.state);
  const nonce = verifiedJwt.payload.nonce || resOpts.nonce || getNonce(state);
  const registration = createDiscoveryMetadataPayload(resOpts.registration);

  //https://sphereon.atlassian.net/browse/VDX-140
  // *********************************************************************************
  // todo We are missing a wrapper object. Actually the current object is the id_token
  // *********************************************************************************

  const { verifiable_presentations, vp_token } = extractPresentations(resOpts);
  const verifiablePresentations = [];
  if (verifiable_presentations && verifiable_presentations.length > 0) {
    for (const vpPayload of verifiable_presentations) {
      verifiablePresentations.push({
        format: vpPayload.format,
        presentation: await resOpts.presentationSignCallback(vpPayload.presentation),
      });
    }
  }
  const authenticationResponsePayload: AuthenticationResponsePayload = {
    iss: ResponseIss.SELF_ISSUED_V2,
    sub: resOpts.did,
    aud: verifiedJwt.payload.redirect_uri,
    did: resOpts.did,
    sub_type: supportedDidMethods.length && resOpts.did ? SubjectIdentifierType.DID : SubjectIdentifierType.JKT,
    state,
    nonce,
    iat: Date.now() / 1000,
    exp: Date.now() / 1000 + (resOpts.expiresIn || 600),
    registration,
    vp_token,
  };
  if (verifiablePresentations.length > 0) {
    authenticationResponsePayload.verifiable_presentations = verifiablePresentations;
  }
  if (supportedDidMethods.indexOf(SubjectSyntaxTypesSupportedValues.JWK_THUMBPRINT) != -1 && !resOpts.did) {
    const { thumbprint, subJwk } = await createThumbprintAndJWK(resOpts);
    authenticationResponsePayload.sub_jwk = subJwk;
    authenticationResponsePayload.sub = thumbprint;
  }
  return authenticationResponsePayload;
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
  verPayload: AuthenticationResponsePayload;
  presentationVerificationCallback?: PresentationVerificationCallback;
}) {
  if ((!args.definitions || args.definitions.length == 0) && !args.verPayload) {
    return;
  }

  // const definitions: PresentationDefinitionWithLocation[] = verifyOpts?.claims?.presentationDefinitions;
  PresentationExchange.assertValidPresentationDefinitionWithLocations(args.definitions);
  let presentationPayloads: VerifiablePresentationPayload[];
  if (args.verPayload.verifiable_presentations && args.verPayload.verifiable_presentations.length > 0) {
    presentationPayloads = args.verPayload.verifiable_presentations;
  }
  if (args.verPayload.vp_token) {
    if (!presentationPayloads) {
      presentationPayloads = [args.verPayload.vp_token];
    } else {
      presentationPayloads.push(args.verPayload.vp_token);
    }
  }

  /*console.log('pd:', JSON.stringify(definitions));
  console.log('vps:', JSON.stringify(presentationPayloads));*/
  if (args.definitions && args.definitions.length > 0 && !presentationPayloads) {
    throw new Error(SIOPErrors.AUTH_REQUEST_EXPECTS_VP);
  } else if (!args.definitions && presentationPayloads) {
    throw new Error(SIOPErrors.AUTH_REQUEST_DOESNT_EXPECT_VP);
  } else if (args.definitions && presentationPayloads && args.definitions.length != presentationPayloads.length) {
    throw new Error(SIOPErrors.AUTH_REQUEST_EXPECTS_VP);
  } else if (args.definitions && presentationPayloads) {
    await PresentationExchange.validatePayloadsAgainstDefinitions(args.definitions, presentationPayloads, args.presentationVerificationCallback);
  }
}
