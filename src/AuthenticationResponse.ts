import { JWTHeader } from 'did-jwt';
import { JWK } from 'jose/types';

import AuthenticationRequest from './AuthenticationRequest';
import { createDiscoveryMetadataPayload } from './AuthenticationResponseRegistration';
import { DIDJwt, DIDres, State } from './functions';
import { fetchDidDocument } from './functions/DIDResolution';
import { signDidJwtPayload, verifyDidJWT } from './functions/DidJWT';
import { getPublicJWKFromHexPrivateKey, getThumbprint, getThumbprintFromJwk } from './functions/Keys';
import { JWT, SIOP, SIOPErrors } from './types';
import {
  AuthenticationResponsePayload,
  SubjectIdentifierType,
  VerifiedAuthenticationResponseWithJWT,
  VerifyAuthenticationResponseOpts,
} from './types/SIOP.types';

export default class AuthenticationResponse {
  /**
   * Creates a SIOP Response Object
   *
   * @param didAuthResponse
   */
  static async createJWTFromRequestJWT(
    requestJwt: string,
    responseOpts: SIOP.AuthenticationResponseOpts,
    verifyOpts: SIOP.VerifyAuthenticationRequestOpts
  ): Promise<SIOP.AuthenticationResponseWithJWT> {
    assertValidResponseOpts(responseOpts);
    const verifiedJWT = await AuthenticationRequest.verifyJWT(requestJwt, verifyOpts);
    return AuthenticationResponse.createJWTFromVerifiedRequest(verifiedJWT, responseOpts);
  }

  static async createJWTFromVerifiedRequest(
    verifiedJwt: SIOP.VerifiedAuthenticationRequestWithJWT,
    responseOpts: SIOP.AuthenticationResponseOpts
  ): Promise<SIOP.AuthenticationResponseWithJWT> {
    // console.log(JSON.stringify(verifiedJwt));

    const payload = await createSIOPResponsePayload(verifiedJwt, responseOpts);
    const jwt = await signDidJwtPayload(payload, responseOpts);

    console.log(jwt);
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
                                        encodingFormat: SIOP.UrlEncodingFormat.FORM_URL_ENCODED,
                                        responseMode: didAuthResponseCall.responseMode
                                            ? didAuthResponseCall.responseMode
                                            : SIOP.ResponseMode.FRAGMENT, // FRAGMENT is the default
                                    };

                                    if (didAuthResponseCall.responseMode === SIOP.ResponseMode.FORM_POST) {
                                        uriResponse.encodedUri = encodeURI(didAuthResponseCall.redirectUri);
                                        uriResponse.bodyEncoded = encodeURI(params);
                                    } else if (didAuthResponseCall.responseMode === SIOP.ResponseMode.QUERY) {
                                        uriResponse.encodedUri = encodeURI(`${didAuthResponseCall.redirectUri}?${params}`);
                                    } else {
                                        uriResponse.responseMode = SIOP.ResponseMode.FRAGMENT;
                                        uriResponse.encodedUri = encodeURI(`${didAuthResponseCall.redirectUri}#${params}`);
                                    }
                                    return uriResponse;*/
  }

  /**
   * Verifies a SIOP ID Response JWT on the RP Side
   *
   * @param jwt ID token to be validated
   * @param audience expected audience
   */
  static async verifyJWT(
    jwt: string,
    verifyOpts: VerifyAuthenticationResponseOpts
  ): Promise<VerifiedAuthenticationResponseWithJWT> {
    if (!jwt) {
      throw new Error(SIOPErrors.NO_JWT);
    }
    assertValidVerifyOpts(verifyOpts);

    const { header, payload } = DIDJwt.parseJWT(jwt);
    assertValidResponseJWT({ header, payload });

    const verifiedJWT = await verifyDidJWT(jwt, DIDres.getResolver(verifyOpts.verification.resolveOpts), {
      audience: verifyOpts.audience,
    });

    const issuerDid = DIDJwt.getIssuerDidFromPayload(payload);

    if (!verifiedJWT || !verifiedJWT.payload) {
      throw Error(SIOPErrors.ERROR_VERIFYING_SIGNATURE);
    }
    const verPayload = verifiedJWT.payload as AuthenticationResponsePayload;
    assertValidResponseJWT({ header, verPayload: verPayload, audience: verifyOpts.audience });

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

function assertValidResponseJWT(opts: {
  header: JWTHeader;
  payload?: JWT.JWTPayload;
  verPayload?: AuthenticationResponsePayload;
  audience?: string;
}) {
  if (!opts.header) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  }
  if (opts.payload) {
    if (opts.payload.iss !== SIOP.ResponseIss.SELF_ISSUED_V2) {
      throw new Error(`${SIOPErrors.NO_SELFISSUED_ISS}, got: ${opts.payload.iss}`);
    }
  }

  if (opts.verPayload) {
    if (!opts.verPayload.nonce) {
      throw Error(SIOPErrors.NO_NONCE);
    } else if (!opts.verPayload.sub_type) {
      throw Error(SIOPErrors.NO_SUB_TYPE);
    } else if (opts.audience && opts.audience != opts.verPayload.aud) {
      throw Error(SIOPErrors.INVALID_AUDIENCE);
    }
  }
}

async function createThumbprintAndJWK(
  resOpts: SIOP.AuthenticationResponseOpts
): Promise<{ thumbprint: string; subJwk: JWK }> {
  let thumbprint;
  let subJwk;
  if (SIOP.isInternalSignature(resOpts.signatureType)) {
    thumbprint = getThumbprint(resOpts.signatureType.hexPrivateKey, resOpts.did);
    subJwk = getPublicJWKFromHexPrivateKey(
      resOpts.signatureType.hexPrivateKey,
      resOpts.signatureType.kid || `${resOpts.signatureType.did}#key-1`,
      resOpts.did
    );
  } else if (SIOP.isExternalSignature(resOpts.signatureType)) {
    const didDocument = await fetchDidDocument(resOpts.registration.registrationBy.referenceUri as string);
    if (!didDocument.verificationMethod || didDocument.verificationMethod.length == 0) {
      throw Error(SIOPErrors.VERIFY_BAD_PARAMS);
    }
    thumbprint = getThumbprintFromJwk(didDocument.verificationMethod[0].publicKeyJwk as JWK, resOpts.did);
    subJwk = didDocument.verificationMethod[0].publicKeyJwk as JWK;
  } else {
    throw new Error(SIOPErrors.SIGNATURE_OBJECT_TYPE_NOT_SET);
  }
  return { thumbprint, subJwk };
}

async function createSIOPResponsePayload(
  verifiedJwt: SIOP.VerifiedAuthenticationRequestWithJWT,
  resOpts: SIOP.AuthenticationResponseOpts
): Promise<SIOP.AuthenticationResponsePayload> {
  assertValidResponseOpts(resOpts);
  if (!verifiedJwt || !verifiedJwt.jwt) {
    throw new Error(SIOPErrors.VERIFY_BAD_PARAMS);
  }
  const isDidSupported = verifiedJwt.payload.registration?.subject_identifiers_supported?.includes(
    SubjectIdentifierType.DID
  );
  // todo did method check against supported did registration value here

  const { thumbprint, subJwk } = await createThumbprintAndJWK(resOpts);
  const state = resOpts.state || State.getState(verifiedJwt.payload.state);
  const nonce = resOpts.nonce || State.getNonce(state, resOpts.nonce);
  const registration = createDiscoveryMetadataPayload(resOpts.registration);
  return {
    iss: SIOP.ResponseIss.SELF_ISSUED_V2,
    sub: isDidSupported && resOpts.did ? resOpts.did : thumbprint,
    aud: verifiedJwt.payload.redirect_uri,
    did: resOpts.did,
    sub_type: isDidSupported && resOpts.did ? SubjectIdentifierType.DID : SubjectIdentifierType.JKT,
    sub_jwk: subJwk,
    state,
    nonce,
    iat: Date.now() / 1000,
    exp: Date.now() / 1000 + (resOpts.expiresIn || 600),
    registration,
    vp: resOpts.vp,
  };
}

function assertValidResponseOpts(opts: SIOP.AuthenticationResponseOpts) {
  if (!opts /*|| !opts.redirectUri*/ || !opts.signatureType /*|| !opts.nonce*/ || !opts.did) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  } else if (!(SIOP.isInternalSignature(opts.signatureType) || SIOP.isExternalSignature(opts.signatureType))) {
    throw new Error(SIOPErrors.SIGNATURE_OBJECT_TYPE_NOT_SET);
  }
}

function assertValidVerifyOpts(opts: SIOP.VerifyAuthenticationResponseOpts) {
  if (
    !opts ||
    !opts.verification ||
    (!SIOP.isExternalVerification(opts.verification) && !SIOP.isInternalVerification(opts.verification))
  ) {
    throw new Error(SIOPErrors.VERIFY_BAD_PARAMS);
  }
}
