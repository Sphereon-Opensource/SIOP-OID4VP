import AuthenticationRequest from './AuthenticationRequest';
import { fetchDidDocument } from './functions/DIDResolution';
import { signDidJwtPayload } from './functions/DidJWT';
import { getPublicJWKFromHexPrivateKey, getThumbprint, getThumbprintFromJwk } from './functions/Keys';
import { SIOP, SIOPErrors } from './types';

export default class AuthenticationResponse {
  static async createJWTFromVerifiedRequest(
    verifiedJwt: SIOP.VerifiedAuthenticationRequestWithJWT,
    resOpts: SIOP.AuthenticationResponseOpts
  ): Promise<string> {
    console.log(verifiedJwt);

    const payload = await createSIOPResponsePayload(resOpts);
    return signDidJwtPayload(payload, resOpts);

    /*if (isInternalSignature(resOpts.signatureType)) {
                        return DIDJwt.signDidJwtInternal(payload, ResponseIss.SELF_ISSUED_V2, resOpts.signatureType.hexPrivateKey, resOpts.signatureType.kid);
                    } else if (isExternalSignature(resOpts.signatureType)) {
                        return DIDJwt.signDidJwtExternal(payload, resOpts.signatureType.signatureUri, resOpts.signatureType.authZToken, resOpts.signatureType.kid);
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
   * Creates a SIOP Response Object
   *
   * @param didAuthResponse
   */
  static async createJWTFromRequestJWT(
    requestJwt: string,
    resOpts: SIOP.AuthenticationResponseOpts,
    verifyOpts?: SIOP.VerifyAuthenticationRequestOpts
  ): Promise<string> {
    assertValidResponseOpts(resOpts);
    const verifiedJWT = await AuthenticationRequest.verifyJWT(requestJwt, verifyOpts);
    return AuthenticationResponse.createJWTFromVerifiedRequest(verifiedJWT, resOpts);
  }
}

async function createSIOPResponsePayload(
  opts: SIOP.AuthenticationResponseOpts
): Promise<SIOP.AuthenticationResponsePayload> {
  assertValidResponseOpts(opts);

  let thumbprint;
  let subJwk;
  if (SIOP.isInternalSignature(opts.signatureType)) {
    thumbprint = getThumbprint(opts.signatureType.hexPrivateKey, opts.did);
    subJwk = getPublicJWKFromHexPrivateKey(
      opts.signatureType.hexPrivateKey,
      opts.signatureType.kid || `${opts.signatureType.did}#key-1`,
      opts.did
    );
  } else if (SIOP.isExternalSignature(opts.signatureType)) {
    const didDocument = await fetchDidDocument(opts.registration.registrationBy.referenceUri);
    thumbprint = getThumbprintFromJwk(didDocument.verificationMethod[0].publicKeyJwk, opts.did);
    subJwk = didDocument.verificationMethod[0].publicKeyJwk;
  } else {
    throw new Error('SIGNATURE_OBJECT_TYPE_NOT_SET');
  }

  return {
    iss: SIOP.ResponseIss.SELF_ISSUED_V2,
    sub: thumbprint,
    aud: opts.redirectUri,
    nonce: opts.nonce,
    did: opts.did,
    sub_jwk: subJwk,
    vp: opts.vp,
  };
}

function assertValidResponseOpts(opts: SIOP.AuthenticationResponseOpts) {
  if (!opts || !opts.redirectUri || !opts.signatureType || !opts.nonce || !opts.did) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  } else if (!(SIOP.isInternalSignature(opts.signatureType) || SIOP.isExternalSignature(opts.signatureType))) {
    throw new Error(SIOPErrors.SIGNATURE_OBJECT_TYPE_NOT_SET);
  }
}
