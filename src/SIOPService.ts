// import querystring from "querystring";
import { encodeURI } from 'js-base64';

import { didJwt } from './did';
import { getAudience, signDidJwtPayload } from './did/DidJWT';
import { DidAuth, jwt } from './types';
import {
  PassBy,
  ResponseOpts,
  SIOPRequest,
  SIOPRequestOpts,
  SIOPRequestWithJWT,
  SIOPResponse,
  SIOPURIRequest,
  UrlEncodingFormat,
  VerifyRequestOpts,
} from './types/DidAuth-types';
import { encodeJsonAsURI } from './util/Encodings';
import { fetchDidDocument } from './util/HttpUtils';
import {
  getPublicJWKFromHexPrivateKey,
  getThumbprint,
  getThumbprintFromJwk,
  isExternalSignature,
  isInternalSignature,
} from './util/KeyUtils';
import { getNonce, getState } from './util/StateUtils';

export default class SIOPService {
  /**
   * Create a signed SIOP request as JWT
   *
   * @param opts Request input data to build a SIOP Request as JWT
   */
  static async createRequestJWT(opts: SIOPRequestOpts): Promise<SIOPRequestWithJWT> {
    SIOPService.assertValidRequestOpts(opts);
    const siopRequestPayload = SIOPService.createInitialRequestPayload(opts);
    const { nonce, state } = siopRequestPayload;
    const jwt = await signDidJwtPayload(siopRequestPayload, opts);

    return {
      jwt,
      nonce,
      state,
      origRequest: siopRequestPayload,
      origOpts: opts,
    };
  }

  /**
   * Create a signed URL encoded URI with a signed DidAuth request token
   *
   * @param opts Request input data to build a  DidAuth Request Token
   */
  static async createRequestUri(opts: SIOPRequestOpts): Promise<SIOPURIRequest> {
    SIOPService.assertValidRequestOpts(opts);
    const { jwt, origRequest } = await this.createRequestJWT(opts);
    return SIOPService.createRequestUriFromJwt(opts, origRequest, jwt);
  }

  static createRequestUriFromRequestWithJwt(request: SIOPRequestWithJWT): SIOPURIRequest {
    return SIOPService.createRequestUriFromJwt(request.origOpts, request.origRequest, request.jwt);
  }

  /**
   * Creates an URI Request
   * @param opts Options to define the Uri Request
   */
  static createRequestUriFromJwt(opts: SIOPRequestOpts, siopRequest: SIOPRequest, jwt: string): SIOPURIRequest {
    if (!jwt || !siopRequest || !siopRequest.client_id || !siopRequest.nonce || !siopRequest.state) {
      throw new Error('BAD_PARAMS');
    }
    let uri = 'openid://?';
    uri += encodeJsonAsURI(siopRequest);

    // const responseUri = `openid://?response_type=${DidAuth.ResponseType.ID_TOKEN}&client_id=${opts.redirectUri}&scope=${DidAuth.Scope.OPENID_DIDAUTHN}&state=${state}&nonce=${nonce}`;

    switch (opts.requestBy?.type) {
      case PassBy.REFERENCE:
        return {
          encodedUri: uri + `&request_uri=${encodeURI(opts.requestBy.referenceUri)}`,
          encodingFormat: UrlEncodingFormat.FORM_URL_ENCODED,
          jwt,
        };
      case PassBy.VALUE:
        return {
          encodedUri: uri + `&request=${jwt}`,
          encodingFormat: UrlEncodingFormat.FORM_URL_ENCODED,
        };
    }
    throw new Error('NO_REQUESTBY_TYPE');
  }

  /**
   * Verifies a DidAuth ID Request Token
   *
   * @param jwt
   * @param opts
   */
  static async verifyJWTRequest(jwt: string, opts?: VerifyRequestOpts): Promise<jwt.VerifiedJWT> {
    if (!jwt) {
      throw new Error('VERIFY_BAD_PARAMETERS');
    }

    /*
              const {header, payload} = decodeJWT(jwt);
              const issuerDid = getIssuerDid(jwt);
              const issuerDidDoc = await resolveDidDocument(this.resolver, issuerDid);*/

    // as audience is set in payload as a DID, it is required to be set as options
    const options = {
      audience: getAudience(jwt),
    };
    const verifiedJWT = await didJwt.verifyDidJWT(jwt, opts.resolver, options);
    if (!verifiedJWT || !verifiedJWT.payload) {
      throw Error('ERROR_VERIFYING_SIGNATURE');
    }
    return verifiedJWT;
  }

  /**
   * Creates a DidAuth Response Object
   *
   * @param didAuthResponse
   */
  static async createAuthResponse(opts: ResponseOpts): Promise<string> {
    SIOPService.assertValidResponseOpts(opts);
    const payload = await SIOPService.createAuthResponsePayload(opts);
    return signDidJwtPayload(payload, opts);

    /*if (isInternalSignature(opts.signatureType)) {
            return didJwt.signDidJwtInternal(payload, ResponseIss.SELF_ISSUED_V2, opts.signatureType.hexPrivateKey, opts.signatureType.kid);
        } else if (isExternalSignature(opts.signatureType)) {
            return didJwt.signDidJwtExternal(payload, opts.signatureType.signatureUri, opts.signatureType.authZToken, opts.signatureType.kid);
        } else {
            throw new Error("INVALID_SIGNATURE_TYPE");
        }*/
    /*const params = `id_token=${jwt}`;
        const uriResponse = {
            encodedUri: "",
            bodyEncoded: "",
            encodingFormat: DidAuth.UrlEncodingFormat.FORM_URL_ENCODED,
            responseMode: didAuthResponseCall.responseMode
                ? didAuthResponseCall.responseMode
                : DidAuth.ResponseMode.FRAGMENT, // FRAGMENT is the default
        };

        if (didAuthResponseCall.responseMode === DidAuth.ResponseMode.FORM_POST) {
            uriResponse.encodedUri = encodeURI(didAuthResponseCall.redirectUri);
            uriResponse.bodyEncoded = encodeURI(params);
        } else if (didAuthResponseCall.responseMode === DidAuth.ResponseMode.QUERY) {
            uriResponse.encodedUri = encodeURI(`${didAuthResponseCall.redirectUri}?${params}`);
        } else {
            uriResponse.responseMode = DidAuth.ResponseMode.FRAGMENT;
            uriResponse.encodedUri = encodeURI(`${didAuthResponseCall.redirectUri}#${params}`);
        }
        return uriResponse;*/
  }

  private static async createAuthResponsePayload(opts: ResponseOpts): Promise<SIOPResponse> {
    this.assertValidResponseOpts(opts);

    let thumbprint;
    let subJwk;
    if (isInternalSignature(opts.signatureType)) {
      thumbprint = getThumbprint(opts.signatureType.hexPrivateKey, opts.did);
      subJwk = getPublicJWKFromHexPrivateKey(
        opts.signatureType.hexPrivateKey,
        opts.signatureType.kid || `${opts.signatureType.did}#key-1`,
        opts.did
      );
    } else if (isExternalSignature(opts.signatureType)) {
      const didDocument = await fetchDidDocument(opts);
      thumbprint = getThumbprintFromJwk(didDocument.verificationMethod[0].publicKeyJwk, opts.did);
      subJwk = didDocument.verificationMethod[0].publicKeyJwk;
    } else {
      throw new Error('SIGNATURE_OBJECT_TYPE_NOT_SET');
    }

    return {
      iss: DidAuth.ResponseIss.SELF_ISSUED_V2,
      sub: thumbprint,
      aud: opts.redirectUri,
      nonce: opts.nonce,
      did: opts.did,
      sub_jwk: subJwk,
      vp: opts.vp,
    };
  }

  private static assertValidResponseOpts(opts: ResponseOpts) {
    if (!opts || !opts.redirectUri || !opts.signatureType || !opts.nonce || !opts.did) {
      throw new Error('BAD_PARAMS');
    } else if (!(isInternalSignature(opts.signatureType) || isExternalSignature(opts.signatureType))) {
      throw new Error('SIGNATURE_OBJECT_TYPE_NOT_SET');
    }
  }

  private static assertValidRequestOpts(opts: SIOPRequestOpts) {
    if (!opts || !opts.redirectUri) {
      throw new Error('BAD_PARAMS');
    } else if (!opts.requestBy || !opts.registrationType) {
      throw new Error('BAD_PARAMS');
    } else if (opts.requestBy.type !== PassBy.REFERENCE && opts.requestBy.type !== PassBy.VALUE) {
      throw new Error('REQUEST_OBJECT_TYPE_NOT_SET');
    } else if (opts.requestBy.type === PassBy.REFERENCE && !opts.requestBy.referenceUri) {
      throw new Error('NO_REFERENCE_URI');
    } else if (opts.registrationType.type !== PassBy.REFERENCE && opts.registrationType.type !== PassBy.VALUE) {
      throw new Error('REGISTRATION_OBJECT_TYPE_NOT_SET');
    } else if (opts.registrationType.type === PassBy.REFERENCE && !opts.registrationType.referenceUri) {
      throw new Error('NO_REFERENCE_URI');
    }
  }

  private static createInitialRequestPayload(opts: SIOPRequestOpts): SIOPRequest {
    SIOPService.assertValidRequestOpts(opts);
    const state = getState(opts.state);
    const registration = null;
    const requestPayload = {
      scope: DidAuth.Scope.OPENID,
      response_type: DidAuth.ResponseType.ID_TOKEN,
      client_id: opts.signatureType.did || opts.redirectUri, //todo: check redirectUri value here
      redirect_uri: opts.redirectUri,
      //id_token_hint
      iss: opts.signatureType.did,
      response_mode: opts.responseMode || DidAuth.ResponseMode.POST,
      response_context: opts.responseContext || DidAuth.ResponseContext.RP,
      nonce: getNonce(state, opts.nonce),
      state,
      registration,
      claims: opts.claims,
    };
    return requestPayload;
  }
}
