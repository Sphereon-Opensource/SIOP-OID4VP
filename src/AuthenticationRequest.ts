import { JWTHeader } from 'did-jwt';

import { assertValidRequestRegistrationOpts, createRequestRegistration } from './AuthenticationRequestRegistration';
import { PresentationExchangeAgent } from './PresentationExchangeAgent';
import { DIDJwt, DIDres, Encodings, State } from './functions';
import { decodeUriAsJson } from './functions/Encodings';
import { JWT, SIOP, SIOPErrors } from './types';
import { AuthenticationRequestPayload } from './types/SIOP.types';

export default class AuthenticationRequest {
  /**
   * Create a signed URL encoded URI with a signed SIOP request token on RP side
   *
   * @param opts Request input data to build a  SIOP Request Token
   * @remarks This method is used to generate a SIOP request with info provided by the RP.
   * First it generates the request payload and then it creates the signed JWT, which is returned as a URI
   *
   * Normally you will want to use this method to create the request.
   */
  static async createURI(opts: SIOP.AuthenticationRequestOpts): Promise<SIOP.AuthenticationRequestURI> {
    const { jwt, payload } = await AuthenticationRequest.createJWT(opts);
    return createURIFromJWT(opts, payload, jwt);
  }

  /**
   * Create a Authentication Request Payload from a URI string
   *
   * @param uri
   */
  static parseURI(uri: string): AuthenticationRequestPayload {
    return decodeUriAsJson(uri.replace(/^.*:\/\/\??/, '')) as AuthenticationRequestPayload;
  }

  /**
   * Create a signed SIOP request as JWT on RP side, typically you will want to use the createURI version!
   *
   * @param opts Request input data to build a SIOP Request as JWT
   * @remarks This method is used to generate a SIOP request with info provided by the RP.
   * First it generates the request payload and then it creates the signed JWT.
   *
   * Normally you will want to use the createURI version. That creates a URI that includes the JWT from this method in the URI
   * If you do use this method, you can call the wrapInUri afterwards to get the URI
   */
  static async createJWT(opts: SIOP.AuthenticationRequestOpts): Promise<SIOP.AuthenticationRequestWithJWT> {
    const siopRequestPayload = createInitialRequestPayload(opts);
    const { nonce, state } = siopRequestPayload;
    const jwt = await DIDJwt.signDidJwtPayload(siopRequestPayload, opts);

    return {
      jwt,
      nonce,
      state,
      payload: siopRequestPayload,
      opts: opts,
    };
  }

  static wrapAsURI(request: SIOP.AuthenticationRequestWithJWT): SIOP.AuthenticationRequestURI {
    return createURIFromJWT(request.opts, request.payload, request.jwt);
  }

  /**
   * Verifies a SIOP Request JWT on OP side
   *
   * @param jwt
   * @param opts
   */
  static async verifyJWT(
    jwt: string,
    opts: SIOP.VerifyAuthenticationRequestOpts
  ): Promise<SIOP.VerifiedAuthenticationRequestWithJWT> {
    assertValidVerifyOpts(opts);
    if (!jwt) {
      throw new Error(SIOPErrors.NO_JWT);
    }

    const { header, payload } = DIDJwt.parseJWT(jwt);
    assertValidRequestJWT(header, payload);

    // const issuerDid = DIDJwt.getIssuerDidFromPayload(payload);
    // const issuerDidDoc = await DIDres.resolveDidDocument(issuerDid, opts.verification.resolveOpts);

    /*
            // Determine the verification method from the RP's DIDres Document that matches the kid of the SIOP Request.
            const verificationMethod = Keys.getVerificationMethod(header.kid, issuerDidDoc);
            if (!verificationMethod) {
              throw new Error(`${SIOPErrors.VERIFICATION_METHOD_NO_MATCH} kid: ${header.kid}, issuer: ${issuerDid}`);
            }
        */
    // as audience is set in payload as a DID it is required to be set as options
    const options = {
      audience: DIDJwt.getAudience(jwt),
      /*proofPurpose: verificationMethod.type as ProofPurposeTypes,*/
    };

    const verifiedJWT = await DIDJwt.verifyDidJWT(jwt, DIDres.getResolver(opts.verification.resolveOpts), options);
    if (!verifiedJWT || !verifiedJWT.payload) {
      throw Error(SIOPErrors.ERROR_VERIFYING_SIGNATURE);
    }
    const verPayload = verifiedJWT.payload as AuthenticationRequestPayload;
    if (opts.nonce && verPayload.nonce !== opts.nonce) {
      throw new Error(`${SIOPErrors.BAD_NONCE} payload: ${verifiedJWT.payload.nonce}, supplied: ${opts.nonce}`);
    } else if (
      verPayload.registration?.subject_identifiers_supported &&
      verPayload.registration.subject_identifiers_supported.length == 0
    ) {
      throw new Error(`${SIOPErrors.VERIFY_BAD_PARAMS}`);
    }
    return {
      ...verifiedJWT,
      verifyOpts: opts,
      payload: verifiedJWT.payload as AuthenticationRequestPayload,
    };
  }
}

/***************************************
 *
 * Helper functions are down below
 *
 ***************************************/

/**
 * Creates an URI Request
 * @param requestOpts Options to define the Uri Request
 * @param requestPayload
 * @param jwt
 * @param requestPayload
 * @param jwt
 */
function createURIFromJWT(
  requestOpts: SIOP.AuthenticationRequestOpts,
  requestPayload: SIOP.AuthenticationRequestPayload,
  jwt: string
): SIOP.AuthenticationRequestURI {
  const schema = 'openid://';
  const peAgent: PresentationExchangeAgent = new PresentationExchangeAgent();
  peAgent.findValidPresentationDefinition(requestPayload, '$..presentation_definition');
  const query = Encodings.encodeJsonAsURI(requestPayload);

  switch (requestOpts.requestBy?.type) {
    case SIOP.PassBy.REFERENCE:
      return {
        encodedUri: `${schema}?${query}&request_uri=${encodeURIComponent(requestOpts.requestBy.referenceUri)}`,
        encodingFormat: SIOP.UrlEncodingFormat.FORM_URL_ENCODED,
        requestOpts,
        requestPayload,
        jwt,
      };
    case SIOP.PassBy.VALUE:
      return {
        encodedUri: `${schema}?${query}&request=${jwt}`,
        encodingFormat: SIOP.UrlEncodingFormat.FORM_URL_ENCODED,
        requestOpts,
        requestPayload,
        jwt,
      };
  }
  throw new Error(SIOPErrors.REQUEST_OBJECT_TYPE_NOT_SET);
}

function assertValidRequestJWT(_header: JWTHeader, _payload: JWT.JWTPayload) {
  /*console.log(_header);
  console.log(_payload);*/
}

function assertValidVerifyOpts(opts: SIOP.VerifyAuthenticationRequestOpts) {
  if (
    !opts ||
    !opts.verification ||
    (!SIOP.isExternalVerification(opts.verification) && !SIOP.isInternalVerification(opts.verification))
  ) {
    throw new Error(SIOPErrors.VERIFY_BAD_PARAMS);
  }
}

function assertValidRequestOpts(opts: SIOP.AuthenticationRequestOpts) {
  if (!opts || !opts.redirectUri) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  } else if (!opts.requestBy) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  } else if (opts.requestBy.type !== SIOP.PassBy.REFERENCE && opts.requestBy.type !== SIOP.PassBy.VALUE) {
    throw new Error(SIOPErrors.REQUEST_OBJECT_TYPE_NOT_SET);
  } else if (opts.requestBy.type === SIOP.PassBy.REFERENCE && !opts.requestBy.referenceUri) {
    throw new Error(SIOPErrors.NO_REFERENCE_URI);
  }
  assertValidRequestRegistrationOpts(opts.registration);
}

function createInitialRequestPayload(opts: SIOP.AuthenticationRequestOpts): SIOP.AuthenticationRequestPayload {
  assertValidRequestOpts(opts);
  const state = State.getState(opts.state);
  const registration = createRequestRegistration(opts.registration);

  return {
    response_type: SIOP.ResponseType.ID_TOKEN,
    scope: SIOP.Scope.OPENID,
    client_id: opts.signatureType.did || opts.redirectUri, //todo: check whether we should include opts.redirectUri value here, or the whole of client_id to begin with
    redirect_uri: opts.redirectUri,
    iss: opts.signatureType.did,
    response_mode: opts.responseMode || SIOP.ResponseMode.POST,
    response_context: opts.responseContext || SIOP.ResponseContext.RP,
    nonce: State.getNonce(state, opts.nonce),
    state,
    ...registration.requestRegistrationPayload,
    claims: opts.claims,
  };
}
