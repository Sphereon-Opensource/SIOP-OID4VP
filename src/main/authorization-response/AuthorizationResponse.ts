import { JWTHeader } from 'did-jwt';
import { JWK } from 'jose';

import AuthorizationRequest from '../authorization-request/AuthorizationRequest';
import {
  getPublicJWKFromHexPrivateKey,
  getResolver,
  getSubDidFromPayload,
  getThumbprint,
  parseJWT,
  validateLinkedDomainWithDid,
  verifyDidJWT,
} from '../functions';
import {
  AuthorizationResponseOpts,
  AuthorizationResponseResult,
  CheckLinkedDomain,
  IDTokenPayload,
  isInternalSignature,
  isSuppliedSignature,
  JWTPayload,
  ResponseIss,
  SIOPErrors,
  VerifiablePresentationPayload,
  VerifiedAuthenticationResponse,
  VerifiedAuthorizationRequest,
  VerifyAuthorizationRequestOpts,
  VerifyAuthorizationResponseOpts,
} from '../types';

import { assertValidVerifiablePresentations } from './OpenID4VP';
import { assertValidResponseOpts, assertValidVerifyOpts } from './ResponseOpts';
import { createIDTokenPayload, createResponsePayload } from './ResponsePayload';

export default class AuthorizationResponse {
  /**
   * Creates a SIOP Response Object
   *
   * @param requestObject
   * @param responseOpts
   * @param verifyOpts
   */
  static async createFromRequestObject(
    requestObject: string,
    responseOpts: AuthorizationResponseOpts,
    verifyOpts: VerifyAuthorizationRequestOpts
  ): Promise<AuthorizationResponseResult> {
    assertValidResponseOpts(responseOpts);
    if (!requestObject || !requestObject.startsWith('ey')) {
      throw new Error(SIOPErrors.NO_JWT);
    }
    const verifiedRequest = await AuthorizationRequest.verify(requestObject, verifyOpts);
    return AuthorizationResponse.createFromVerifiedAuthorizationRequest(verifiedRequest, responseOpts);
  }

  // TODO SK Can you please put some documentation on it?
  static async createFromVerifiedAuthorizationRequest(
    authorizationRequest: VerifiedAuthorizationRequest,
    responseOpts: AuthorizationResponseOpts
  ): Promise<AuthorizationResponseResult> {
    const idToken = await createIDTokenPayload(authorizationRequest, responseOpts);
    const authorizationResponse = await createResponsePayload(authorizationRequest, idToken, responseOpts);
    await assertValidVerifiablePresentations({
      presentationDefinitions: authorizationRequest.presentationDefinitions,
      presentationPayloads: authorizationResponse.vp_token as VerifiablePresentationPayload[] | VerifiablePresentationPayload,
      verificationCallback: responseOpts.presentationExchange?.presentationVerificationCallback,
    });

    return {
      state: authorizationResponse.state,
      nonce: idToken.nonce,
      idToken: authorizationResponse.id_token,
      idTokenPayload: idToken,
      responsePayload: authorizationResponse,
      responseOpts,
    };
  }

  /**
   * Verifies a SIOP ID Response JWT on the RP Side
   *
   * @param idToken ID token to be validated
   * @param verifyOpts
   */
  static async verifyIDToken(idToken: string, verifyOpts: VerifyAuthorizationResponseOpts): Promise<VerifiedAuthenticationResponse> {
    if (!idToken) {
      throw new Error(SIOPErrors.NO_JWT);
    }
    assertValidVerifyOpts(verifyOpts);

    const { header, payload } = parseJWT(idToken);
    assertValidResponseJWT({ header, payload });

    const verifiedJWT = await verifyDidJWT(idToken, getResolver(verifyOpts.verification.resolveOpts), {
      audience: verifyOpts.audience,
    });

    const issuerDid = getSubDidFromPayload(payload);
    if (verifyOpts.verification.checkLinkedDomain && verifyOpts.verification.checkLinkedDomain !== CheckLinkedDomain.NEVER) {
      await validateLinkedDomainWithDid(issuerDid, verifyOpts.verifyCallback, verifyOpts.verification.checkLinkedDomain);
    } else if (!verifyOpts.verification.checkLinkedDomain) {
      await validateLinkedDomainWithDid(issuerDid, verifyOpts.verifyCallback, CheckLinkedDomain.IF_PRESENT);
    }
    const verPayload = verifiedJWT.payload as IDTokenPayload;
    assertValidResponseJWT({ header, verPayload: verPayload, audience: verifyOpts.audience });
    // Enforces verifyPresentationCallback function on the RP side,
    if (!verifyOpts?.presentationVerificationCallback) {
      throw new Error(SIOPErrors.VERIFIABLE_PRESENTATION_VERIFICATION_FUNCTION_MISSING);
    }
    return {
      signer: verifiedJWT.signer,
      didResolutionResult: verifiedJWT.didResolutionResult,
      jwt: idToken,
      verifyOpts,
      issuer: issuerDid,
      payload: {
        ...verPayload,
      },
    };
  }
}

function assertValidResponseJWT(opts: { header: JWTHeader; payload?: JWTPayload; verPayload?: IDTokenPayload; audience?: string }) {
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

export async function createThumbprintAndJWK(resOpts: AuthorizationResponseOpts): Promise<{ thumbprint: string; subJwk: JWK }> {
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
