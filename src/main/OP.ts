import Ajv from 'ajv';
import fetch from 'cross-fetch';

import AuthenticationRequest from './AuthenticationRequest';
import AuthenticationResponse from './AuthenticationResponse';
import OPBuilder from './OPBuilder';
import { getResolver } from './functions/DIDResolution';
import { postAuthenticationResponse, postAuthenticationResponseJwt } from './functions/HttpUtils';
import { AuthenticationResponseOptsSchema } from './schemas/AuthenticationResponseOpts.schema';
import { SIOP, SIOPErrors } from './types';
import {
  AuthenticationResponseOpts,
  AuthenticationResponseWithJWT,
  ExternalVerification,
  InternalVerification,
  ParsedAuthenticationRequestURI,
  ResponseMode,
  ResponseRegistrationOpts,
  UrlEncodingFormat,
  VerifiablePresentationResponseOpts,
  VerificationMode,
  VerifiedAuthenticationRequestWithJWT,
  VerifyAuthenticationRequestOpts,
} from './types/SIOP.types';

const ajv = new Ajv();

const validate = ajv.compile(AuthenticationResponseOptsSchema);

export class OP {
  private readonly _authResponseOpts: AuthenticationResponseOpts;
  private readonly _verifyAuthRequestOpts: Partial<VerifyAuthenticationRequestOpts>;

  public constructor(opts: {
    builder?: OPBuilder;
    responseOpts?: AuthenticationResponseOpts;
    verifyOpts?: VerifyAuthenticationRequestOpts;
  }) {
    this._authResponseOpts = { ...createResponseOptsFromBuilderOrExistingOpts(opts) };
    this._verifyAuthRequestOpts = { ...createVerifyRequestOptsFromBuilderOrExistingOpts(opts) };
  }

  get authResponseOpts(): AuthenticationResponseOpts {
    return this._authResponseOpts;
  }

  get verifyAuthRequestOpts(): Partial<VerifyAuthenticationRequestOpts> {
    return this._verifyAuthRequestOpts;
  }

  public async postAuthenticationResponse(authenticationResponse: AuthenticationResponseWithJWT): Promise<Response> {
    return postAuthenticationResponse(authenticationResponse.payload.aud, authenticationResponse);
  }

  public async verifyAuthenticationRequest(
    requestJwtorUri: string,
    opts?: { nonce?: string; verification?: InternalVerification | ExternalVerification }
  ): Promise<VerifiedAuthenticationRequestWithJWT> {
    const jwt = requestJwtorUri.startsWith('ey') ? requestJwtorUri : (await parseAndResolveUri(requestJwtorUri)).jwt;
    const verifiedJwt = AuthenticationRequest.verifyJWT(jwt, this.newVerifyAuthenticationRequestOpts(opts));
    return verifiedJwt;
  }

  public async createAuthenticationResponse(
    verifiedJwt: SIOP.VerifiedAuthenticationRequestWithJWT,
    responseOpts?: {
      nonce?: string;
      state?: string;
      // audience: string;
      verification?: InternalVerification | ExternalVerification;
      vp?: VerifiablePresentationResponseOpts[];
    }
  ): Promise<AuthenticationResponseWithJWT> {
    return AuthenticationResponse.createJWTFromVerifiedRequest(
      verifiedJwt,
      this.newAuthenticationResponseOpts(responseOpts)
    );
  }

  public async submitAuthenticationResponse(verifiedJwt: SIOP.AuthenticationResponseWithJWT): Promise<Response> {
    if (
      !verifiedJwt ||
      (verifiedJwt.responseOpts.responseMode &&
        !(
          verifiedJwt.responseOpts.responseMode == ResponseMode.POST ||
          verifiedJwt.responseOpts.responseMode == ResponseMode.FORM_POST
        ))
    ) {
      throw new Error(SIOPErrors.BAD_PARAMS);
    }
    return postAuthenticationResponseJwt(verifiedJwt.payload.aud, verifiedJwt.jwt);
  }

  /**
   * Create a Authentication Request Payload from a URI string
   *
   * @param encodedUri
   */
  public async parseAuthenticationRequestURI(encodedUri: string): Promise<ParsedAuthenticationRequestURI> {
    const { requestPayload, jwt, registration } = await parseAndResolveUri(encodedUri);

    return {
      encodedUri,
      encodingFormat: UrlEncodingFormat.FORM_URL_ENCODED,
      jwt,
      requestPayload,
      registration,
    };
  }

  public newAuthenticationResponseOpts(opts?: {
    nonce?: string;
    state?: string;
    vp?: VerifiablePresentationResponseOpts[];
  }): AuthenticationResponseOpts {
    const state = opts?.state;
    const nonce = opts?.nonce;
    const vp = opts?.vp;
    return {
      ...this._authResponseOpts,
      nonce,
      state,
      vp,
    };
  }

  public newVerifyAuthenticationRequestOpts(opts?: {
    nonce?: string;
    verification?: InternalVerification | ExternalVerification;
  }): VerifyAuthenticationRequestOpts {
    return {
      ...this._verifyAuthRequestOpts,
      nonce: opts?.nonce || this._verifyAuthRequestOpts.nonce,
      verification: opts?.verification || this._verifyAuthRequestOpts.verification,
    };
  }

  public static fromOpts(responseOpts: AuthenticationResponseOpts, verifyOpts: VerifyAuthenticationRequestOpts): OP {
    return new OP({ responseOpts, verifyOpts });
  }

  public static builder() {
    return new OPBuilder();
  }
}

async function parseAndResolveUri(encodedUri: string) {
  const requestPayload = AuthenticationRequest.parseURI(encodedUri);
  const jwt = requestPayload.request || (await (await fetch(requestPayload.request_uri)).text());
  const registration = requestPayload.registration || (await (await fetch(requestPayload.registration_uri)).json());
  return { requestPayload, jwt, registration };
}

function createResponseOptsFromBuilderOrExistingOpts(opts: {
  builder?: OPBuilder;
  responseOpts?: AuthenticationResponseOpts;
}) {
  const responseOpts: AuthenticationResponseOpts = opts.builder
    ? {
        registration: opts.builder.responseRegistration as ResponseRegistrationOpts,
        did: opts.builder.signatureType.did,
        expiresIn: opts.builder.expiresIn,
        signatureType: opts.builder.signatureType,
        responseMode: opts.builder.responseMode,
      }
    : { ...opts.responseOpts };

  const valid = validate(responseOpts);
  if (!valid) {
    throw new Error('OP builder validation error: ' + JSON.stringify(validate.errors));
  }
  return responseOpts;
}

function createVerifyRequestOptsFromBuilderOrExistingOpts(opts: {
  builder?: OPBuilder;
  verifyOpts?: Partial<VerifyAuthenticationRequestOpts>;
}) {
  return opts.builder
    ? {
        verification: {
          mode: VerificationMode.INTERNAL,
          resolveOpts: {
            didMethods: opts.builder.didMethods,
            resolver: getResolver({ didMethods: opts.builder.didMethods }),
          },
        },
      }
    : opts.verifyOpts;
}
