import Ajv from 'ajv';
import fetch from 'cross-fetch';

import AuthenticationRequest from './AuthenticationRequest';
import AuthenticationResponse from './AuthenticationResponse';
import OPBuilder from './OPBuilder';
import { getResolver } from './functions/DIDResolution';
import { AuthenticationResponseOptsSchema } from './schemas/AuthenticationResponseOpts.schema';
import { SIOP, SIOPErrors } from './types';
import {
  AuthenticationResponseOpts,
  AuthenticationResponseWithJWT,
  ExternalVerification,
  InternalVerification,
  ParsedAuthenticationRequestURI,
  ResponseRegistrationOpts,
  UrlEncodingFormat,
  VerificationMode,
  VerifiedAuthenticationRequestWithJWT,
  VerifyAuthenticationRequestOpts,
} from './types/SIOP.types';

const ajv = new Ajv();
const validate = ajv.compile(AuthenticationResponseOptsSchema);

export class OP {
  private readonly authResponseOpts: AuthenticationResponseOpts;
  private readonly verifyAuthRequestOpts: Partial<VerifyAuthenticationRequestOpts>;

  public constructor(opts: {
    builder?: OPBuilder;
    responseOpts?: AuthenticationResponseOpts;
    verifyOpts?: VerifyAuthenticationRequestOpts;
  }) {
    this.authResponseOpts = { ...createResponseOptsFromBuilderOrExistingOpts(opts) };
    this.verifyAuthRequestOpts = { ...createVerifyRequestOptsFromBuilderOrExistingOpts(opts) };
  }

  public async createAuthenticationResponse(
    requestJwtorUri: string,
    opts?: {
      nonce?: string;
      state?: string;
      // audience: string;
      verification?: InternalVerification | ExternalVerification;
    }
  ): Promise<AuthenticationResponseWithJWT> {
    if (!requestJwtorUri) {
      throw new Error(SIOPErrors.BAD_PARAMS);
    }
    const jwt = requestJwtorUri.startsWith('ey') ? requestJwtorUri : (await parseAndResolveUri(requestJwtorUri)).jwt;

    return AuthenticationResponse.createJWTFromRequestJWT(
      jwt,
      this.newAuthenticationResponseOpts(opts),
      this.newVerifyAuthenticationRequestOpts(opts)
    );
  }

  public createAuthenticationResponseFromVerifiedRequest(
    verifiedJwt: SIOP.VerifiedAuthenticationRequestWithJWT,
    responseOpts?: {
      nonce?: string;
      state?: string;
      // audience: string;
      verification?: InternalVerification | ExternalVerification;
    }
  ): Promise<AuthenticationResponseWithJWT> {
    return AuthenticationResponse.createJWTFromVerifiedRequest(
      verifiedJwt,
      this.newAuthenticationResponseOpts(responseOpts)
    );
  }

  public verifyAuthenticationRequest(
    requestJwt: string,
    opts?: { /*audience?: string;*/ nonce?: string; verification?: InternalVerification | ExternalVerification }
  ): Promise<VerifiedAuthenticationRequestWithJWT> {
    return AuthenticationRequest.verifyJWT(requestJwt, this.newVerifyAuthenticationRequestOpts(opts));
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

  public newAuthenticationResponseOpts(opts?: { nonce?: string; state?: string }): AuthenticationResponseOpts {
    const state = opts?.state;
    const nonce = opts?.nonce;
    return {
      ...this.authResponseOpts,
      nonce,
      state,
    };
  }

  public newVerifyAuthenticationRequestOpts(opts?: {
    nonce?: string;
    verification?: InternalVerification | ExternalVerification;
  }): VerifyAuthenticationRequestOpts {
    return {
      ...this.verifyAuthRequestOpts,
      nonce: opts?.nonce || this.verifyAuthRequestOpts.nonce,
      verification: opts?.verification || this.verifyAuthRequestOpts.verification,
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
