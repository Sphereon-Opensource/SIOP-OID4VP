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
  UrlEncodingFormat,
  VerifiablePresentationResponseOpts,
  VerificationMode,
  VerifiedAuthenticationRequestWithJWT,
  VerifyAuthenticationRequestOpts,
} from './types/SIOP.types';

const ajv = new Ajv();

const validate = ajv.compile(AuthenticationResponseOptsSchema);

// TODO HR This class has all the VDX-122 marked already. Once done remove this comment.

// The OP publishes the formats it supports using the vp_formats_supported metadata parameter as defined above in its "openid-configuration".
export class OP {
  private readonly _authResponseOpts: AuthenticationResponseOpts;
  private readonly _verifyAuthRequestOpts: Partial<VerifyAuthenticationRequestOpts>;

  public constructor(opts: { builder?: OPBuilder; responseOpts?: AuthenticationResponseOpts; verifyOpts?: VerifyAuthenticationRequestOpts }) {
    this._authResponseOpts = { ...createResponseOptsFromBuilderOrExistingOpts(opts) };
    this._verifyAuthRequestOpts = { ...createVerifyRequestOptsFromBuilderOrExistingOpts(opts) };
  }

  get authResponseOpts(): AuthenticationResponseOpts {
    return this._authResponseOpts;
  }

  get verifyAuthRequestOpts(): Partial<VerifyAuthenticationRequestOpts> {
    return this._verifyAuthRequestOpts;
  }

  // TODO SK Can you please put some documentation on it?
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
      audience?: string;
      verification?: InternalVerification | ExternalVerification;
      vp?: VerifiablePresentationResponseOpts[];
    }
  ): Promise<AuthenticationResponseWithJWT> {
    return AuthenticationResponse.createJWTFromVerifiedRequest(verifiedJwt, this.newAuthenticationResponseOpts(responseOpts));
  }

  // TODO SK Can you please put some documentation on it?
  public async submitAuthenticationResponse(verifiedJwt: SIOP.AuthenticationResponseWithJWT): Promise<Response> {
    if (
      !verifiedJwt ||
      (verifiedJwt.responseOpts.responseMode &&
        !(verifiedJwt.responseOpts.responseMode == ResponseMode.POST || verifiedJwt.responseOpts.responseMode == ResponseMode.FORM_POST))
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
    audience?: string;
    vp?: VerifiablePresentationResponseOpts[];
  }): AuthenticationResponseOpts {
    const state = opts?.state;
    const nonce = opts?.nonce;
    const vp = opts?.vp;
    const audience = opts?.audience;
    return {
      redirectUri: audience,
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

  // TODO HR add VDX-122 code here.
  const registration = requestPayload.registration || (await (await fetch(requestPayload.registration_uri)).json());
  return { requestPayload, jwt, registration };
}

function createResponseOptsFromBuilderOrExistingOpts(opts: { builder?: OPBuilder; responseOpts?: AuthenticationResponseOpts }) {
  const responseOpts: AuthenticationResponseOpts = opts.builder
    ? {
        registration: {
          issuer: opts.builder.issuer,
          authorizationEndpoint: opts.builder.responseRegistration.authorizationEndpoint,
          tokenEndpoint: opts.builder.responseRegistration.tokenEndpoint,
          userinfoEndpoint: opts.builder.responseRegistration.userinfoEndpoint,
          jwksUri: opts.builder.responseRegistration.jwksUri,
          registrationEndpoint: opts.builder.responseRegistration.registrationEndpoint,
          scopesSupported: opts.builder.responseRegistration.scopesSupported,
          responseTypesSupported: opts.builder.responseRegistration.responseTypesSupported,
          responseModesSupported: opts.builder.responseRegistration.responseModesSupported,
          grantTypesSupported: opts.builder.responseRegistration.grantTypesSupported,
          acrValuesSupported: opts.builder.responseRegistration.acrValuesSupported,
          subjectTypesSupported: opts.builder.responseRegistration.subjectTypesSupported,
          idTokenSigningAlgValuesSupported: opts.builder.responseRegistration.idTokenSigningAlgValuesSupported,
          idTokenEncryptionAlgValuesSupported: opts.builder.responseRegistration.idTokenEncryptionAlgValuesSupported,
          idTokenEncryptionEncValuesSupported: opts.builder.responseRegistration.idTokenEncryptionEncValuesSupported,
          userinfoSigningAlgValuesSupported: opts.builder.responseRegistration.userinfoSigningAlgValuesSupported,
          userinfoEncryptionAlgValuesSupported: opts.builder.responseRegistration.userinfoEncryptionAlgValuesSupported,
          userinfoEncryptionEncValuesSupported: opts.builder.responseRegistration.userinfoEncryptionEncValuesSupported,
          requestObjectSigningAlgValuesSupported: opts.builder.responseRegistration.requestObjectSigningAlgValuesSupported,
          requestObjectEncryptionAlgValuesSupported: opts.builder.responseRegistration.requestObjectEncryptionAlgValuesSupported,
          requestObjectEncryptionEncValuesSupported: opts.builder.responseRegistration.requestObjectEncryptionEncValuesSupported,
          tokenEndpointAuthMethodsSupported: opts.builder.responseRegistration.tokenEndpointAuthMethodsSupported,
          tokenEndpointAuthSigningAlgValuesSupported: opts.builder.responseRegistration.tokenEndpointAuthSigningAlgValuesSupported,
          displayValuesSupported: opts.builder.responseRegistration.displayValuesSupported,
          claimTypesSupported: opts.builder.responseRegistration.claimTypesSupported,
          claimsSupported: opts.builder.responseRegistration.claimsSupported,
          serviceDocumentation: opts.builder.responseRegistration.serviceDocumentation,
          claimsLocalesSupported: opts.builder.responseRegistration.claimsLocalesSupported,
          uiLocalesSupported: opts.builder.responseRegistration.uiLocalesSupported,
          claimsParameterSupported: opts.builder.responseRegistration.claimsParameterSupported,
          requestParameterSupported: opts.builder.responseRegistration.requestParameterSupported,
          requestUriParameterSupported: opts.builder.responseRegistration.requestUriParameterSupported,
          requireRequestUriRegistration: opts.builder.responseRegistration.requireRequestUriRegistration,
          opPolicyUri: opts.builder.responseRegistration.opPolicyUri,
          opTosUri: opts.builder.responseRegistration.opTosUri,

          registrationBy: opts.builder.responseRegistration.registrationBy,
          subjectSyntaxTypesSupported: opts.builder.responseRegistration.subjectSyntaxTypesSupported,

          vpFormats: opts.builder.responseRegistration.vpFormats,
          idTokenTypesSupported: opts.builder.responseRegistration.idTokenTypesSupported,
        },
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

function createVerifyRequestOptsFromBuilderOrExistingOpts(opts: { builder?: OPBuilder; verifyOpts?: Partial<VerifyAuthenticationRequestOpts> }) {
  const subjectSyntaxTypesSupported = [];
  if (opts.builder?.responseRegistration?.subjectSyntaxTypesSupported) {
    if (Array.isArray(opts.builder.responseRegistration.subjectSyntaxTypesSupported)) {
      subjectSyntaxTypesSupported.push(...opts.builder.responseRegistration.subjectSyntaxTypesSupported);
    } else {
      subjectSyntaxTypesSupported.push(...opts.builder.responseRegistration.subjectSyntaxTypesSupported);
    }
  }
  return opts.builder
    ? {
        verification: {
          mode: VerificationMode.INTERNAL,
          resolveOpts: {
            //TODO: https://sphereon.atlassian.net/browse/VDX-126 add support of other subjectSyntaxTypes
            didMethods: subjectSyntaxTypesSupported.filter((t) => t.startsWith('did:')),
            resolver: opts.builder.resolvers
              ? //TODO: discuss this with Niels
                getResolver({ resolver: opts.builder.resolvers.values().next().value })
              : getResolver({ subjectSyntaxTypesSupported: subjectSyntaxTypesSupported }),
          },
        },
      }
    : opts.verifyOpts;
}
