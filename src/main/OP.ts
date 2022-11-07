import { VerifyCallback } from '@sphereon/wellknown-dids-client';
import Ajv from 'ajv';
import fetch from 'cross-fetch';
import { Resolvable } from 'did-resolver';

import AuthenticationRequest from './AuthenticationRequest';
import AuthenticationResponse from './AuthenticationResponse';
import OPBuilder from './OPBuilder';
import { getResolverUnion, LanguageTagUtils, mergeAllDidMethods, postAuthenticationResponse, postAuthenticationResponseJwt } from './functions';
import { AuthenticationResponseOptsSchema } from './schemas';
import {
  AuthenticationResponseOpts,
  AuthenticationResponseWithJWT,
  ExternalVerification,
  InternalVerification,
  ParsedAuthenticationRequestURI,
  ResponseMode,
  SIOPErrors,
  UrlEncodingFormat,
  VerifiablePresentationResponseOpts,
  Verification,
  VerificationMode,
  VerifiedAuthenticationRequestWithJWT,
  VerifyAuthenticationRequestOpts,
} from './types';

const ajv = new Ajv({ allowUnionTypes: true });

const validate = ajv.compile(AuthenticationResponseOptsSchema);

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
    return postAuthenticationResponse(authenticationResponse.payload.idToken.aud, authenticationResponse);
  }

  public async verifyAuthenticationRequest(
    requestJwtOrUri: string,
    opts?: { nonce?: string; verification?: InternalVerification | ExternalVerification }
  ): Promise<VerifiedAuthenticationRequestWithJWT> {
    const verifyCallback = (this._verifyAuthRequestOpts.verification as Verification).verifyCallback || this._verifyAuthRequestOpts.verifyCallback;
    const jwt = requestJwtOrUri.startsWith('ey') ? requestJwtOrUri : (await parseAndResolveRequestUri(requestJwtOrUri)).jwt;
    return AuthenticationRequest.verifyJWT(jwt, this.newVerifyAuthenticationRequestOpts({ ...opts, verifyCallback }));
  }

  public async createAuthenticationResponse(
    verifiedJwt: VerifiedAuthenticationRequestWithJWT,
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
  public async submitAuthenticationResponse(verifiedJwt: AuthenticationResponseWithJWT): Promise<Response> {
    if (
      !verifiedJwt ||
      (verifiedJwt.responseOpts.responseMode &&
        !(verifiedJwt.responseOpts.responseMode == ResponseMode.POST || verifiedJwt.responseOpts.responseMode == ResponseMode.FORM_POST))
    ) {
      throw new Error(SIOPErrors.BAD_PARAMS);
    }
    return postAuthenticationResponseJwt(verifiedJwt.idToken.aud, verifiedJwt.payload);
  }

  /**
   * Create a Authentication Request Payload from a URI string
   *
   * @param encodedUri
   */
  public async parseAuthenticationRequestURI(encodedUri: string): Promise<ParsedAuthenticationRequestURI> {
    const { requestPayload, jwt, registrationMetadata } = await parseAndResolveUri(encodedUri);

    return {
      encodedUri,
      encodingFormat: UrlEncodingFormat.FORM_URL_ENCODED,
      jwt,
      requestPayload,
      registration: registrationMetadata,
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
    verifyCallback?: VerifyCallback;
  }): VerifyAuthenticationRequestOpts {
    return {
      ...this._verifyAuthRequestOpts,
      nonce: opts?.nonce || this._verifyAuthRequestOpts.nonce,
      verification: opts?.verification || this._verifyAuthRequestOpts.verification,
      verifyCallback: opts?.verifyCallback,
    };
  }

  public static fromOpts(responseOpts: AuthenticationResponseOpts, verifyOpts: VerifyAuthenticationRequestOpts): OP {
    return new OP({ responseOpts, verifyOpts });
  }

  public static builder() {
    return new OPBuilder();
  }
}

async function parseAndResolveRequestUri(encodedUri: string) {
  const requestPayload = AuthenticationRequest.parseURI(encodedUri);
  const jwt = requestPayload.request || (await (await fetch(requestPayload.request_uri)).text());
  return { requestPayload, jwt };
}

async function parseAndResolveUri(encodedUri: string) {
  const { requestPayload, jwt } = await parseAndResolveRequestUri(encodedUri);
  AuthenticationRequest.assertValidRequestObject(requestPayload);
  const registrationMetadata = await AuthenticationRequest.getRegistrationObj(requestPayload.registration_uri, requestPayload.registration);
  AuthenticationRequest.assertValidRegistrationObject(registrationMetadata);

  return { requestPayload, jwt, registrationMetadata };
}

function createResponseOptsFromBuilderOrExistingOpts(opts: {
  builder?: OPBuilder;
  responseOpts?: AuthenticationResponseOpts;
}): AuthenticationResponseOpts {
  if (opts?.builder?.resolvers.size && opts.builder?.responseRegistration?.subjectSyntaxTypesSupported) {
    opts.builder.responseRegistration.subjectSyntaxTypesSupported = mergeAllDidMethods(
      opts.builder.responseRegistration.subjectSyntaxTypesSupported,
      opts.builder.resolvers
    );
  }

  let responseOpts: AuthenticationResponseOpts;

  if (opts.builder) {
    responseOpts = {
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
        clientName: opts.builder.responseRegistration.clientName,
        clientId: opts.builder.responseRegistration.clientId,
        applicationType: opts.builder.responseRegistration.applicationType,
        grantTypes: opts.builder.responseRegistration.grantTypes,
        responseTypes: opts.builder.responseRegistration.responseTypes,
        redirectUris: opts.builder.responseRegistration.redirectUris,
        tokenEndpointAuthMethod: opts.builder.responseRegistration.tokenEndpointAuthMethod,
        logoUri: opts.builder.responseRegistration.logoUri,
        clientPurpose: opts.builder.responseRegistration.clientPurpose,
        idTokenTypesSupported: opts.builder.responseRegistration.idTokenTypesSupported,
      },
      did: opts.builder.signatureType.did,
      expiresIn: opts.builder.expiresIn,
      signatureType: opts.builder.signatureType,
      responseMode: opts.builder.responseMode,
      presentationSignCallback: opts.builder.presentationSignCallback,
    };

    const languageTagEnabledFieldsNames = ['clientName', 'clientPurpose'];
    const languageTaggedFields: Map<string, string> = LanguageTagUtils.getLanguageTaggedProperties(
      opts.builder.responseRegistration,
      languageTagEnabledFieldsNames
    );

    languageTaggedFields.forEach((value: string, key: string) => {
      responseOpts.registration[key] = value;
    });
  } else {
    responseOpts = {
      ...opts.responseOpts,
    };
  }

  const valid = validate(responseOpts);
  if (!valid) {
    throw new Error('OP builder validation error: ' + JSON.stringify(validate.errors));
  }

  return responseOpts;
}

function createVerifyRequestOptsFromBuilderOrExistingOpts(opts: {
  builder?: OPBuilder;
  verifyOpts?: VerifyAuthenticationRequestOpts;
}): VerifyAuthenticationRequestOpts {
  if (opts?.builder?.resolvers.size && opts.builder?.responseRegistration) {
    opts.builder.responseRegistration.subjectSyntaxTypesSupported = mergeAllDidMethods(
      opts.builder.responseRegistration.subjectSyntaxTypesSupported,
      opts.builder.resolvers
    );
  }
  let resolver: Resolvable;
  if (opts.builder) {
    resolver = getResolverUnion(opts.builder.customResolver, opts.builder.responseRegistration.subjectSyntaxTypesSupported, opts.builder.resolvers);
  }
  return opts.builder
    ? {
        verification: {
          mode: VerificationMode.INTERNAL,
          checkLinkedDomain: opts.builder.checkLinkedDomain,
          verifyCallback: opts.builder.verifyCallback,
          resolveOpts: {
            subjectSyntaxTypesSupported: opts.builder.responseRegistration.subjectSyntaxTypesSupported,
            resolver: resolver,
          },
          supportedVersions: opts.builder.supportedVersions,
        } as InternalVerification,
      }
    : opts.verifyOpts;
}
