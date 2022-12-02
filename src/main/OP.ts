import { VerifyCallback } from '@sphereon/wellknown-dids-client';
import Ajv from 'ajv';
import { Resolvable } from 'did-resolver';

import OPBuilder from './OPBuilder';
import AuthorizationRequest from './authorization-request/AuthorizationRequest';
import AuthorizationResponse from './authorization-response/AuthorizationResponse';
import { getResolverUnion, LanguageTagUtils, mergeAllDidMethods, postAuthenticationResponse, postAuthenticationResponseJwt } from './functions';
import { authorizationRequestVersionDiscovery } from './functions/SIOPVersionDiscovery';
import { AuthorizationResponseOptsSchema } from './schemas';
import {
  AuthorizationRequestPayload,
  AuthorizationResponseOpts,
  AuthorizationResponseResult,
  ExternalVerification,
  InternalVerification,
  ParsedAuthorizationRequestURI,
  PresentationExchangeOpts,
  ResponseMode,
  SIOPErrors,
  SupportedVersion,
  UrlEncodingFormat,
  VerifiablePresentationWithLocation,
  Verification,
  VerificationMode,
  VerifiedAuthorizationRequest,
  VerifyAuthorizationRequestOpts,
} from './types';

const ajv = new Ajv({ allowUnionTypes: true, strict: false });

const validate = ajv.compile(AuthorizationResponseOptsSchema);

// The OP publishes the formats it supports using the vp_formats_supported metadata parameter as defined above in its "openid-configuration".
export class OP {
  private readonly _authResponseOpts: AuthorizationResponseOpts;
  private readonly _verifyAuthRequestOpts: Partial<VerifyAuthorizationRequestOpts>;

  public constructor(opts: { builder?: OPBuilder; responseOpts?: AuthorizationResponseOpts; verifyOpts?: VerifyAuthorizationRequestOpts }) {
    this._authResponseOpts = { ...createResponseOptsFromBuilderOrExistingOpts(opts) };
    this._verifyAuthRequestOpts = { ...createVerifyRequestOptsFromBuilderOrExistingOpts(opts) };
  }

  get authResponseOpts(): AuthorizationResponseOpts {
    return this._authResponseOpts;
  }

  get verifyAuthRequestOpts(): Partial<VerifyAuthorizationRequestOpts> {
    return this._verifyAuthRequestOpts;
  }

  // TODO SK Can you please put some documentation on it?
  public async postAuthenticationResponse(authenticationResponse: AuthorizationResponseResult): Promise<Response> {
    return postAuthenticationResponse(authenticationResponse.responsePayload.idToken.aud, authenticationResponse);
  }

  /**
   * This method tries to infer the SIOP specs version based on the request payload.
   * If the version cannot be inferred or is not supported it throws an exception.
   * This method needs to be called to ensure the OP can handle the request
   * @param payload is the authentication request payload
   */
  public async checkSIOPSpecVersionSupported(payload: AuthorizationRequestPayload): Promise<SupportedVersion> {
    const version: SupportedVersion = authorizationRequestVersionDiscovery(payload);
    if (!this._verifyAuthRequestOpts.verification.supportedVersions.includes(version)) {
      throw new Error(`SIOP ${version} is not supported`);
    }
    return version;
  }

  public async verifyAuthenticationRequest(
    requestJwtOrUri: string,
    opts?: { nonce?: string; verification?: InternalVerification | ExternalVerification }
  ): Promise<VerifiedAuthorizationRequest> {
    const verifyCallback = (this._verifyAuthRequestOpts.verification as Verification).verifyCallback || this._verifyAuthRequestOpts.verifyCallback;
    return AuthorizationRequest.verify(requestJwtOrUri, this.newVerifyAuthenticationRequestOpts({ ...opts, verifyCallback }));
  }

  public async createAuthenticationResponse(
    verifiedJwt: VerifiedAuthorizationRequest,
    responseOpts?: {
      nonce?: string;
      state?: string;
      audience?: string;
      verification?: InternalVerification | ExternalVerification;
      presentationExchange?: {
        vps?: VerifiablePresentationWithLocation[];
      };
    }
  ): Promise<AuthorizationResponseResult> {
    return AuthorizationResponse.createFromVerifiedAuthorizationRequest(verifiedJwt, this.newAuthenticationResponseOpts(responseOpts));
  }

  // TODO SK Can you please put some documentation on it?
  public async submitAuthenticationResponse(verifiedJwt: AuthorizationResponseResult): Promise<Response> {
    if (
      !verifiedJwt ||
      (verifiedJwt.responseOpts.responseMode &&
        !(verifiedJwt.responseOpts.responseMode == ResponseMode.POST || verifiedJwt.responseOpts.responseMode == ResponseMode.FORM_POST))
    ) {
      throw new Error(SIOPErrors.BAD_PARAMS);
    }
    return postAuthenticationResponseJwt(verifiedJwt.idTokenPayload.aud, verifiedJwt.idToken);
  }

  /**
   * Create a Authentication Request Payload from a URI string
   *
   * @param encodedUri
   */
  public async parseAuthenticationRequestURI(encodedUri: string): Promise<ParsedAuthorizationRequestURI> {
    const { uriScheme, requestObject, authorizationRequest, registrationMetadata } = await AuthorizationRequest.URI.parseAndResolve(encodedUri);

    return {
      encodedUri,
      encodingFormat: UrlEncodingFormat.FORM_URL_ENCODED,
      uriScheme,
      requestObject,
      authorizationRequest,
      registration: registrationMetadata,
    };
  }

  public newAuthenticationResponseOpts(opts?: {
    nonce?: string;
    state?: string;
    audience?: string;
    presentationExchange?: PresentationExchangeOpts;
  }): AuthorizationResponseOpts {
    return {
      ...(opts?.audience ? { redirectUri: opts.audience } : {}),
      ...this._authResponseOpts,
      ...(opts?.nonce ? { nonce: opts.nonce } : {}),
      ...(opts?.state ? { state: opts.state } : {}),
      ...(opts?.presentationExchange ? { presentationExchange: opts.presentationExchange } : {}),
    };
  }

  public newVerifyAuthenticationRequestOpts(opts?: {
    nonce?: string;
    verification?: InternalVerification | ExternalVerification;
    verifyCallback?: VerifyCallback;
  }): VerifyAuthorizationRequestOpts {
    return {
      ...this._verifyAuthRequestOpts,
      nonce: opts?.nonce || this._verifyAuthRequestOpts.nonce,
      verification: opts?.verification || this._verifyAuthRequestOpts.verification,
      verifyCallback: opts?.verifyCallback,
    };
  }

  public static fromOpts(responseOpts: AuthorizationResponseOpts, verifyOpts: VerifyAuthorizationRequestOpts): OP {
    return new OP({ responseOpts, verifyOpts });
  }

  public static builder() {
    return new OPBuilder();
  }
}

function createResponseOptsFromBuilderOrExistingOpts(opts: {
  builder?: OPBuilder;
  responseOpts?: AuthorizationResponseOpts;
}): AuthorizationResponseOpts {
  if (opts?.builder?.resolvers.size && opts.builder?.responseRegistration?.subjectSyntaxTypesSupported) {
    opts.builder.responseRegistration.subjectSyntaxTypesSupported = mergeAllDidMethods(
      opts.builder.responseRegistration.subjectSyntaxTypesSupported,
      opts.builder.resolvers
    );
  }

  let responseOpts: AuthorizationResponseOpts;

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
      presentationExchange: {
        presentationSignCallback: opts.builder.presentationSignCallback,
      },
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
  verifyOpts?: VerifyAuthorizationRequestOpts;
}): VerifyAuthorizationRequestOpts {
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
