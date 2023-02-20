import { Resolvable } from 'did-resolver';

import { VerifyAuthorizationRequestOpts } from '../authorization-request';
import { AuthorizationResponseOpts } from '../authorization-response';
import { getResolverUnion, mergeAllDidMethods } from '../did';
import { LanguageTagUtils } from '../helpers';
import { AuthorizationResponseOptsSchema } from '../schemas';
import { InternalVerification, ResponseRegistrationOpts, VerificationMode } from '../types';

import { Builder } from './Builder';

export const createResponseOptsFromBuilderOrExistingOpts = (opts: {
  builder?: Builder;
  responseOpts?: AuthorizationResponseOpts;
}): AuthorizationResponseOpts => {
  if (opts?.builder?.resolvers.size && opts.builder?.responseRegistration?.subjectSyntaxTypesSupported) {
    opts.builder.responseRegistration.subjectSyntaxTypesSupported = mergeAllDidMethods(
      opts.builder.responseRegistration.subjectSyntaxTypesSupported,
      opts.builder.resolvers
    );
  }

  let responseOpts: AuthorizationResponseOpts;

  // const builderRegistration: Partial<ResponseRegistrationOpts> = JSON.parse(JSON.stringify(opts.builder.responseRegistration));
  // delete builderRegistration.registrationBy;

  if (opts.builder) {
    responseOpts = {
      registration: {
        issuer: opts.builder.issuer,
        ...(opts.builder.responseRegistration as ResponseRegistrationOpts),
        /*authorizationEndpoint: opts.builder.responseRegistration.authorizationEndpoint,
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
        idTokenTypesSupported: opts.builder.responseRegistration.idTokenTypesSupported,*/
      },
      did: opts.builder.signatureType.did,
      expiresIn: opts.builder.expiresIn,
      signatureType: opts.builder.signatureType,
      responseMode: opts.builder.responseMode,
      /*presentationExchange: {
        presentationSignCallback: opts.builder.presentationSignCallback,
      },*/
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

  const valid = AuthorizationResponseOptsSchema(responseOpts);
  if (!valid) {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    throw new Error('OP builder validation error: ' + JSON.stringify(valid.errors));
  }

  return responseOpts;
};

export const createVerifyRequestOptsFromBuilderOrExistingOpts = (opts: {
  builder?: Builder;
  verifyOpts?: VerifyAuthorizationRequestOpts;
}): VerifyAuthorizationRequestOpts => {
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
          wellknownDIDVerifyCallback: opts.builder.verifyCallback,
          resolveOpts: {
            subjectSyntaxTypesSupported: opts.builder.responseRegistration.subjectSyntaxTypesSupported,
            resolver: resolver,
          },
        } as InternalVerification,
        supportedVersions: opts.builder.supportedVersions,
      }
    : opts.verifyOpts;
};
