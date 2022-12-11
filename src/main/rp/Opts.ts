import Ajv from 'ajv';
import { Resolvable } from 'did-resolver';

import { CreateAuthorizationRequestOpts } from '../authorization-request';
import { VerifyAuthorizationResponseOpts } from '../authorization-response';
import { getResolverUnion, mergeAllDidMethods } from '../did';
import { AuthorizationRequestOptsSchema } from '../schemas';
import { ClientMetadataOpts, InternalVerification, VerificationMode } from '../types';

import Builder from './Builder';

const ajv = new Ajv({ allowUnionTypes: true, strict: false });
const requestOptsValidate = ajv.compile(AuthorizationRequestOptsSchema);
export const createRequestOptsFromBuilderOrExistingOpts = (opts: { builder?: Builder; createRequestOpts?: CreateAuthorizationRequestOpts }) => {
  const createRequestOpts: CreateAuthorizationRequestOpts = opts.builder
    ? {
        payload: {
          authorization_endpoint: opts.builder.authorizationEndpoint,
          subject_types_supported: opts.builder.requestRegistration.subjectTypesSupported,
          request_object_signing_alg_values_supported: opts.builder.requestRegistration.requestObjectSigningAlgValuesSupported,
          response_mode: opts.builder.responseMode,
          // responseContext: opts.builder.responseContext,
          claims: opts.builder.claims,
          scope: opts.builder.scope,
          response_type: opts.builder.responseType,
          client_id: opts.builder.clientId,
          redirect_uri: opts.builder.redirectUri,
          response_types_supported: opts.builder.requestRegistration.responseTypesSupported,
          scopes_supported: opts.builder.requestRegistration.scopesSupported,
        },
        requestObject: {
          ...opts.builder.requestObjectBy,
          signatureType: opts.builder.signatureType,
        },
        clientMetadata: opts.builder.requestRegistration as ClientMetadataOpts,
      }
    : opts.createRequestOpts;

  const valid = requestOptsValidate(createRequestOpts);
  if (!valid) {
    throw new Error('RP builder validation error: ' + JSON.stringify(requestOptsValidate.errors));
  }
  return createRequestOpts;
};

export const createVerifyResponseOptsFromBuilderOrExistingOpts = (opts: { builder?: Builder; verifyOpts?: VerifyAuthorizationResponseOpts }) => {
  if (opts?.builder?.resolvers.size && opts.builder?.requestRegistration) {
    opts.builder.requestRegistration.subjectSyntaxTypesSupported = mergeAllDidMethods(
      opts.builder.requestRegistration.subjectSyntaxTypesSupported,
      opts.builder.resolvers
    );
  }
  let resolver: Resolvable;
  if (opts.builder) {
    resolver = getResolverUnion(opts.builder.customResolver, opts.builder.requestRegistration.subjectSyntaxTypesSupported, opts.builder.resolvers);
  }
  return opts.builder
    ? {
        verification: {
          mode: VerificationMode.INTERNAL,
          checkLinkedDomain: opts.builder.checkLinkedDomain,
          wellknownDIDVerifyCallback: opts.builder.verifyCallback,
          presentationVerificationCallback: opts.builder.presentationVerificationCallback,
          resolveOpts: {
            subjectSyntaxTypesSupported: opts.builder.requestRegistration.subjectSyntaxTypesSupported,
            resolver: resolver,
          },
          supportedVersions: opts.builder.supportedVersions,
          revocationOpts: {
            revocationVerification: opts.builder.revocationVerification,
            revocationVerificationCallback: opts.builder.revocationVerificationCallback,
          },
        } as InternalVerification,
      }
    : opts.verifyOpts;
};
