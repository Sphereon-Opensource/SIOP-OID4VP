import Ajv from 'ajv';
import { Resolvable } from 'did-resolver';

import { CreateAuthorizationRequestOpts, PropertyTarget, PropertyTargets, RequestPropertyWithTargets } from '../authorization-request';
import { VerifyAuthorizationResponseOpts } from '../authorization-response';
import { getResolverUnion, mergeAllDidMethods } from '../did';
import { AuthorizationRequestOptsSchema } from '../schemas';
import { ClientMetadataOpts, InternalVerification, RequestObjectPayload, SIOPErrors, VerificationMode } from '../types';

import Builder from './Builder';

const ajv = new Ajv({ allowUnionTypes: true, strict: false });
const requestOptsValidate = ajv.compile(AuthorizationRequestOptsSchema);
export const createRequestOptsFromBuilderOrExistingOpts = (opts: { builder?: Builder; createRequestOpts?: CreateAuthorizationRequestOpts }) => {
  const version = opts.builder ? opts.builder.getSupportedRequestVersion() : opts.createRequestOpts.version;
  if (!version) {
    throw Error(SIOPErrors.NO_REQUEST_VERSION);
  }

  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  const createRequestOpts: CreateAuthorizationRequestOpts = opts.builder
    ? {
        version,
        payload: {
          ...opts.builder.authorizationRequestPayload,
          //response_types_supported: opts.builder.clientMetadata?.responseTypesSupported,
          // subject_types_supported: opts.builder.clientMetadata?.subjectTypesSupported,
          // request_object_signing_alg_values_supported: opts.builder.clientMetadata?.requestObjectSigningAlgValuesSupported
          //scopes_supported: opts.builder.clientMetadata?.scopesSupported,
        },
        requestObject: {
          ...opts.builder.requestObjectBy,
          payload: {
            ...(opts.builder.requestObjectPayload as RequestObjectPayload),
            subject_types_supported: opts.builder.clientMetadata?.subjectTypesSupported,
            request_object_signing_alg_values_supported: opts.builder.clientMetadata?.requestObjectSigningAlgValuesSupported,
          },
          signatureType: opts.builder.signatureType,
        },
        clientMetadata: opts.builder.clientMetadata as ClientMetadataOpts,
      }
    : opts.createRequestOpts;

  const valid = requestOptsValidate(createRequestOpts);
  if (!valid) {
    throw new Error('RP builder validation error: ' + JSON.stringify(requestOptsValidate.errors));
  }
  return createRequestOpts;
};

export const createVerifyResponseOptsFromBuilderOrExistingOpts = (opts: { builder?: Builder; verifyOpts?: VerifyAuthorizationResponseOpts }) => {
  if (opts?.builder?.resolvers.size && opts.builder?.clientMetadata) {
    opts.builder.clientMetadata.subjectSyntaxTypesSupported = mergeAllDidMethods(
      opts.builder.clientMetadata.subjectSyntaxTypesSupported,
      opts.builder.resolvers
    );
  }
  let resolver: Resolvable;
  if (opts.builder) {
    resolver = getResolverUnion(opts.builder.customResolver, opts.builder.clientMetadata.subjectSyntaxTypesSupported, opts.builder.resolvers);
  }
  return opts.builder
    ? {
        verification: {
          mode: VerificationMode.INTERNAL,
          checkLinkedDomain: opts.builder.checkLinkedDomain,
          wellknownDIDVerifyCallback: opts.builder.verifyCallback,
          presentationVerificationCallback: opts.builder.presentationVerificationCallback,
          resolveOpts: {
            subjectSyntaxTypesSupported: opts.builder.clientMetadata.subjectSyntaxTypesSupported,
            resolver: resolver,
          },
          supportedVersions: opts.builder.supportedVersions,
          revocationOpts: {
            revocationVerification: opts.builder.revocationVerification,
            revocationVerificationCallback: opts.builder.revocationVerificationCallback,
          },
          replayRegistry: opts.builder.replayRegistry,
        } as InternalVerification,
      }
    : opts.verifyOpts;
};

export const isTargetOrNoTargets = (searchTarget: PropertyTarget, targets?: PropertyTargets): boolean => {
  if (!targets) {
    return true;
  }
  return isTarget(searchTarget, targets);
};

export const isTarget = (searchTarget: PropertyTarget, targets: PropertyTargets): boolean => {
  return Array.isArray(targets) ? targets.includes(searchTarget) : targets === searchTarget;
};

export const assignIfAuth = <T>(opt: RequestPropertyWithTargets<T>): T => {
  if (isTargetOrNoTargets(PropertyTarget.AUTHORIZATION_REQUEST, opt.targets)) {
    return opt.propertyValue;
  }
  return undefined;
};

export const assignIfRequestObject = <T>(opt: RequestPropertyWithTargets<T>): T => {
  if (isTargetOrNoTargets(PropertyTarget.REQUEST_OBJECT, opt.targets)) {
    return opt.propertyValue;
  }
  return undefined;
};
