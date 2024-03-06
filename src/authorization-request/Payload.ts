import { PEX } from '@sphereon/pex';

import { validateLinkedDomainWithDid } from '../did';
import { getNonce, removeNullUndefined } from '../helpers';
import { RequestObject } from '../request-object';
import { isTarget, isTargetOrNoTargets } from '../rp/Opts';
import { RPRegistrationMetadataPayloadSchema } from '../schemas';
import {
  AuthorizationRequestPayload,
  CheckLinkedDomain,
  ClaimPayloadVID1,
  ClientMetadataOpts,
  PassBy,
  RequestObjectPayload,
  RPRegistrationMetadataPayload,
  SIOPErrors,
  SupportedVersion,
} from '../types';

import { createRequestRegistration } from './RequestRegistration';
import { ClaimPayloadOptsVID1, CreateAuthorizationRequestOpts, PropertyTarget, VerifyAuthorizationRequestOpts } from './types';

export const createPresentationDefinitionClaimsProperties = (opts: ClaimPayloadOptsVID1): ClaimPayloadVID1 => {
  if (!opts || !opts.vp_token || (!opts.vp_token.presentation_definition && !opts.vp_token.presentation_definition_uri)) {
    return undefined;
  }
  const discoveryResult = PEX.definitionVersionDiscovery(opts.vp_token.presentation_definition);
  if (discoveryResult.error) {
    throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
  }

  return {
    ...(opts.id_token ? { id_token: opts.id_token } : {}),
    ...((opts.vp_token.presentation_definition || opts.vp_token.presentation_definition_uri) && {
      vp_token: {
        ...(!opts.vp_token.presentation_definition_uri && { presentation_definition: opts.vp_token.presentation_definition }),
        ...(opts.vp_token.presentation_definition_uri && { presentation_definition_uri: opts.vp_token.presentation_definition_uri }),
      },
    }),
  };
};

export const createAuthorizationRequestPayload = async (
  opts: CreateAuthorizationRequestOpts,
  requestObject?: RequestObject
): Promise<AuthorizationRequestPayload> => {
  const payload = opts.payload;
  const state = payload?.state ?? undefined;
  const nonce = payload?.nonce ? getNonce(state, payload.nonce) : undefined;
  // TODO: if opts['registration] throw Error to get rid of test code using that key
  const clientMetadata = opts['registration'] ? opts['registration'] : (opts.clientMetadata as ClientMetadataOpts);
  const registration = await createRequestRegistration(clientMetadata, opts);
  const claims =
    opts.version >= SupportedVersion.SIOPv2_ID1 ? opts.payload.claims : createPresentationDefinitionClaimsProperties(opts.payload.claims);
  const isRequestTarget = isTargetOrNoTargets(PropertyTarget.AUTHORIZATION_REQUEST, opts.requestObject.targets);
  const isRequestByValue = opts.requestObject.passBy === PassBy.VALUE;

  if (isRequestTarget && isRequestByValue && !requestObject) {
    throw Error(SIOPErrors.NO_JWT);
  }
  const request = isRequestByValue ? await requestObject.toJwt() : undefined;

  const authRequestPayload = {
    ...payload,
    //TODO implement /.well-known/openid-federation support in the OP side to resolve the client_id (URL) and retrieve the metadata
    ...(isRequestTarget && opts.requestObject.passBy === PassBy.REFERENCE ? { request_uri: opts.requestObject.reference_uri } : {}),
    ...(isRequestTarget && isRequestByValue && { request }),
    ...(nonce && { nonce }),
    ...(state && { state }),
    ...(registration.payload && isTarget(PropertyTarget.AUTHORIZATION_REQUEST, registration.clientMetadataOpts.targets) ? registration.payload : {}),
    ...(claims && { claims }),
  };

  return removeNullUndefined(authRequestPayload);
};

export const assertValidRPRegistrationMedataPayload = (regObj: RPRegistrationMetadataPayload) => {
  if (regObj) {
    const valid = RPRegistrationMetadataPayloadSchema(regObj);
    if (!valid) {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      //@ts-ignore
      throw new Error('Registration data validation error: ' + JSON.stringify(RPRegistrationMetadataPayloadSchema.errors));
    }
  }
  if (regObj?.subject_syntax_types_supported && regObj.subject_syntax_types_supported.length == 0) {
    throw new Error(`${SIOPErrors.VERIFY_BAD_PARAMS}`);
  }
};

export const checkWellknownDIDFromRequest = async (
  authorizationRequestPayload: RequestObjectPayload,
  opts: VerifyAuthorizationRequestOpts
): Promise<void> => {
  if (authorizationRequestPayload.client_id.startsWith('did:')) {
    if (opts.verification.checkLinkedDomain && opts.verification.checkLinkedDomain != CheckLinkedDomain.NEVER) {
      await validateLinkedDomainWithDid(authorizationRequestPayload.client_id, opts.verification);
    } else if (!opts.verification.checkLinkedDomain && opts.verification.wellknownDIDVerifyCallback) {
      await validateLinkedDomainWithDid(authorizationRequestPayload.client_id, opts.verification);
    }
  }
};
