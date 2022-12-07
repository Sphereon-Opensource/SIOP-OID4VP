import { PEX } from '@sphereon/pex';
import Ajv from 'ajv';

import { ClaimOpts } from '../authorization-response';
import { getNonce, getState } from '../functions';
import { RequestObject } from '../request-object';
import { RPRegistrationMetadataPayloadSchema } from '../schemas';
import {
  AuthorizationRequestPayload,
  ClaimPayload,
  ClientMetadataOpts,
  PassBy,
  ResponseMode,
  ResponseType,
  RPRegistrationMetadataPayload,
  Scope,
  SIOPErrors,
} from '../types';

import { createRequestRegistration } from './RequestRegistration';
import { AuthorizationRequestOpts } from './types';

const ajv = new Ajv({ allowUnionTypes: true, strict: false });
const validateRPRegistrationMetadata = ajv.compile(RPRegistrationMetadataPayloadSchema);

export const createClaimsProperties = (opts: ClaimOpts): ClaimPayload => {
  if (!opts || !opts.vpToken || (!opts.vpToken.presentationDefinition && !opts.vpToken.presentationDefinitionUri)) {
    return undefined;
  }
  const pex: PEX = new PEX();
  const discoveryResult = pex.definitionVersionDiscovery(opts.vpToken.presentationDefinition);
  if (discoveryResult.error) {
    throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
  }

  return {
    ...(opts.idToken ? { id_token: opts.idToken } : {}),
    ...(opts.vpToken.presentationDefinition || opts.vpToken.presentationDefinitionUri
      ? {
          vp_token: {
            ...(opts.vpToken.presentationDefinition ? { presentation_definition: opts.vpToken.presentationDefinition } : {}),
            ...(opts.vpToken.presentationDefinitionUri ? { presentation_definition_uri: opts.vpToken.presentationDefinitionUri } : {}),
          },
        }
      : {}),
  };
};

export const createAuthorizationRequestPayload = async (
  opts: AuthorizationRequestOpts,
  requestObject?: RequestObject
): Promise<AuthorizationRequestPayload> => {
  const state = getState(opts.state);
  const clientMetadata = opts['registration'] ? opts['registration'] : (opts.clientMetadata as ClientMetadataOpts);
  const registration = await createRequestRegistration(clientMetadata);
  const claims = createClaimsProperties(opts.claims);
  const clientId = opts.clientId ? opts.clientId : registration.requestRegistration.registration.client_id;

  const isRequestByValue = opts.type === PassBy.VALUE;

  if (isRequestByValue && !requestObject) {
    throw Error(SIOPErrors.NO_JWT);
  }
  const request = isRequestByValue ? await requestObject.toJwt() : undefined;

  return {
    response_type: ResponseType.ID_TOKEN,
    scope: Scope.OPENID,
    //TODO implement /.well-known/openid-federation support in the OP side to resolve the client_id (URL) and retrieve the metadata
    client_id: clientId ? clientId : opts.signatureType.did,
    redirect_uri: opts.redirectUri,
    response_mode: opts.responseMode || ResponseMode.POST,
    id_token_hint: opts.idTokenHint,
    registration_uri: registration?.requestRegistration?.registration_uri, //opts['registrationUri'],
    ...(opts.type === PassBy.REFERENCE ? { request_uri: opts.referenceUri } : {}),
    ...(isRequestByValue ? { request } : {}),
    nonce: getNonce(state, opts.nonce),
    state,
    ...registration.requestRegistration,
    claims,
  };
};

export const assertValidRPRegistrationMedataPayload = (regObj: RPRegistrationMetadataPayload) => {
  if (regObj && !validateRPRegistrationMetadata(regObj)) {
    throw new Error('Registration data validation error: ' + JSON.stringify(validateRPRegistrationMetadata.errors));
  } else if (regObj?.subject_syntax_types_supported && regObj.subject_syntax_types_supported.length == 0) {
    throw new Error(`${SIOPErrors.VERIFY_BAD_PARAMS}`);
  }
};
