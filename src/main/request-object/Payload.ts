import { CreateAuthorizationRequestOpts, createPresentationDefinitionClaimsProperties } from '../authorization-request';
import { createRequestRegistration } from '../authorization-request/RequestRegistration';
import { getNonce, getState } from '../helpers';
import { RequestObjectPayload, ResponseMode, ResponseType, Scope, SIOPErrors, SupportedVersion } from '../types';

import { assertValidRequestObjectOpts } from './Opts';

export const createRequestObjectPayload = async (opts: CreateAuthorizationRequestOpts): Promise<RequestObjectPayload | undefined> => {
  assertValidRequestObjectOpts(opts.requestObject, false);
  if (!opts.requestObject?.payload) {
    return undefined; // No request object apparently
  }
  assertValidRequestObjectOpts(opts.requestObject, true);

  const requestObjectOpts = opts.requestObject.payload;

  const state = getState(requestObjectOpts.state);
  const registration = await createRequestRegistration(opts.clientMetadata, opts);
  const claims = createPresentationDefinitionClaimsProperties(requestObjectOpts.claims);

  let clientId = requestObjectOpts.client_id;

  const metadataKey = opts.version >= SupportedVersion.SIOPv2_D11.valueOf() ? 'client_metadata' : 'registration';
  if (!clientId) {
    clientId = registration.payload[metadataKey];
  }

  return {
    response_type: ResponseType.ID_TOKEN,
    scope: Scope.OPENID,
    //TODO implement /.well-known/openid-federation support in the OP side to resolve the client_id (URL) and retrieve the metadata
    client_id: clientId ? clientId : opts.requestObject.signatureType.did,
    redirect_uri: requestObjectOpts.redirect_uri,
    response_mode: requestObjectOpts.response_mode || ResponseMode.POST,
    id_token_hint: requestObjectOpts.id_token_hint,
    registration_uri: registration.clientMetadataOpts.referenceUri, //requestObjectOpts['registrationUri'],
    nonce: getNonce(state, requestObjectOpts.nonce),
    state,
    ...registration.payload,
    claims,
  };
};

export const assertValidRequestObjectPayload = (verPayload: RequestObjectPayload): void => {
  console.log('assertValidRequestObjectPayload')
  if (verPayload['registration_uri'] && verPayload['registration']) {
    throw new Error(`${SIOPErrors.REG_OBJ_N_REG_URI_CANT_BE_SET_SIMULTANEOUSLY}`);
  }
};
