import { CreateAuthorizationRequestOpts, createClaimsProperties } from '../authorization-request';
import { createRequestRegistration } from '../authorization-request/RequestRegistration';
import { getNonce, getState } from '../helpers';
import { RequestObjectPayload, ResponseMode, ResponseType, Scope, SIOPErrors } from '../types';

import { assertValidRequestObjectOpts } from './Opts';

export const createRequestObjectPayload = async (opts: CreateAuthorizationRequestOpts): Promise<RequestObjectPayload> => {
  assertValidRequestObjectOpts(opts.requestObject, true);

  const requestObjectOpts = opts.requestObject.payload;

  const state = getState(requestObjectOpts.state);
  const registration = await createRequestRegistration(opts.clientMetadata);
  const claims = createClaimsProperties(requestObjectOpts.claims);

  const clientId = requestObjectOpts.client_id ? requestObjectOpts.client_id : registration.requestRegistration.registration.client_id;

  return {
    response_type: ResponseType.ID_TOKEN,
    scope: Scope.OPENID,
    //TODO implement /.well-known/openid-federation support in the OP side to resolve the client_id (URL) and retrieve the metadata
    client_id: clientId ? clientId : opts.requestObject.signatureType.did,
    redirect_uri: requestObjectOpts.redirect_uri,
    response_mode: requestObjectOpts.response_mode || ResponseMode.POST,
    id_token_hint: requestObjectOpts.id_token_hint,
    registration_uri: registration.opts.referenceUri, //requestObjectOpts['registrationUri'],
    nonce: getNonce(state, requestObjectOpts.nonce),
    state,
    ...registration.requestRegistration,
    claims,
  };
};

export const assertValidRequestObjectPayload = (verPayload: RequestObjectPayload): void => {
  if (verPayload['registration_uri'] && verPayload['registration']) {
    throw new Error(`${SIOPErrors.REG_OBJ_N_REG_URI_CANT_BE_SET_SIMULTANEOUSLY}`);
  }
};
