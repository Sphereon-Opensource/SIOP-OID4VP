import { createClaimsProperties } from '../authorization-request';
import { createRequestRegistration } from '../authorization-request/RequestRegistration';
import { getNonce, getState } from '../functions';
import { RequestObjectPayload, ResponseMode, ResponseType, Scope, SIOPErrors } from '../types';

import { assertValidRequestObjectOpts } from './Opts';
import { RequestObjectOpts } from './types';

export const createRequestObjectPayload = async (opts: RequestObjectOpts): Promise<RequestObjectPayload> => {
  assertValidRequestObjectOpts(opts, true);

  const requestObjectOpts = opts.request;

  const state = getState(requestObjectOpts.state);
  const registration = await createRequestRegistration(requestObjectOpts['clientMetadata']);
  const claims = createClaimsProperties(requestObjectOpts.claims);

  const clientId = requestObjectOpts.clientId ? requestObjectOpts.clientId : registration.requestRegistration.registration.client_id;

  return {
    response_type: ResponseType.ID_TOKEN,
    scope: Scope.OPENID,
    //TODO implement /.well-known/openid-federation support in the OP side to resolve the client_id (URL) and retrieve the metadata
    client_id: clientId ? clientId : opts.signatureType.did,
    redirect_uri: requestObjectOpts.redirectUri,
    response_mode: requestObjectOpts.responseMode || ResponseMode.POST,
    id_token_hint: requestObjectOpts.idTokenHint,
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
