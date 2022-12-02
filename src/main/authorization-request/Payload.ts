import { PEX } from '@sphereon/pex';
import Ajv from 'ajv';

import { getNonce, getState } from '../functions';
import { RPRegistrationMetadataPayloadSchema } from '../schemas';
import {
  AuthorizationRequestOpts,
  ClaimOpts,
  ClaimPayload,
  RequestObjectPayload,
  ResponseMode,
  ResponseType,
  RPRegistrationMetadataPayload,
  Scope,
  SIOPErrors,
} from '../types';

import Opts from './Opts';
import { createRequestRegistration } from './RequestRegistration';

const ajv = new Ajv({ allowUnionTypes: true, strict: false });
const validateRPRegistrationMetadata = ajv.compile(RPRegistrationMetadataPayloadSchema);

export default class Payload {
  static createClaimsProperties(opts: ClaimOpts): ClaimPayload {
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
  }

  static async createRequestObject(opts: AuthorizationRequestOpts): Promise<RequestObjectPayload> {
    Opts.assertValidRequestOpts(opts);

    // todo restrict opts to request type
    const requestOpts = opts.requestBy?.request ? { ...opts, ...opts.requestBy.request } : opts;
    const state = getState(requestOpts.state);
    const registration = await createRequestRegistration(requestOpts['registration']);
    const claims = Payload.createClaimsProperties(requestOpts.claims);

    const clientId = requestOpts.clientId ? requestOpts.clientId : registration.requestRegistration.registration.client_id;

    return {
      response_type: ResponseType.ID_TOKEN,
      scope: Scope.OPENID,
      //TODO implement /.well-known/openid-federation support in the OP side to resolve the client_id (URL) and retrieve the metadata
      client_id: clientId ? clientId : requestOpts.signatureType.did,
      redirect_uri: requestOpts.redirectUri,
      response_mode: requestOpts.responseMode || ResponseMode.POST,
      id_token_hint: requestOpts.idTokenHint,
      registration_uri: requestOpts['registrationUri'],
      nonce: getNonce(state, requestOpts.nonce),
      state,
      ...registration.requestRegistration,
      claims,
    };
  }

  static assertValidRegistrationObject(regObj: RPRegistrationMetadataPayload) {
    if (regObj && !validateRPRegistrationMetadata(regObj)) {
      throw new Error('Registration data validation error: ' + JSON.stringify(validateRPRegistrationMetadata.errors));
    } else if (regObj?.subject_syntax_types_supported && regObj.subject_syntax_types_supported.length == 0) {
      throw new Error(`${SIOPErrors.VERIFY_BAD_PARAMS}`);
    }
  }

  static assertValidRequestObject(verPayload: RequestObjectPayload): void {
    if (verPayload['registration_uri'] || verPayload['registration']) {
      throw new Error(`${SIOPErrors.REG_OBJ_N_REG_URI_CANT_BE_SET_SIMULTANEOUSLY}`);
    }
  }
}
