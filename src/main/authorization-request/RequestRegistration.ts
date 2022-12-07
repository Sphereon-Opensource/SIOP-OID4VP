import Ajv from 'ajv';

import { getWithUrl, LanguageTagUtils } from '../functions';
import { RPRegistrationMetadataPayloadSchema } from '../schemas';
import {
  ClientMetadataOpts,
  PassBy,
  RequestRegistrationPayloadProperties,
  RPRegistrationMetadataOpts,
  RPRegistrationMetadataPayload,
  SIOPErrors,
} from '../types';

const ajv = new Ajv({ allowUnionTypes: true, strict: false });
const validateRPRegistrationMetadata = ajv.compile(RPRegistrationMetadataPayloadSchema);

export const assertValidRequestRegistrationOpts = (opts: ClientMetadataOpts) => {
  if (!opts) {
    throw new Error(SIOPErrors.REGISTRATION_NOT_SET);
  } else if (opts.type !== PassBy.REFERENCE && opts.type !== PassBy.VALUE) {
    throw new Error(SIOPErrors.REGISTRATION_OBJECT_TYPE_NOT_SET);
  } else if (opts.type === PassBy.REFERENCE && !opts.referenceUri) {
    throw new Error(SIOPErrors.NO_REFERENCE_URI);
  }
};

export const createRequestRegistrationPayload = async (
  opts: ClientMetadataOpts /*, keyName: string*/
): Promise<RequestRegistrationPayloadProperties> => {
  assertValidRequestRegistrationOpts(opts);

  if (opts.type == PassBy.VALUE) {
    return { registration: createRPRegistrationMetadataPayload(opts) };
  }

  // pass by ref
  const regObjToValidate = (await getWithUrl(opts.referenceUri)) as unknown as RPRegistrationMetadataPayload;
  if (!regObjToValidate || !validateRPRegistrationMetadata(regObjToValidate)) {
    throw new Error('Registration data validation error: ' + JSON.stringify(validateRPRegistrationMetadata.errors));
  }
  return {
    registration: regObjToValidate,
    registration_uri: opts.referenceUri,
  };
};

export const createRequestRegistration = async (
  opts: ClientMetadataOpts
): Promise<{
  requestRegistration: RequestRegistrationPayloadProperties;
  rpRegistrationMetadata: RPRegistrationMetadataPayload;
  opts: ClientMetadataOpts;
}> => {
  const requestRegistrationPayload = await createRequestRegistrationPayload(opts);
  return {
    requestRegistration: requestRegistrationPayload,
    rpRegistrationMetadata: createRPRegistrationMetadataPayload(opts),
    opts,
  };
};

const createRPRegistrationMetadataPayload = (opts: RPRegistrationMetadataOpts): RPRegistrationMetadataPayload => {
  const rpRegistrationMetadataPayload = {
    id_token_signing_alg_values_supported: opts.idTokenSigningAlgValuesSupported,
    request_object_signing_alg_values_supported: opts.requestObjectSigningAlgValuesSupported,
    response_types_supported: opts.responseTypesSupported,
    scopes_supported: opts.scopesSupported,
    subject_types_supported: opts.subjectTypesSupported,
    subject_syntax_types_supported: opts.subjectSyntaxTypesSupported || ['did:web:', 'did:ion:'],
    vp_formats: opts.vpFormatsSupported,
    client_name: opts.clientName,
    logo_uri: opts.logoUri,
    client_purpose: opts.clientPurpose,
    client_id: opts.clientId,
  };

  const languageTagEnabledFieldsNamesMapping = new Map<string, string>();
  languageTagEnabledFieldsNamesMapping.set('clientName', 'client_name');
  languageTagEnabledFieldsNamesMapping.set('clientPurpose', 'client_purpose');

  const languageTaggedFields: Map<string, string> = LanguageTagUtils.getLanguageTaggedPropertiesMapped(opts, languageTagEnabledFieldsNamesMapping);

  languageTaggedFields.forEach((value: string, key: string) => {
    rpRegistrationMetadataPayload[key] = value;
  });

  return rpRegistrationMetadataPayload;
};
