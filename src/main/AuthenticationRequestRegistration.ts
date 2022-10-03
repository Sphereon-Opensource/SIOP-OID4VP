import Ajv from 'ajv';

import { getWithUrl, LanguageTagUtils } from './functions';
import { RPRegistrationMetadataPayloadSchema } from './schemas';
import {
  PassBy,
  RequestRegistrationOpts,
  RequestRegistrationPayload,
  RPRegistrationMetadataOpts,
  RPRegistrationMetadataPayload,
  SIOPErrors,
} from './types';

const ajv = new Ajv({ allowUnionTypes: true });
const validateRPRegistrationMetadata = ajv.compile(RPRegistrationMetadataPayloadSchema);

export function assertValidRequestRegistrationOpts(opts: RequestRegistrationOpts) {
  if (!opts) {
    throw new Error(SIOPErrors.REGISTRATION_NOT_SET);
  } else if (opts.registrationBy.type !== PassBy.REFERENCE && opts.registrationBy.type !== PassBy.VALUE) {
    throw new Error(SIOPErrors.REGISTRATION_OBJECT_TYPE_NOT_SET);
  } else if (opts.registrationBy.type === PassBy.REFERENCE && !opts.registrationBy.referenceUri) {
    throw new Error(SIOPErrors.NO_REFERENCE_URI);
  }
}

export async function createRequestRegistrationPayload(opts: RequestRegistrationOpts): Promise<RequestRegistrationPayload> {
  assertValidRequestRegistrationOpts(opts);

  const regObj: RPRegistrationMetadataPayload = createRPRegistrationMetadataPayload(opts);

  if (opts.registrationBy.referenceUri) {
    const regObjToValidate = (await getWithUrl(opts.registrationBy.referenceUri)) as unknown as RPRegistrationMetadataPayload;
    if (!regObjToValidate || !validateRPRegistrationMetadata(regObjToValidate)) {
      throw new Error('Registration data validation error: ' + JSON.stringify(validateRPRegistrationMetadata.errors));
    }
  }

  if (opts.registrationBy.type == PassBy.VALUE) {
    return { registration: regObj };
  } else {
    return { registration_uri: opts.registrationBy.referenceUri };
  }
}

export async function createRequestRegistration(opts: RequestRegistrationOpts): Promise<{
  requestRegistrationPayload: RequestRegistrationPayload;
  rpRegistrationMetadataPayload: RPRegistrationMetadataPayload;
  opts: RequestRegistrationOpts;
}> {
  const requestRegistrationPayload = await createRequestRegistrationPayload(opts);
  return {
    requestRegistrationPayload: requestRegistrationPayload,
    rpRegistrationMetadataPayload: createRPRegistrationMetadataPayload(opts),
    opts,
  };
}

function createRPRegistrationMetadataPayload(opts: RPRegistrationMetadataOpts): RPRegistrationMetadataPayload {
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
  };

  const languageTagEnabledFieldsNamesMapping = new Map<string, string>();
  languageTagEnabledFieldsNamesMapping.set('clientName', 'client_name');
  languageTagEnabledFieldsNamesMapping.set('clientPurpose', 'client_purpose');

  const languageTaggedFields: Map<string, string> = LanguageTagUtils.getLanguageTaggedPropertiesMapped(opts, languageTagEnabledFieldsNamesMapping);

  languageTaggedFields.forEach((value: string, key: string) => {
    rpRegistrationMetadataPayload[key] = value;
  });

  return rpRegistrationMetadataPayload;
}
