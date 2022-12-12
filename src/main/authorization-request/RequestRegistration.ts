import { LanguageTagUtils } from '../helpers';
import {
  ClientMetadataOpts,
  PassBy,
  RequestClientMetadataPayloadProperties,
  RequestRegistrationPayloadProperties,
  RPRegistrationMetadataOpts,
  RPRegistrationMetadataPayload,
  SIOPErrors,
  SupportedVersion,
} from '../types';

import { CreateAuthorizationRequestOpts } from './types';

/*const ajv = new Ajv({ allowUnionTypes: true, strict: false });
const validateRPRegistrationMetadata = ajv.compile(RPRegistrationMetadataPayloadSchema);*/

export const assertValidRequestRegistrationOpts = (opts: ClientMetadataOpts) => {
  if (!opts) {
    throw new Error(SIOPErrors.REGISTRATION_NOT_SET);
  } else if (opts.passBy !== PassBy.REFERENCE && opts.passBy !== PassBy.VALUE) {
    throw new Error(SIOPErrors.REGISTRATION_OBJECT_TYPE_NOT_SET);
  } else if (opts.passBy === PassBy.REFERENCE && !opts.referenceUri) {
    throw new Error(SIOPErrors.NO_REFERENCE_URI);
  }
};

const createRequestRegistrationPayload = async (
  opts: ClientMetadataOpts,
  metatadaPayload: RPRegistrationMetadataPayload,
  version: SupportedVersion
): Promise<RequestRegistrationPayloadProperties | RequestClientMetadataPayloadProperties> => {
  assertValidRequestRegistrationOpts(opts);

  if (opts.passBy == PassBy.VALUE) {
    if (version >= SupportedVersion.SIOPv2_D11.valueOf()) {
      return { client_metadata: metatadaPayload };
    } else {
      return { registration: metatadaPayload };
    }
  } else {
    if (version >= SupportedVersion.SIOPv2_D11.valueOf()) {
      return {
        client_metadata_uri: opts.referenceUri,
      };
    } else {
      return {
        registration_uri: opts.referenceUri,
      };
    }
  }
};

export const createRequestRegistration = async (
  clientMetadataOpts: ClientMetadataOpts,
  createRequestOpts: CreateAuthorizationRequestOpts
): Promise<{
  payload: RequestRegistrationPayloadProperties | RequestClientMetadataPayloadProperties;
  metadata: RPRegistrationMetadataPayload;
  createRequestOpts: CreateAuthorizationRequestOpts;
  clientMetadataOpts: ClientMetadataOpts;
}> => {
  const metadata = createRPRegistrationMetadataPayload(clientMetadataOpts);
  const payload = await createRequestRegistrationPayload(clientMetadataOpts, metadata, createRequestOpts.version);
  return {
    payload,
    metadata,
    createRequestOpts,
    clientMetadataOpts,
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
