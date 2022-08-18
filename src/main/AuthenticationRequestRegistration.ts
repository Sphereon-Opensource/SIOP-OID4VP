import { SIOP, SIOPErrors } from './types';
import { PassBy, RequestRegistrationPayload } from './types/SIOP.types';

export function assertValidRequestRegistrationOpts(opts: SIOP.RequestRegistrationOpts) {
  if (!opts) {
    throw new Error(SIOPErrors.REGISTRATION_NOT_SET);
  } else if (opts.registrationBy.type !== SIOP.PassBy.REFERENCE && opts.registrationBy.type !== SIOP.PassBy.VALUE) {
    throw new Error(SIOPErrors.REGISTRATION_OBJECT_TYPE_NOT_SET);
  } else if (opts.registrationBy.type === SIOP.PassBy.REFERENCE && !opts.registrationBy.referenceUri) {
    throw new Error(SIOPErrors.NO_REFERENCE_URI);
  }
}

export function createRequestRegistrationPayload(opts: SIOP.RequestRegistrationOpts): RequestRegistrationPayload {
  assertValidRequestRegistrationOpts(opts);
  if (opts.registrationBy.type == PassBy.VALUE) {
    return { registration: createRPRegistrationMetadataPayload(opts) };
  } else {
    return { registration_uri: opts.registrationBy.referenceUri };
  }

  // TODO write VDX-122 code here.
}

export function createRequestRegistration(opts: SIOP.RequestRegistrationOpts): {
  requestRegistrationPayload: RequestRegistrationPayload;
  rpRegistrationMetadataPayload: SIOP.RPRegistrationMetadataPayload;
  opts: SIOP.RequestRegistrationOpts;
} {
  return {
    requestRegistrationPayload: createRequestRegistrationPayload(opts),
    rpRegistrationMetadataPayload: createRPRegistrationMetadataPayload(opts),
    opts,
  };
}

function createRPRegistrationMetadataPayload(opts: SIOP.RPRegistrationMetadataOpts): SIOP.RPRegistrationMetadataPayload {
  return {
    id_token_signing_alg_values_supported: opts.idTokenSigningAlgValuesSupported,
    request_object_signing_alg_values_supported: opts.requestObjectSigningAlgValuesSupported,
    response_types_supported: opts.responseTypesSupported,
    scopes_supported: opts.scopesSupported,
    subject_types_supported: opts.subjectTypesSupported,
    // TODO: https://sphereon.atlassian.net/browse/VDX-126 : supporting JSON Web Key (JWK) Thumbprint
    subject_syntax_types_supported: opts.subjectSyntaxTypesSupported || ['did:web:', 'did:ion:'],
    vp_formats: opts.vpFormatsSupported,
  };
}
