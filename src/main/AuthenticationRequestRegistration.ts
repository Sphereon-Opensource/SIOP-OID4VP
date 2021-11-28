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
    did_methods_supported: opts.didMethodsSupported || ['did:eosio:', 'did:ethr:', 'did:factom:', 'did:lto:'],
    subject_identifiers_supported: opts.subjectIdentifiersSupported || SIOP.SubjectIdentifierType.DID,
    credential_formats_supported: opts.credentialFormatsSupported || [],
  };
}
