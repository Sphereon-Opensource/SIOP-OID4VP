import { SIOP } from './types';
import { SubjectIdentifierType } from './types/SIOP.types';

export default class RPRegistrationMetadata {
  static createPayload(opts: SIOP.RPRegistrationMetadataOpts): SIOP.RPRegistrationMetadataPayload {
    return {
      did_methods_supported: opts.didMethodsSupported || ['did:eosio:', 'did:ethr:', 'did:factom:', 'did:lto:'],
      subject_identifiers_supported: opts.subjectIdentifiersSupported || SubjectIdentifierType.DID,
    };
  }
}
