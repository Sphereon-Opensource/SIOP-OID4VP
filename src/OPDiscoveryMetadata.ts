import { SIOP } from './types';
import { ResponseIss, ResponseType, Schema, Scope, SubjectType } from './types/SIOP.types';

export default class OPDiscoveryMetadata {
  static createPayload(opts: SIOP.DiscoveryMetadataOpts): SIOP.DiscoveryMetadataPayload {
    return {
      issuer: ResponseIss.SELF_ISSUED_V2,
      response_types_supported: ResponseType.ID_TOKEN,
      authorization_endpoint: opts?.authorizationEndpoint || Schema.OPENID,
      scopes_supported: opts?.scopesSupported || Scope.OPENID,
      id_token_signing_alg_values_supported: opts?.idTokenSigningAlgValuesSupported || [
        SIOP.KeyAlgo.ES256K,
        SIOP.KeyAlgo.EDDSA,
      ],
      request_object_signing_alg_values_supported: opts?.requestObjectSigningAlgValuesSupported || [
        SIOP.SigningAlgo.ES256K,
        SIOP.SigningAlgo.EDDSA,
      ],
      subject_types_supported: opts?.subjectTypesSupported || SubjectType.PAIRWISE,
    };
  }
}
