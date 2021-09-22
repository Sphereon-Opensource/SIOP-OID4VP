import { SIOP } from './types';
import { ResponseIss, ResponseType, Schema, Scope, SubjectType } from './types/SIOP.types';

export function createDiscoveryMetadataPayload(opts: SIOP.DiscoveryMetadataOpts): SIOP.DiscoveryMetadataPayload {
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
    credential_formats_supported: opts.credential_formats_supported,
    did_methods_supported: opts.did_methods_supported,
    credential_claims_supported: opts.credential_claims_supported,
    credential_endpoint: opts.credential_endpoint,
    credential_name: opts.credential_name,
    credential_supported: opts.credential_supported,
    dids_supported: opts.dids_supported,
  };
}
