import { ClaimPayloadCommonOpts, RequestObjectPayloadOpts } from '../authorization-request';
import { ExternalSignature, InternalSignature, NoSignature, ObjectBy, SuppliedSignature } from '../types';

export interface RequestObjectOpts<CT extends ClaimPayloadCommonOpts> extends ObjectBy {
  payload?: RequestObjectPayloadOpts<CT>; // for pass by value
  signatureType: InternalSignature | ExternalSignature | SuppliedSignature | NoSignature; // Whether no signature is being used, internal (access to private key), or external (hosted using authentication), or supplied (callback supplied)
}
