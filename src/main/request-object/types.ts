import { RequestObjectPayloadOpts } from '../authorization-request';
import { ExternalSignature, InternalSignature, NoSignature, ObjectBy, SuppliedSignature } from '../types';

export interface RequestObjectOpts extends RequestBy {
  // requestBy: RequestBy; // Whether the request is returned by value in the URI or retrieved by reference at the provided URL
  signatureType: InternalSignature | ExternalSignature | SuppliedSignature | NoSignature; // Whether no signature is being used, internal (access to private key), or external (hosted using authentication), or supplied (callback supplied)
}

export interface RequestBy extends ObjectBy {
  payload?: RequestObjectPayloadOpts; // for pass by value
}
