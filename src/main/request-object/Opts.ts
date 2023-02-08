import { ClaimPayloadCommonOpts } from '../authorization-request';
import { PassBy, SIOPErrors } from '../types';

import { RequestObjectOpts } from './types';

export const assertValidRequestObjectOpts = (opts: RequestObjectOpts<ClaimPayloadCommonOpts>, checkRequestObject: boolean) => {
  if (!opts) {
    throw new Error(SIOPErrors.BAD_PARAMS + 'for RequestObjectOpts the root object should be usable(non-null and defined).');
  } else if (opts.passBy !== PassBy.REFERENCE && opts.passBy !== PassBy.VALUE) {
    throw new Error(SIOPErrors.REQUEST_OBJECT_TYPE_NOT_SET);
  } else if (opts.passBy === PassBy.REFERENCE && !opts.referenceUri) {
    throw new Error(SIOPErrors.NO_REFERENCE_URI);
  } else if (!opts.payload) {
    if (opts.referenceUri) {
      // reference URI, but no actual payload to host there!
      throw Error(SIOPErrors.REFERENCE_URI_NO_PAYLOAD);
    } else if (checkRequestObject) {
      throw Error(SIOPErrors.BAD_PARAMS + 'checkRequestObject should pass');
    }
  }
  // assertValidRequestRegistrationOpts(opts['registration'] ? opts['registration'] : opts['clientMetadata']);
};
