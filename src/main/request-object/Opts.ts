import { ClaimPayloadCommonOpts } from '../authorization-request';
import { PassBy, SIOPErrors } from '../types';

import { RequestObjectOpts } from './types';

export const assertValidRequestObjectOpts = (opts: RequestObjectOpts<ClaimPayloadCommonOpts>, checkRequestObject: boolean) => {
  if (!opts) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  } else if (opts.passBy !== PassBy.REFERENCE && opts.passBy !== PassBy.VALUE) {
    throw new Error(SIOPErrors.REQUEST_OBJECT_TYPE_NOT_SET);
  } else if (opts.passBy === PassBy.REFERENCE && !opts.referenceUri) {
    throw new Error(SIOPErrors.NO_REFERENCE_URI);
  } else if (checkRequestObject && !opts.payload) {
    throw Error(SIOPErrors.BAD_PARAMS);
  }
  // assertValidRequestRegistrationOpts(opts['registration'] ? opts['registration'] : opts['clientMetadata']);
};
