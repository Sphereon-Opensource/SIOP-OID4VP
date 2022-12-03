import { assertValidRequestRegistrationOpts } from '../authorization-request/RequestRegistration';
import { PassBy, RequestObjectOpts, SIOPErrors } from '../types';

export const assertValidRequestObjectOpts = (opts: RequestObjectOpts, checkRequestObject: boolean) => {
  if (!opts) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  } else if (!opts.requestBy) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  } else if (opts.requestBy.type !== PassBy.REFERENCE && opts.requestBy.type !== PassBy.VALUE) {
    throw new Error(SIOPErrors.REQUEST_OBJECT_TYPE_NOT_SET);
  } else if (opts.requestBy.type === PassBy.REFERENCE && !opts.requestBy.referenceUri) {
    throw new Error(SIOPErrors.NO_REFERENCE_URI);
  } else if (checkRequestObject && !opts.requestBy.request) {
    throw Error(SIOPErrors.BAD_PARAMS);
  }
  assertValidRequestRegistrationOpts(opts['registration']);
};
