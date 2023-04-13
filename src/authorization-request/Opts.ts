import { assertValidRequestObjectOpts } from '../request-object/Opts';
import { isExternalVerification, isInternalVerification, SIOPErrors } from '../types';

import { assertValidRequestRegistrationOpts } from './RequestRegistration';
import { CreateAuthorizationRequestOpts, VerifyAuthorizationRequestOpts } from './types';

export const assertValidVerifyAuthorizationRequestOpts = (opts: VerifyAuthorizationRequestOpts) => {
  if (!opts || !opts.verification || (!isExternalVerification(opts.verification) && !isInternalVerification(opts.verification))) {
    throw new Error(SIOPErrors.VERIFY_BAD_PARAMS);
  }
  if (!opts.correlationId) {
    throw new Error('No correlation id found');
  }
};

export const assertValidAuthorizationRequestOpts = (opts: CreateAuthorizationRequestOpts) => {
  if (!opts || !opts.requestObject || (!opts.payload && !opts.requestObject.payload) || (opts.payload?.request_uri && !opts.requestObject.payload)) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  }
  assertValidRequestObjectOpts(opts.requestObject, false);
  assertValidRequestRegistrationOpts(opts['registration'] ? opts['registration'] : opts.clientMetadata);
};
