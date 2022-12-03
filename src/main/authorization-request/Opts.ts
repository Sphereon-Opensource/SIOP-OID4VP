import { assertValidRequestObjectOpts } from '../request-object/Opts';
import { AuthorizationRequestOpts, isExternalVerification, isInternalVerification, SIOPErrors, VerifyAuthorizationRequestOpts } from '../types';

import { assertValidRequestRegistrationOpts } from './RequestRegistration';

export const assertValidVerifyAuthorizationRequestOpts = (opts: VerifyAuthorizationRequestOpts) => {
  if (!opts || !opts.verification || (!isExternalVerification(opts.verification) && !isInternalVerification(opts.verification))) {
    throw new Error(SIOPErrors.VERIFY_BAD_PARAMS);
  }
};

export const assertValidAuthorizationRequestOpts = (opts: AuthorizationRequestOpts) => {
  if (!opts || !opts.redirectUri) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  }
  assertValidRequestObjectOpts(opts, false);
  assertValidRequestRegistrationOpts(opts['registration']);
};
