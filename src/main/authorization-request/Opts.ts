import {
  AuthorizationRequestOpts,
  isExternalVerification,
  isInternalVerification,
  PassBy,
  SIOPErrors,
  VerifyAuthorizationRequestOpts,
} from '../types';

import { assertValidRequestRegistrationOpts } from './RequestRegistration';

export default class Opts {
  static assertValidVerifyOpts(opts: VerifyAuthorizationRequestOpts) {
    if (!opts || !opts.verification || (!isExternalVerification(opts.verification) && !isInternalVerification(opts.verification))) {
      throw new Error(SIOPErrors.VERIFY_BAD_PARAMS);
    }
  }

  static assertValidRequestOpts(opts: AuthorizationRequestOpts) {
    if (!opts || !opts.redirectUri) {
      throw new Error(SIOPErrors.BAD_PARAMS);
    } else if (!opts.requestBy) {
      throw new Error(SIOPErrors.BAD_PARAMS);
    } else if (opts.requestBy.type !== PassBy.REFERENCE && opts.requestBy.type !== PassBy.VALUE) {
      throw new Error(SIOPErrors.REQUEST_OBJECT_TYPE_NOT_SET);
    } else if (opts.requestBy.type === PassBy.REFERENCE && !opts.requestBy.referenceUri) {
      throw new Error(SIOPErrors.NO_REFERENCE_URI);
    }
    assertValidRequestRegistrationOpts(opts['registration']);
  }
}
