import { assertValidRequestRegistrationOpts } from '../AuthenticationRequestRegistration';
import {
  AuthenticationRequestOpts,
  isExternalVerification,
  isInternalVerification,
  PassBy,
  SIOPErrors,
  VerifyAuthenticationRequestOpts,
} from '../types';

export default class Opts {
  static assertValidVerifyOpts(opts: VerifyAuthenticationRequestOpts) {
    if (!opts || !opts.verification || (!isExternalVerification(opts.verification) && !isInternalVerification(opts.verification))) {
      throw new Error(SIOPErrors.VERIFY_BAD_PARAMS);
    }
  }

  static assertValidRequestOpts(opts: AuthenticationRequestOpts) {
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
