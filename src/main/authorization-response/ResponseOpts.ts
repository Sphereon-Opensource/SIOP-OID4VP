import {
  AuthorizationResponseOpts,
  isExternalSignature,
  isExternalVerification,
  isInternalSignature,
  isInternalVerification,
  isSuppliedSignature,
  SIOPErrors,
  VerifyAuthorizationResponseOpts,
} from '../types';

export const assertValidResponseOpts = (opts: AuthorizationResponseOpts) => {
  if (!opts /*|| !opts.redirectUri*/ || !opts.signatureType /*|| !opts.nonce*/ || !opts.did) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  } else if (!(isInternalSignature(opts.signatureType) || isExternalSignature(opts.signatureType) || isSuppliedSignature(opts.signatureType))) {
    throw new Error(SIOPErrors.SIGNATURE_OBJECT_TYPE_NOT_SET);
  }
};

export const assertValidVerifyOpts = (opts: VerifyAuthorizationResponseOpts) => {
  if (!opts || !opts.verification || (!isExternalVerification(opts.verification) && !isInternalVerification(opts.verification))) {
    throw new Error(SIOPErrors.VERIFY_BAD_PARAMS);
  }
};
