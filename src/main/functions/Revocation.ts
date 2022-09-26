import { IVerifiableCredential } from '@sphereon/ssi-types';

import {
  RevocationStatus,
  RevocationVerification,
  RevocationVerificationCallback,
  VerifiableCredentialTypeFormat,
  VerifiablePresentationPayload,
  VerifiablePresentationTypeFormat,
} from '../types';

export const verifyRevocation = async (
  vpToken: VerifiablePresentationPayload,
  revocationVerificationCallback: RevocationVerificationCallback,
  revocationVerification: RevocationVerification
): Promise<void> => {
  if (!vpToken) {
    throw new Error(`VP token not provided`);
  }

  if (!revocationVerificationCallback) {
    throw new Error(`Revocation callback not provided`);
  }

  switch (vpToken.format) {
    case VerifiablePresentationTypeFormat.LDP_VP: {
      for (const vc of vpToken.presentation.verifiableCredential) {
        if (
          revocationVerification === RevocationVerification.ALWAYS ||
          (revocationVerification === RevocationVerification.IF_PRESENT && (<IVerifiableCredential>vc).credentialStatus)
        ) {
          const result = await revocationVerificationCallback(<IVerifiableCredential>vc, VerifiableCredentialTypeFormat.LDP_VC);
          if (result.status === RevocationStatus.INVALID) {
            throw new Error(`Revocation invalid for vc: ${(<IVerifiableCredential>vc).id}. Error: ${result.error}`);
          }
        }
      }
      break;
    }
    case VerifiablePresentationTypeFormat.JWT_VP: {
      // TODO create implementation for JWT status-list-2021 verification, we already have a callback, but we also need to parse the vp token
      break;
    }
    default:
      throw new Error(`VP format not supported`);
  }
};
