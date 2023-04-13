import { W3CVerifiableCredential, WrappedVerifiablePresentation } from '@sphereon/ssi-types';

import { RevocationStatus, RevocationVerification, RevocationVerificationCallback, VerifiableCredentialTypeFormat } from '../types';

export const verifyRevocation = async (
  vpToken: WrappedVerifiablePresentation,
  revocationVerificationCallback: RevocationVerificationCallback,
  revocationVerification: RevocationVerification
): Promise<void> => {
  if (!vpToken) {
    throw new Error(`VP token not provided`);
  }
  if (!revocationVerificationCallback) {
    throw new Error(`Revocation callback not provided`);
  }

  const vcs = Array.isArray(vpToken.presentation.verifiableCredential)
    ? vpToken.presentation.verifiableCredential
    : [vpToken.presentation.verifiableCredential];
  for (const vc of vcs) {
    if (
      revocationVerification === RevocationVerification.ALWAYS ||
      (revocationVerification === RevocationVerification.IF_PRESENT && vc.credential.credentialStatus)
    ) {
      const result = await revocationVerificationCallback(
        vc.original as W3CVerifiableCredential,
        vc.format.toLowerCase().includes('jwt') ? VerifiableCredentialTypeFormat.JWT_VC : VerifiableCredentialTypeFormat.LDP_VC
      );
      if (result.status === RevocationStatus.INVALID) {
        throw new Error(`Revocation invalid for vc: ${vc.credential.id}. Error: ${result.error}`);
      }
    }
  }
};
