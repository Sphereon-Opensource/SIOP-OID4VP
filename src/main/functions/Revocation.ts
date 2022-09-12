import {
  RevocationStatus,
  RevocationVcType,
  RevocationVerificationCallback,
  VerifiablePresentationPayload,
  VerifiablePresentationTypeFormat
} from '../types';
//import jwt_decode from 'jwt-decode';

export const verifyRevocation = async (vpToken: VerifiablePresentationPayload, revocationVerificationCallback: RevocationVerificationCallback) => {
  if (!vpToken) {
    throw new Error(`VP token not provided`);
  }

  if (!revocationVerificationCallback) {
    throw new Error(`Revocation callback not provided`);
  }

  switch (vpToken.format) {
    case VerifiablePresentationTypeFormat.LDP_VP: {
      for (const vc of vpToken.presentation.verifiableCredential) {
        const result = await revocationVerificationCallback(vc, RevocationVcType.LDP_VC)
        if (result.status === RevocationStatus.INVALID) {
          throw new Error(`Revocation invalid for vc: ${vc.id}. Error: ${result.error}`);
        }
      }
      break;
    }
    case VerifiablePresentationTypeFormat.JWT_VP: {
      for (const vc of vpToken.presentation.verifiableCredential) {

        //const decodedVc = jwt_decode(vc, { header: false })

        const result = await revocationVerificationCallback(vc, RevocationVcType.JWT_VC)
        if (result.status === RevocationStatus.INVALID) {
          throw new Error(`Revocation invalid for vc: ${vc.id}. Error: ${result.error}`);
        }
      }
      break;
    }
    default:
      throw new Error(`VP format not supported`);
  }
}
