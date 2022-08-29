import { IVerifyCredentialResult, ValidationStatusEnum, WellKnownDidVerifier } from '@sphereon/wellknown-dids-client';
import WDCErrors from '@sphereon/wellknown-dids-client/dist/constants/Errors';

import { LinkedDomainValidationMode } from '../types/SIOP.types';

import { resolveDidDocument } from './DIDResolution';
import { getMethodFromDid } from './DidJWT';

export async function validateWithDid(did: string, linkedDomainValidationMode: LinkedDomainValidationMode) {
  const validMessages: string[] = [
    WDCErrors.PROPERTY_LINKED_DIDS_DOES_NOT_CONTAIN_ANY_DOAMIN_LINK_CREDENTIALS.valueOf(),
    WDCErrors.PROPERTY_LINKED_DIDS_NOT_PRESENT.valueOf(),
    WDCErrors.PROPERTY_TYPE_NOT_CONTAIN_VALID_LINKED_DOMAIN.valueOf(),
    WDCErrors.PROPERTY_SERVICE_NOT_PRESENT.valueOf(),
  ];

  const verifyCallback = async (): Promise<IVerifyCredentialResult> => {
    return { verified: true };
  };
  const verifier = new WellKnownDidVerifier({
    verifySignatureCallback: () => verifyCallback(),
    onlyVerifyServiceDid: false,
  });

  const didDocument = await resolveDidDocument(did, { subjectSyntaxTypesSupported: [getMethodFromDid(did)] });
  try {
    const validationResult = await verifier.verifyDomainLinkage({ didDocument: didDocument });
    if (validationResult.status === ValidationStatusEnum.INVALID) {
      const messageCondition: boolean = validMessages.includes(validationResult.message);

      if (
        linkedDomainValidationMode === LinkedDomainValidationMode.ALWAYS ||
        (linkedDomainValidationMode === LinkedDomainValidationMode.OPTIONAL && !messageCondition)
      ) {
        throw new Error(validationResult.message);
      }
    }
  } catch (err) {
    const messageCondition: boolean = validMessages.includes(err.message);

    if (
      linkedDomainValidationMode === LinkedDomainValidationMode.ALWAYS ||
      (linkedDomainValidationMode === LinkedDomainValidationMode.OPTIONAL && !messageCondition)
    ) {
      throw new Error(err.message);
    }
  }
}
