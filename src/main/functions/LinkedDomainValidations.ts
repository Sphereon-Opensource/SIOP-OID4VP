import {
  IDomainLinkageValidation,
  IVerifyCredentialResult,
  ValidationStatusEnum,
  WDCErrors,
  WellKnownDidVerifier,
} from '@sphereon/wellknown-dids-client';

import { CheckLinkedDomain, DIDDocument } from '../types';

import { resolveDidDocument } from './DIDResolution';
import { getMethodFromDid } from './DidJWT';

export async function validateLinkedDomainWithDid(did: string, checkLinkedDomain: CheckLinkedDomain) {
  const validMessages: string[] = [
    WDCErrors.PROPERTY_LINKED_DIDS_DOES_NOT_CONTAIN_ANY_DOMAIN_LINK_CREDENTIALS.valueOf(),
    WDCErrors.PROPERTY_LINKED_DIDS_NOT_PRESENT.valueOf(),
    WDCErrors.PROPERTY_TYPE_NOT_CONTAIN_VALID_LINKED_DOMAIN.valueOf(),
    WDCErrors.PROPERTY_SERVICE_NOT_PRESENT.valueOf(),
  ];

  const didDocument = await resolveDidDocument(did, { subjectSyntaxTypesSupported: [getMethodFromDid(did)] });
  try {
    const validationResult = await checkWellknownDid(didDocument);
    if (validationResult.status === ValidationStatusEnum.INVALID) {
      const messageCondition: boolean = validMessages.includes(validationResult.message);

      if (checkLinkedDomain === CheckLinkedDomain.ALWAYS || (checkLinkedDomain === CheckLinkedDomain.IF_PRESENT && !messageCondition)) {
        throw new Error(
          validationResult.message
            ? validationResult.message
            : validationResult.endpointDescriptors.length
            ? validationResult.endpointDescriptors[0].message
            : 'Failed to validate domain linkage.'
        );
      }
    }
  } catch (err) {
    const messageCondition: boolean = validMessages.includes(err.message);
    if (checkLinkedDomain === CheckLinkedDomain.ALWAYS || (checkLinkedDomain === CheckLinkedDomain.IF_PRESENT && !messageCondition)) {
      throw new Error(err.message);
    }
  }
}

async function checkWellknownDid(didDocument: DIDDocument): Promise<IDomainLinkageValidation> {
  const verifyCallback = async (): Promise<IVerifyCredentialResult> => {
    return { verified: true };
  };
  const verifier = new WellKnownDidVerifier({
    verifySignatureCallback: () => verifyCallback(),
    onlyVerifyServiceDid: false,
  });
  return await verifier.verifyDomainLinkage({ didDocument: didDocument });
}
