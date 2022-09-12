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

function getValidationErrorMessages(validationResult: IDomainLinkageValidation): string[] {
  const messages = [];
  if (validationResult.message) {
    messages.push(validationResult.message);
  }
  if (validationResult?.endpointDescriptors.length) {
    for (const endpointDescriptor of validationResult.endpointDescriptors) {
      if (endpointDescriptor.message) {
        messages.push(endpointDescriptor.message);
      }
      if (endpointDescriptor.resources) {
        for (const resource of endpointDescriptor.resources) {
          if (resource.message) {
            messages.push(resource.message);
          }
        }
      }
    }
  }
  return messages;
}

/**
 * @param validationErrorMessages
 * @return returns false if the messages received from wellknown-dids-client makes this invalid for CheckLinkedDomain.IF_PRESENT plus the message itself
 *                  and true for when we can move on
 */
function checkInvalidMessages(validationErrorMessages: string[]): { status: boolean; message?: string } {
  if (!validationErrorMessages || !validationErrorMessages.length) {
    return { status: false, message: 'linked domain is invalid.' };
  }
  const validMessages: string[] = [
    WDCErrors.PROPERTY_LINKED_DIDS_DOES_NOT_CONTAIN_ANY_DOMAIN_LINK_CREDENTIALS.valueOf(),
    WDCErrors.PROPERTY_LINKED_DIDS_NOT_PRESENT.valueOf(),
    WDCErrors.PROPERTY_TYPE_NOT_CONTAIN_VALID_LINKED_DOMAIN.valueOf(),
    WDCErrors.PROPERTY_SERVICE_NOT_PRESENT.valueOf(),
  ];
  for (const validationErrorMessage of validationErrorMessages) {
    if (!validMessages.filter((vm) => validationErrorMessage.includes(vm)).pop()) {
      return { status: false, message: validationErrorMessage };
    }
  }
  return { status: true };
}

export async function validateLinkedDomainWithDid(did: string, verifyCallback: () => Promise<IVerifyCredentialResult>, checkLinkedDomain: CheckLinkedDomain) {
  const didDocument = await resolveDidDocument(did, { subjectSyntaxTypesSupported: [getMethodFromDid(did)] });
  try {
    const validationResult = await checkWellKnownDid({ didDocument, verifyCallback });
    if (validationResult.status === ValidationStatusEnum.INVALID) {
      const validationErrorMessages = getValidationErrorMessages(validationResult);
      const messageCondition: { status: boolean; message?: string } = checkInvalidMessages(validationErrorMessages);
      if (checkLinkedDomain === CheckLinkedDomain.ALWAYS || (checkLinkedDomain === CheckLinkedDomain.IF_PRESENT && !messageCondition.status)) {
        throw new Error(messageCondition.message ? messageCondition.message : validationErrorMessages[0]);
      }
    }
  } catch (err) {
    const messageCondition: { status: boolean; message?: string } = checkInvalidMessages([err.message]);
    if (checkLinkedDomain === CheckLinkedDomain.ALWAYS || (checkLinkedDomain === CheckLinkedDomain.IF_PRESENT && !messageCondition.status)) {
      throw new Error(err.message);
    }
  }
}

interface CheckWellKnownDidArgs {
  didDocument: DIDDocument;
  verifyCallback: () => Promise<IVerifyCredentialResult>
}

async function checkWellKnownDid(args: CheckWellKnownDidArgs): Promise<IDomainLinkageValidation> {
  const verifier = new WellKnownDidVerifier({
    verifySignatureCallback: () => args.verifyCallback(),
    onlyVerifyServiceDid: false,
  });
  return await verifier.verifyDomainLinkage({ didDocument: args.didDocument });
}