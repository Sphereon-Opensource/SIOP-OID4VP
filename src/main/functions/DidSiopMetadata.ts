import { SIOP, SIOPErrors } from '../types';
import { CommonSupportedMetadata, DiscoveryMetadataPayload, RPRegistrationMetadataPayload, SubjectIdentifierType } from '../types/SIOP.types';

export function assertValidMetadata(opMetadata: DiscoveryMetadataPayload, rpMetadata: RPRegistrationMetadataPayload): CommonSupportedMetadata {
  let methods = [];
  const credentials = supportedCredentialsFormats(rpMetadata.credential_formats_supported, opMetadata.credential_formats_supported);
  const isDid = verifySubjectIdentifiers(rpMetadata.subject_identifiers_supported);
  if (isDid && rpMetadata.did_methods_supported) {
    methods = supportedDidMethods(rpMetadata.did_methods_supported, opMetadata.did_methods_supported);
  } else if (isDid && (!rpMetadata.did_methods_supported || !rpMetadata.did_methods_supported.length)) {
    if (opMetadata.did_methods_supported || opMetadata.did_methods_supported.length) {
      methods = [...opMetadata.did_methods_supported];
    }
  }
  return { credential_formats_supported: credentials, did_methods_supported: methods };
}

function getIntersection<T>(rpMetadata: Array<T> | T, opMetadata: Array<T> | T): Array<T> {
  let arrayA, arrayB;
  if (!Array.isArray(rpMetadata)) {
    arrayA = [rpMetadata];
  } else {
    arrayA = rpMetadata;
  }
  if (!Array.isArray(opMetadata)) {
    arrayB = [opMetadata];
  } else {
    arrayB = opMetadata;
  }
  return arrayA.filter((value) => arrayB.includes(value));
}

function verifySubjectIdentifiers(subjectIdentifiers: SubjectIdentifierType | SubjectIdentifierType[]): boolean {
  if (subjectIdentifiers || subjectIdentifiers.length) {
    if (Array.isArray(subjectIdentifiers)) {
      return subjectIdentifiers.includes(SIOP.SubjectIdentifierType.DID);
    }
    return subjectIdentifiers === SIOP.SubjectIdentifierType.DID;
  } else {
    return false;
  }
}

function supportedDidMethods(rpMethods: string[] | string, opMethods: string[] | string): Array<string> {
  const supportedDidMethods = getIntersection(rpMethods, opMethods);
  if (!supportedDidMethods.length) {
    throw Error(SIOPErrors.DID_METHODS_NOT_SUPORTED);
  }
  return supportedDidMethods;
}

function supportedCredentialsFormats(rpCredentials: string[] | string, opCredentials: string[] | string): Array<string> {
  const supportedCredentials = getIntersection(rpCredentials, opCredentials);
  if (!supportedCredentials.length) {
    throw new Error(SIOPErrors.CREDENTIAL_FORMATS_NOT_SUPPORTED);
  }
  return supportedCredentials;
}
