import { SIOP, SIOPErrors } from '../types';
import { DiscoveryMetadataPayload, RPRegistrationMetadataPayload, SubjectIdentifierType } from '../types/SIOP.types';

export function assertValidMetadata(opMetadata: DiscoveryMetadataPayload, rpMetadata: RPRegistrationMetadataPayload) {
  verifyCredentialsFormat(rpMetadata.credential_formats_supported, opMetadata.credential_formats_supported);
  const isDid = verifySubjectIdentifiers(rpMetadata.subject_identifiers_supported);
  if (isDid && rpMetadata.did_methods_supported) {
    verifyDidMethods(rpMetadata.did_methods_supported, opMetadata.did_methods_supported);
  }
}

function getIntersection<T>(a: Array<T> | T, b: Array<T> | T): Array<T> {
  let arrayA, arrayB;
  if (!Array.isArray(a)) {
    arrayA = [a];
  } else {
    arrayA = a;
  }
  if (!Array.isArray(b)) {
    arrayB = [b];
  } else {
    arrayB = b;
  }
  return arrayA.filter((value) => arrayB.includes(value));
}

function verifySubjectIdentifiers(subjectIdentifiers: SubjectIdentifierType | SubjectIdentifierType[]) {
  if (Array.isArray(subjectIdentifiers)) {
    return subjectIdentifiers.includes(SIOP.SubjectIdentifierType.DID);
  }
  return subjectIdentifiers === SIOP.SubjectIdentifierType.DID;
}

function verifyDidMethods(methodsA: string[] | string, methodsB: string[] | string): void {
  const supportedDidMethods = getIntersection(methodsA, methodsB);
  if (!supportedDidMethods.length) {
    throw Error(SIOPErrors.DID_METHODS_NOT_SUPORTED);
  }
}

function verifyCredentialsFormat(credentialsA: string[] | string, credentialsB: string[] | string): void {
  const supportedCredentials = getIntersection(credentialsA, credentialsB);
  if (!supportedCredentials.length) {
    throw new Error(SIOPErrors.CREDENTIAL_FORMATS_NOT_SUPPORTED);
  }
}
