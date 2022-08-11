import { Format } from '@sphereon/pex-models';

import { SIOP, SIOPErrors } from '../types';
import { CommonSupportedMetadata, DiscoveryMetadataPayload, RPRegistrationMetadataPayload, SubjectIdentifierType } from '../types/SIOP.types';

export function assertValidMetadata(opMetadata: DiscoveryMetadataPayload, rpMetadata: RPRegistrationMetadataPayload): CommonSupportedMetadata {
  let subjectSyntaxTypesSupported = [];
  const credentials = supportedCredentialsFormats(rpMetadata.vp_formats, opMetadata.vp_formats);
  const isDid = verifySubjectIdentifiers(rpMetadata.subject_syntax_types_supported);
  if (isDid && rpMetadata.subject_syntax_types_supported) {
    subjectSyntaxTypesSupported = supportedDidMethods(rpMetadata.subject_syntax_types_supported, opMetadata.subject_syntax_types_supported);
  } else if (isDid && (!rpMetadata.subject_syntax_types_supported || !rpMetadata.subject_syntax_types_supported.length)) {
    if (opMetadata.subject_syntax_types_supported || opMetadata.subject_syntax_types_supported.length) {
      subjectSyntaxTypesSupported = [...opMetadata.subject_syntax_types_supported];
    }
  }
  return { vp_formats: credentials, subject_syntax_types_supported: subjectSyntaxTypesSupported };
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

function verifySubjectIdentifiers(subjectSyntaxTypesSupported: string[]): boolean {
  if (subjectSyntaxTypesSupported.length) {
    if (Array.isArray(subjectSyntaxTypesSupported)) {
      return subjectSyntaxTypesSupported.includes(SIOP.SubjectIdentifierType.DID);
    }
  }
  return false;
}

function supportedDidMethods(rpMethods: string[] | string, opMethods: string[] | string): Array<string> {
  const supportedDidMethods = getIntersection(rpMethods, opMethods);
  if (!supportedDidMethods.length || (supportedDidMethods.length === 1 && supportedDidMethods[0] === SubjectIdentifierType.DID)) {
    throw Error(SIOPErrors.DID_METHODS_NOT_SUPORTED);
  }
  return supportedDidMethods;
}

export function supportedCredentialsFormats(rpCredentials: Format, opCredentials: Format): Format {
  if (!rpCredentials || !opCredentials || !Object.keys(rpCredentials).length || !Object.keys(opCredentials).length) {
    throw new Error(SIOPErrors.CREDENTIALS_FORMATS_NOT_PROVIDED);
  }
  const supportedCredentials = getIntersection(Object.keys(rpCredentials), Object.keys(opCredentials));
  if (!supportedCredentials.length) {
    throw new Error(SIOPErrors.CREDENTIAL_FORMATS_NOT_SUPPORTED);
  }
  const intersectionFormat: Format = {};
  supportedCredentials.forEach(function (crFormat) {
    const rpAlgs = [];
    const opAlgs = [];
    Object.keys(rpCredentials[crFormat]).forEach((k) => rpAlgs.push(...rpCredentials[crFormat][k]));
    Object.keys(opCredentials[crFormat]).forEach((k) => opAlgs.push(...opCredentials[crFormat][k]));
    let methodKeyRP = undefined;
    let methodKeyOP = undefined;
    Object.keys(rpCredentials[crFormat]).forEach((k) => (methodKeyRP = k));
    Object.keys(opCredentials[crFormat]).forEach((k) => (methodKeyOP = k));
    if (methodKeyRP !== methodKeyOP) {
      throw new Error(SIOPErrors.CREDENTIAL_FORMATS_NOT_SUPPORTED);
    }
    const algs = getIntersection(rpAlgs, opAlgs);
    if (!algs.length) {
      throw new Error(SIOPErrors.CREDENTIAL_FORMATS_NOT_SUPPORTED);
    }
    intersectionFormat[crFormat] = {};
    intersectionFormat[crFormat][methodKeyOP] = algs;
  });
  return intersectionFormat;
}
