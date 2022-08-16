import { Format } from '@sphereon/pex-models';

import { SIOP, SIOPErrors } from '../types';
import { CommonSupportedMetadata, DiscoveryMetadataPayload, RPRegistrationMetadataPayload, SubjectIdentifierType } from '../types/SIOP.types';

//TODO, since syntax_types_Supported can contain non DIDs, fix it in the VDX-126
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

function getFormatIntersection(rpFormat: Format, opFormat: Format) {
  const intersectionFormat: Format = {};
  const supportedCredentials = getIntersection(Object.keys(rpFormat), Object.keys(opFormat));
  if (!supportedCredentials.length) {
    throw new Error(SIOPErrors.CREDENTIAL_FORMATS_NOT_SUPPORTED);
  }
  supportedCredentials.forEach(function (crFormat) {
    const rpAlgs = [];
    const opAlgs = [];
    Object.keys(rpFormat[crFormat]).forEach((k) => rpAlgs.push(...rpFormat[crFormat][k]));
    Object.keys(opFormat[crFormat]).forEach((k) => opAlgs.push(...opFormat[crFormat][k]));
    let methodKeyRP = undefined;
    let methodKeyOP = undefined;
    Object.keys(rpFormat[crFormat]).forEach((k) => (methodKeyRP = k));
    Object.keys(opFormat[crFormat]).forEach((k) => (methodKeyOP = k));
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

export function supportedCredentialsFormats(rpFormat: Format, opFormat: Format): Format {
  if (!rpFormat || !opFormat || !Object.keys(rpFormat).length || !Object.keys(opFormat).length) {
    throw new Error(SIOPErrors.CREDENTIALS_FORMATS_NOT_PROVIDED);
  }
  return getFormatIntersection(rpFormat, opFormat);
}
