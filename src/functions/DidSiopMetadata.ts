import { SIOP, SIOPErrors } from '../types';
import {
  DiscoveryMetadataPayload,
  RPRegistrationMetadataPayload,
  SubjectIdentifierType,
  SupportedTypes,
} from '../types/SIOP.types';

const allDidMethodsSupported = [
  'did:3:',
  'did:abt:',
  'did:aergo:',
  'did:ala:',
  'did:amo:',
  'did:bba:',
  'did:bid:',
  'did:bnb:',
  'did:bryk:',
  'did:btcr:',
  'did:ccp:',
  'did:celo:',
  'did:com:',
  'did:corda:',
  'did:did:',
  'did:dns:',
  'did:dock:',
  'did:dom:',
  'did:dual:',
  'did:echo:',
  'did:elastos:',
  'did:elem:',
  'did:emtrust:',
  'did:ens:',
  'did:eosio:',
  'did:evan:',
  'did:example:',
  'did:erc725:',
  'did:etho:',
  'did:ethr:',
  'did:factom:',
  'did:future:',
  'did:gatc:',
  'did:git:',
  'did:github:',
  'did:grg:',
  'did:hedera:',
  'did:holo:',
  'did:hpass:',
  'did:icon:',
  'did:infra:',
  'did:io:',
  'did:ion:',
  'did:iota:',
  'did:ipid:',
  'did:is:',
  'did:iwt:',
  'did:jlinc:',
  'did:jnctn:',
  'did:jolo:',
  'did:keri:',
  'did:key:',
  'did:kilt:',
  'did:klay:',
  'did:kr:',
  'did:life:',
  'did:lit:',
  'did:meme:',
  'did:meta:',
  'did:moac:',
  'did:monid:',
  'did:morpheus:',
  'did:mydata:',
  'did:near:',
  'did:nft:',
  'did:ockam:',
  'did:onion:',
  'did:ont:',
  'did:omn:',
  'did:op:',
  'did:orb:',
  'did:panacea:',
  'did:peer:',
  'did:pistis:',
  'did:pkh:',
  'did:polygon:',
  'did:ptn:',
  'did:safe:',
  'did:san:',
  'did:schema:',
  'did:selfkey:',
  'did:signor:',
  'did:sirius:',
  'did:sol:',
  'did:sov:',
  'did:ssb:',
  'did:ssw:',
  'did:stack:',
  'did:tangle:',
  'did:tls:',
  'did:trust:',
  'did:trustbloc:',
  'did:trx:',
  'did:ttm:',
  'did:tyron:',
  'did:twit:',
  'did:tys:',
  'did:tz:',
  'did:unik:',
  'did:unisot:',
  'did:uns:',
  'did:uport:',
  'did:v1:',
  'did:vaa:',
  'did:vaultie:',
  'did:vid:',
  'did:vivid:',
  'did:vvo:',
  'did:web:',
  'did:wlk:',
  'did:work:',
  'did:lac:',
  'did:pml:',
];

export function assertValidMetadata(
  opMetadata: DiscoveryMetadataPayload,
  rpMetadata: RPRegistrationMetadataPayload
): SupportedTypes {
  let methods = [];
  const credentials = verifyCredentialsFormat(
    rpMetadata.credential_formats_supported,
    opMetadata.credential_formats_supported
  );
  const isDid = verifySubjectIdentifiers(rpMetadata.subject_identifiers_supported);
  if (isDid && rpMetadata.did_methods_supported) {
    methods = verifyDidMethods(rpMetadata.did_methods_supported, opMetadata.did_methods_supported);
  } else if (isDid && (!rpMetadata.did_methods_supported || !rpMetadata.did_methods_supported.length)) {
    methods = verifyDidMethods(allDidMethodsSupported, opMetadata.did_methods_supported);
  }
  return { op_rp_credential_formats_supported: credentials, op_rp_did_methods_supported: methods };
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

function verifyDidMethods(methodsA: string[] | string, methodsB: string[] | string): Array<string> {
  const supportedDidMethods = getIntersection(methodsA, methodsB);
  if (!supportedDidMethods.length) {
    throw Error(SIOPErrors.DID_METHODS_NOT_SUPORTED);
  }
  return supportedDidMethods;
}

function verifyCredentialsFormat(credentialsA: string[] | string, credentialsB: string[] | string): Array<string> {
  const supportedCredentials = getIntersection(credentialsA, credentialsB);
  if (!supportedCredentials.length) {
    throw new Error(SIOPErrors.CREDENTIAL_FORMATS_NOT_SUPPORTED);
  }
  return supportedCredentials;
}
