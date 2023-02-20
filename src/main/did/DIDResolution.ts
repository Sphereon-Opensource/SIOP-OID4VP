import { getUniResolver, UniResolver } from '@sphereon/did-uni-client';
import { DIDResolutionOptions, DIDResolutionResult, ParsedDID, Resolvable, Resolver } from 'did-resolver';

import { getMethodFromDid, toSIOPRegistrationDidMethod } from '../did';
import { DIDDocument, ResolveOpts, SIOPErrors, SubjectIdentifierType, SubjectSyntaxTypesSupportedValues } from '../types';

export function getResolver(opts: ResolveOpts): Resolvable {
  if (opts && opts.resolver) {
    return opts.resolver;
  }
  if (!opts || !opts.subjectSyntaxTypesSupported) {
    return new UniResolver();
    // throw new Error(`${SIOPErrors.BAD_PARAMS} No subject syntax types supported`);
  }

  const uniResolvers: {
    [p: string]: (did: string, _parsed: ParsedDID, _didResolver: Resolver, _options: DIDResolutionOptions) => Promise<DIDResolutionResult>;
  }[] = [];
  if (opts.subjectSyntaxTypesSupported.indexOf(SubjectIdentifierType.DID) === -1) {
    const specificDidMethods = opts.subjectSyntaxTypesSupported.filter((sst) => sst.includes('did:'));
    if (!specificDidMethods.length) {
      throw new Error(SIOPErrors.NO_DID_METHOD_FOUND);
    }
    for (const didMethod of specificDidMethods) {
      const uniResolver = getUniResolver(getMethodFromDid(didMethod), { resolveUrl: opts.resolveUrl });
      uniResolvers.push(uniResolver);
    }
    return new Resolver(...uniResolvers);
  } else {
    return new UniResolver();
  }
}

/**
 * This method returns a resolver object in OP/RP
 * If the user of this library, configures OP/RP to have a customResolver, we will use that
 * If the user of this library configures OP/RP to use a custom resolver for any specific did method, we will use that
 * and in the end for the rest of the did methods, configured either with calling `addDidMethod` upon building OP/RP
 * (without any resolver configuration) or declaring in the subject_syntax_types_supported of the registration object
 * we will use universal resolver from Sphereon's DID Universal Resolver library
 * @param customResolver
 * @param subjectSyntaxTypesSupported
 * @param resolverMap
 */
export function getResolverUnion(
  customResolver: Resolvable,
  subjectSyntaxTypesSupported: string[] | string,
  resolverMap: Map<string, Resolvable>
): Resolvable {
  if (customResolver) {
    return customResolver;
  }
  const fallbackResolver: Resolvable = customResolver ? customResolver : new UniResolver();
  const uniResolvers: {
    [p: string]: (did: string, _parsed: ParsedDID, _didResolver: Resolver, _options: DIDResolutionOptions) => Promise<DIDResolutionResult>;
  }[] = [];
  const subjectTypes: string[] = [];
  if (subjectSyntaxTypesSupported) {
    typeof subjectSyntaxTypesSupported === 'string'
      ? subjectTypes.push(subjectSyntaxTypesSupported)
      : subjectTypes.push(...subjectSyntaxTypesSupported);
  }
  if (subjectTypes.indexOf(SubjectSyntaxTypesSupportedValues.DID.valueOf()) !== -1) {
    return customResolver ? customResolver : new UniResolver();
  }
  const specificDidMethods = subjectTypes.filter((sst) => !!sst && sst.startsWith('did:'));
  specificDidMethods.forEach((dm) => {
    let methodResolver;
    if (!resolverMap.has(dm) || resolverMap.get(dm) === null) {
      methodResolver = getUniResolver(getMethodFromDid(dm));
    } else {
      methodResolver = resolverMap.get(dm);
    }
    uniResolvers.push(methodResolver);
  });
  return subjectTypes.indexOf(SubjectSyntaxTypesSupportedValues.DID.valueOf()) !== -1
    ? new Resolver(...{ fallbackResolver, ...uniResolvers })
    : new Resolver(...uniResolvers);
}

export function mergeAllDidMethods(subjectSyntaxTypesSupported: string | string[], resolvers: Map<string, Resolvable>): string[] {
  if (!Array.isArray(subjectSyntaxTypesSupported)) {
    subjectSyntaxTypesSupported = [subjectSyntaxTypesSupported];
  }
  const unionSubjectSyntaxTypes = new Set();
  subjectSyntaxTypesSupported.forEach((sst) => unionSubjectSyntaxTypes.add(sst));
  resolvers.forEach((_, didMethod) => unionSubjectSyntaxTypes.add(toSIOPRegistrationDidMethod(didMethod)));
  return Array.from(unionSubjectSyntaxTypes) as string[];
}

export async function resolveDidDocument(did: string, opts?: ResolveOpts): Promise<DIDDocument> {
  return (await getResolver(opts).resolve(did)).didDocument;
}
