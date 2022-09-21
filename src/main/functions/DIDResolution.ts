import { getUniResolver, UniResolver } from '@sphereon/did-uni-client';
import { DIDResolutionOptions, DIDResolutionResult, ParsedDID, Resolvable, Resolver } from 'did-resolver';

import { DIDDocument, ResolveOpts, SIOPErrors, SubjectIdentifierType, SubjectSyntaxTypesSupportedValues } from '../types';

import { getMethodFromDid, toQualifiedDidMethod } from './';

export function getResolver(opts: ResolveOpts): Resolvable {
  if (opts && opts.resolver) {
    return opts.resolver;
  }
  if (!opts || !opts.subjectSyntaxTypesSupported) {
    throw new Error(SIOPErrors.BAD_PARAMS);
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

export function getResolverUnion(subjectSyntaxTypesSupported: string[] | string, resolverMap: Map<string, Resolvable>): Resolvable {
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
    return new UniResolver();
  }
  const specificDidMethods = subjectTypes.filter((sst) => sst.startsWith('did:'));
  specificDidMethods.forEach((dm) => {
    let uniResolver;
    if (!resolverMap.has(dm)) {
      uniResolver = getUniResolver(getMethodFromDid(dm));
    } else {
      uniResolver = getUniResolver(getMethodFromDid(dm), resolverMap.get(dm));
    }
    uniResolvers.push(uniResolver);
  });
  return new Resolver(...uniResolvers);
}

export function mergeAllDidMethods(subjectSyntaxTypesSupported: string | string[], resolvers: Map<string, Resolvable>): string[] {
  if (!Array.isArray(subjectSyntaxTypesSupported)) {
    subjectSyntaxTypesSupported = [subjectSyntaxTypesSupported];
  }
  const unionSubjectSyntaxTypes = new Set();
  subjectSyntaxTypesSupported.forEach((sst) => unionSubjectSyntaxTypes.add(sst));
  resolvers.forEach((_value, didMethod) => unionSubjectSyntaxTypes.add(toQualifiedDidMethod(didMethod)));
  return Array.from(unionSubjectSyntaxTypes) as string[];
}

export async function resolveDidDocument(did: string, opts?: ResolveOpts): Promise<DIDDocument> {
  return (await getResolver(opts).resolve(did)).didDocument;
}
