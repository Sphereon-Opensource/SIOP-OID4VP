import { getUniResolver, UniResolver } from '@sphereon/did-uni-client';
import { DIDResolutionOptions, DIDResolutionResult, ParsedDID, Resolvable, Resolver } from 'did-resolver';

import { DIDDocument, ResolveOpts, SIOPErrors, SubjectIdentifierType } from '../types';

import { getMethodFromDid } from './';

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

export async function resolveDidDocument(did: string, opts?: ResolveOpts): Promise<DIDDocument> {
  return (await getResolver(opts).resolve(did)).didDocument;
}
