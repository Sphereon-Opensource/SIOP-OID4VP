import { getUniResolver } from '@sphereon/did-uni-client';
import { DIDResolutionOptions, DIDResolutionResult, ParsedDID, Resolvable, Resolver } from 'did-resolver';

import SIOPErrors from '../types/Errors';
import { ResolveOpts } from '../types/SSI.types';

import { getMethodFromDid } from './DidJWT';

export function getResolver(opts: ResolveOpts): Resolvable {
  if (opts && opts.resolver) {
    return opts.resolver;
  }
  if (!opts || !opts.subjectSyntaxTypesSupported) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  }
  // 'did:eth:'
  // const didMethods = opts.subjectSyntaxTypesSupported.filter((supported) => supported.includes('did:'));
  const uniResolvers: {
    [p: string]: (did: string, _parsed: ParsedDID, _didResolver: Resolver, _options: DIDResolutionOptions) => Promise<DIDResolutionResult>;
  }[] = [];
  for (const didMethod of opts.subjectSyntaxTypesSupported) {
    const uniResolver = getUniResolver(getMethodFromDid(didMethod), { resolveUrl: opts.resolveUrl });
    uniResolvers.push(uniResolver);
  }
  return new Resolver(...uniResolvers);
}
