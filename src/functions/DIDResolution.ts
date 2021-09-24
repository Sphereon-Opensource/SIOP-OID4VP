import { getResolver as getUniResolver } from '@sphereon/did-uni-client/dist/resolver/Resolver';
import { fetch } from 'cross-fetch';
import { DIDResolutionOptions, DIDResolutionResult, ParsedDID, Resolvable, Resolver } from 'did-resolver';

import SIOPErrors from '../types/Errors';
import { DIDDocument, ResolveOpts } from '../types/SSI.types';

import { getMethodFromDid } from './DidJWT';

export function getResolver(opts: ResolveOpts): Resolvable {
  if (opts && opts.resolver) {
    return opts.resolver;
  }
  if (!opts || !opts.didMethods) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  }

  const uniResolvers: {
    [p: string]: (
      did: string,
      _parsed: ParsedDID,
      _didResolver: Resolver,
      _options: DIDResolutionOptions
    ) => Promise<DIDResolutionResult>;
  }[] = [];
  for (const didMethod of opts.didMethods) {
    const uniResolver = getUniResolver(getMethodFromDid(didMethod), { resolveUrl: opts.resolveUrl });
    uniResolvers.push(uniResolver);
  }
  return new Resolver(...uniResolvers);
}

export async function resolveDidDocument(did: string, opts?: ResolveOpts): Promise<DIDDocument> {
  return (await getResolver(opts).resolve(did)).didDocument;
}

export async function fetchDidDocument(uri: string): Promise<DIDDocument> {
  const response = await fetch(uri);
  if (!response) {
    throw new Error('ERROR_RETRIEVING_DID_DOCUMENT');
  }
  const json = await response.json();
  const didDoc = json as DIDDocument;
  if (!didDoc.verificationMethod && !didDoc.verificationMethod[0] && !didDoc.verificationMethod[0].publicKeyJwk) {
    throw new Error('ERROR_RETRIEVING_DID_DOCUMENT');
  }
  return didDoc;
}
