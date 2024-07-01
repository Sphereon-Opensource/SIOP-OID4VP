import { getUniResolver } from '@sphereon/did-uni-client';
import { DIDResolutionResult, ParsedDID, Resolvable, Resolver } from 'did-resolver';
import { DIDDocument as DIFDIDDocument } from 'did-resolver';
import { DIDResolutionOptions } from 'did-resolver/src/resolver';

import { SIOPErrors } from '../src';

export interface DIDDocument extends DIFDIDDocument {
  owner?: string;
  created?: string;
  updated?: string;
  proof?: LinkedDataProof;
}

export interface LinkedDataProof {
  type: string;
  created: string;
  creator: string;
  nonce: string;
  signatureValue: string;
}

export function getResolver(methods: string | string[]): Resolvable {
  function getMethodFromDid(did: string): string {
    if (!did) {
      throw new Error(SIOPErrors.BAD_PARAMS);
    }
    const split = did.split(':');
    if (split.length == 1 && did.length > 0) {
      return did;
    } else if (!did.startsWith('did:') || split.length < 2) {
      throw new Error(SIOPErrors.BAD_PARAMS);
    }

    return split[1];
  }

  const uniResolvers: {
    [p: string]: (did: string, _parsed: ParsedDID, _didResolver: Resolver, _options: DIDResolutionOptions) => Promise<DIDResolutionResult>;
  }[] = [];
  for (const didMethod of typeof methods === 'string' ? [methods] : methods) {
    const uniResolver = getUniResolver(getMethodFromDid(didMethod));
    uniResolvers.push(uniResolver);
  }
  return new Resolver(...uniResolvers);
}
