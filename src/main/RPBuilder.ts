import { getUniResolver } from '@sphereon/did-uni-client';
import { Resolvable, Resolver } from 'did-resolver';

import { RP } from './RP';
import { getMethodFromDid, toSIOPRegistrationDidMethod } from './functions';
import {
  CheckLinkedDomain,
  ClaimOpts,
  EcdsaSignature,
  ExternalSignature,
  InternalSignature,
  NoSignature,
  ObjectBy,
  PassBy,
  PresentationDefinitionWithLocation,
  RequestRegistrationOpts,
  ResponseContext,
  ResponseIss,
  ResponseMode,
  SuppliedSignature,
} from './types';

export default class RPBuilder {
  authorizationEndpoint: string;
  issuer: ResponseIss;
  resolvers: Map<string, Resolvable> = new Map<string, Resolvable>();
  customResolver?: Resolvable;
  requestRegistration: Partial<RequestRegistrationOpts> = {};
  redirectUri: string;
  requestObjectBy: ObjectBy;
  signatureType: InternalSignature | ExternalSignature | SuppliedSignature | NoSignature;
  responseMode?: ResponseMode;
  responseContext?: ResponseContext.RP;
  claims?: ClaimOpts;
  checkLinkedDomain?: CheckLinkedDomain;
  didMethods: string[] = [];
  // claims?: ClaimPayload;

  addIssuer(issuer: ResponseIss): RPBuilder {
    this.issuer = issuer;
    return this;
  }

  withCustomResolver(resolver: Resolvable): RPBuilder {
    this.customResolver = resolver;
    return this;
  }

  addResolver(didMethod: string, resolver: Resolvable): RPBuilder {
    if (!this.requestRegistration.subjectSyntaxTypesSupported || !this.requestRegistration.subjectSyntaxTypesSupported.length) {
      this.requestRegistration.subjectSyntaxTypesSupported = [];
    }
    this.requestRegistration.subjectSyntaxTypesSupported.push(toSIOPRegistrationDidMethod(didMethod));
    this.resolvers.set(getMethodFromDid(didMethod), resolver);
    return this;
  }

  withAuthorizationEndpoint(authorizationEndpoint: string): RPBuilder {
    this.authorizationEndpoint = authorizationEndpoint;
    return this;
  }

  withCheckLinkedDomain(mode: CheckLinkedDomain): RPBuilder {
    this.checkLinkedDomain = mode;
    return this;
  }

  addDidMethod(didMethod: string, opts?: { resolveUrl?: string; baseUrl?: string }): RPBuilder {
    if (didMethod.startsWith('did:')) {
      this.addResolver(getMethodFromDid(didMethod), new Resolver(getUniResolver(getMethodFromDid(didMethod), { ...opts })));
      this.didMethods.push(getMethodFromDid(didMethod));
    } else {
      this.addResolver(didMethod, new Resolver(getUniResolver(didMethod, { ...opts })));
      this.didMethods.push(didMethod);
    }
    return this;
  }

  redirect(redirectUri: string): RPBuilder {
    this.redirectUri = redirectUri;
    return this;
  }

  requestBy(type: PassBy, referenceUri?: string): RPBuilder {
    this.requestObjectBy = {
      type,
      referenceUri,
    };
    return this;
  }

  response(responseMode: ResponseMode): RPBuilder {
    this.responseMode = responseMode;
    return this;
  }

  registrationBy(requestRegistration: RequestRegistrationOpts): RPBuilder {
    this.requestRegistration = {
      ...requestRegistration,
    };
    return this;
  }

  // Only internal | supplied supported for now
  signature(signatureType: InternalSignature | SuppliedSignature): RPBuilder {
    this.signatureType = signatureType;
    return this;
  }

  internalSignature(hexPrivateKey: string, did: string, kid?: string): RPBuilder {
    this.signature({ hexPrivateKey, did, kid });
    return this;
  }

  suppliedSignature(signature: (data: string | Uint8Array) => Promise<EcdsaSignature | string>, did: string, kid: string): RPBuilder {
    this.signature({ signature, did, kid });
    return this;
  }

  addPresentationDefinitionClaim(definitionOpt: PresentationDefinitionWithLocation): RPBuilder {
    if (!this.claims || !this.claims.presentationDefinitions) {
      this.claims = {
        presentationDefinitions: [definitionOpt],
      };
    } else {
      this.claims.presentationDefinitions.push(definitionOpt);
    }
    return this;
  }

  build(): RP {
    return new RP({ builder: this });
  }
}
