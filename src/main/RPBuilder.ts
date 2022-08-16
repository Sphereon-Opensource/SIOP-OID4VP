import { getUniResolver } from '@sphereon/did-uni-client';
import { Resolvable, Resolver } from 'did-resolver';

import { RP } from './RP';
import { DIDJwt } from './functions';
import { EcdsaSignature } from './types/JWT.types';
import {
  ClaimOpts,
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
} from './types/SIOP.types';

export default class RPBuilder {
  authorizationEndpoint: string;
  issuer: ResponseIss;
  resolvers: Map<string, Resolvable> = new Map<string, Resolvable>();
  resolver?: Resolvable;
  requestRegistration: Partial<RequestRegistrationOpts> = {};
  redirectUri: string;
  requestObjectBy: ObjectBy;
  signatureType: InternalSignature | ExternalSignature | SuppliedSignature | NoSignature;
  responseMode?: ResponseMode;
  responseContext?: ResponseContext.RP;
  claims?: ClaimOpts;

  // claims?: ClaimPayload;

  addIssuer(issuer: ResponseIss): RPBuilder {
    this.issuer = issuer;
    return this;
  }

  defaultResolver(resolver: Resolvable): RPBuilder {
    this.resolver = resolver;
    return this;
  }

  addResolver(didMethod: string, resolver: Resolvable): RPBuilder {
    if (!this.requestRegistration.subjectSyntaxTypesSupported || !this.requestRegistration.subjectSyntaxTypesSupported.length) {
      this.requestRegistration.subjectSyntaxTypesSupported = [];
    }
    this.requestRegistration.subjectSyntaxTypesSupported.push(DIDJwt.toSIOPRegistrationDidMethod(didMethod));
    this.resolvers.set(DIDJwt.getMethodFromDid(didMethod), resolver);
    return this;
  }

  withAuthorizationEndpoint(authorizationEndpoint: string): RPBuilder {
    this.authorizationEndpoint = authorizationEndpoint;
    return this;
  }

  addDidMethod(didMethod: string, opts?: { resolveUrl?: string; baseUrl?: string }): RPBuilder {
    this.addResolver(didMethod, new Resolver(getUniResolver(DIDJwt.getMethodFromDid(didMethod), { ...opts })));
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
