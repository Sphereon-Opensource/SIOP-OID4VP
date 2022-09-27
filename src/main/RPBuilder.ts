import { Config, getUniResolver, UniResolver } from '@sphereon/did-uni-client';
import { VerifyCallback } from '@sphereon/wellknown-dids-client';
import { Resolvable, Resolver } from 'did-resolver';

import { RP } from './RP';
import { getMethodFromDid } from './functions';
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
  Profile,
  RequestRegistrationOpts,
  ResponseContext,
  ResponseIss,
  ResponseMode,
  RevocationVerification,
  RevocationVerificationCallback,
  SubjectSyntaxTypesSupportedValues,
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
  // claims?: ClaimPayload;
  verifyCallback?: VerifyCallback;
  revocationVerification?: RevocationVerification;
  revocationVerificationCallback?: RevocationVerificationCallback;
  profiles: Array<Profile>;

  addIssuer(issuer: ResponseIss): RPBuilder {
    this.issuer = issuer;
    return this;
  }

  withRevocationVerification(mode: RevocationVerification): RPBuilder {
    this.revocationVerification = mode;
    return this;
  }

  withRevocationVerificationCallback(callback: RevocationVerificationCallback): RPBuilder {
    this.revocationVerificationCallback = callback;
    return this;
  }

  withCustomResolver(resolver: Resolvable): RPBuilder {
    this.customResolver = resolver;
    return this;
  }

  addResolver(didMethod: string, resolver: Resolvable): RPBuilder {
    const qualifiedDidMethod = didMethod.startsWith('did:') ? getMethodFromDid(didMethod) : didMethod;
    this.resolvers.set(qualifiedDidMethod, resolver);
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
    const method = didMethod.startsWith('did:') ? getMethodFromDid(didMethod) : didMethod;
    if (method === SubjectSyntaxTypesSupportedValues.DID.valueOf()) {
      opts ? this.addResolver('', new UniResolver({ ...opts } as Config)) : this.addResolver('', null);
    }
    opts ? this.addResolver(method, new Resolver(getUniResolver(method, { ...opts }))) : this.addResolver(method, null);
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

  addVerifyCallback(verifyCallback: VerifyCallback): RPBuilder {
    this.verifyCallback = verifyCallback;
    return this;
  }
  private initProfiles() {
    if (!this.profiles) {
      this.profiles = [];
    }
  }

  withProfileStr(profileStr: string): RPBuilder {
    this.initProfiles();
    this.profiles.push(Profile[profileStr]);
    return this;
  }

  addProfile(profile: Profile): RPBuilder {
    this.initProfiles();
    this.profiles.push(profile);
    return this;
  }

  withProfiles(profiles: Array<Profile>): RPBuilder {
    this.profiles = profiles;
    return this;
  }

  build(): RP {
    return new RP({ builder: this });
  }
}
