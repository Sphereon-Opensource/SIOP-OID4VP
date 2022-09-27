import { Config, getUniResolver, UniResolver } from '@sphereon/did-uni-client';
import { VerifyCallback } from '@sphereon/wellknown-dids-client';
import { Resolvable, Resolver } from 'did-resolver';

import { OP } from './OP';
import { getMethodFromDid } from './functions';
import {
  CheckLinkedDomain,
  EcdsaSignature,
  ExternalSignature,
  InternalSignature,
  Profile,
  ResponseIss,
  ResponseMode,
  ResponseRegistrationOpts,
  SubjectSyntaxTypesSupportedValues,
  SuppliedSignature,
} from './types';

export default class OPBuilder {
  expiresIn?: number;
  issuer: ResponseIss;
  resolvers: Map<string, Resolvable> = new Map<string, Resolvable>();
  responseMode?: ResponseMode;
  responseRegistration: Partial<ResponseRegistrationOpts> = {};
  // did: string;
  // vp?: VerifiablePresentation;
  customResolver?: Resolvable;
  signatureType: InternalSignature | ExternalSignature | SuppliedSignature;
  checkLinkedDomain?: CheckLinkedDomain;
  verifyCallback?: VerifyCallback;
  profiles: Array<Profile>;

  addDidMethod(didMethod: string, opts?: { resolveUrl?: string; baseUrl?: string }): OPBuilder {
    const method = didMethod.startsWith('did:') ? getMethodFromDid(didMethod) : didMethod;
    if (method === SubjectSyntaxTypesSupportedValues.DID.valueOf()) {
      opts ? this.addResolver('', new UniResolver({ ...opts } as Config)) : this.addResolver('', null);
    }
    opts ? this.addResolver(method, new Resolver(getUniResolver(method, { ...opts }))) : this.addResolver(method, null);
    return this;
  }

  addIssuer(issuer: ResponseIss): OPBuilder {
    this.issuer = issuer;
    return this;
  }

  withCustomResolver(resolver: Resolvable): OPBuilder {
    this.customResolver = resolver;
    return this;
  }

  addResolver(didMethod: string, resolver: Resolvable): OPBuilder {
    const qualifiedDidMethod = didMethod.startsWith('did:') ? getMethodFromDid(didMethod) : didMethod;
    this.resolvers.set(qualifiedDidMethod, resolver);
    return this;
  }

  /*withDid(did: string): OPBuilder {
    this.did = did;
    return this;
  }
*/
  withExpiresIn(expiresIn: number): OPBuilder {
    this.expiresIn = expiresIn;
    return this;
  }

  withCheckLinkedDomain(mode: CheckLinkedDomain): OPBuilder {
    this.checkLinkedDomain = mode;
    return this;
  }

  response(responseMode: ResponseMode): OPBuilder {
    this.responseMode = responseMode;
    return this;
  }

  registrationBy(responseRegistration: ResponseRegistrationOpts): OPBuilder {
    this.responseRegistration = {
      ...responseRegistration,
    };
    return this;
  }

  /*//TODO registration object creation
  authorizationEndpoint?: Schema.OPENID | string;
  scopesSupported?: Scope[] | Scope;
  subjectTypesSupported?: SubjectType[] | SubjectType;
  idTokenSigningAlgValuesSupported?: KeyAlgo[] | KeyAlgo;
  requestObjectSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo;
*/
  // Only internal | supplied supported for now
  signature(signatureType: InternalSignature | SuppliedSignature): OPBuilder {
    this.signatureType = signatureType;
    return this;
  }

  internalSignature(hexPrivateKey: string, did: string, kid: string): OPBuilder {
    this.signature({ hexPrivateKey, did, kid });
    return this;
  }

  suppliedSignature(signature: (data: string | Uint8Array) => Promise<EcdsaSignature | string>, did: string, kid: string): OPBuilder {
    this.signature({ signature, did, kid });
    return this;
  }

  addVerifyCallback(verifyCallback: VerifyCallback) {
    this.verifyCallback = verifyCallback;
    return this;
  }

  private initProfiles() {
    if (!this.profiles) {
      this.profiles = [];
    }
  }

  withProfileStr(profileStr: string): OPBuilder {
    this.initProfiles();
    this.profiles.push(Profile[profileStr]);
    return this;
  }

  addProfile(profile: Profile): OPBuilder {
    this.initProfiles();
    this.profiles.push(profile);
    return this;
  }

  withProfiles(profiles: Array<Profile>): OPBuilder {
    this.profiles = profiles;
    return this;
  }

  build(): OP {
    // this.responseRegistration.didMethodsSupported = this.didMethods;
    // this.responseRegistration.subjectIdentifiersSupported = this.subjectIdentifierTypes;
    // this.responseRegistration.credentialFormatsSupported = this.credentialFormats;
    return new OP({ builder: this });
  }
}
