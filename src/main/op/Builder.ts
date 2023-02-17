import EventEmitter from 'events';

import { Config, getUniResolver, UniResolver } from '@sphereon/did-uni-client';
import { VerifyCallback } from '@sphereon/wellknown-dids-client';
import { Signer } from 'did-jwt';
import { Resolvable, Resolver } from 'did-resolver';

import { PropertyTargets } from '../authorization-request';
import { PresentationSignCallback } from '../authorization-response';
import { getMethodFromDid } from '../did';
import {
  CheckLinkedDomain,
  EcdsaSignature,
  ExternalSignature,
  InternalSignature,
  ResponseIss,
  ResponseMode,
  ResponseRegistrationOpts,
  SigningAlgo,
  SubjectSyntaxTypesSupportedValues,
  SuppliedSignature,
  SupportedVersion,
} from '../types';

import { OP } from './OP';

export class Builder {
  expiresIn?: number;
  issuer: ResponseIss;
  resolvers: Map<string, Resolvable> = new Map<string, Resolvable>();
  responseMode?: ResponseMode;
  responseRegistration: Partial<ResponseRegistrationOpts> = {};
  customResolver?: Resolvable;
  signatureType: InternalSignature | ExternalSignature | SuppliedSignature;
  checkLinkedDomain?: CheckLinkedDomain;
  verifyCallback?: VerifyCallback;
  presentationSignCallback?: PresentationSignCallback;
  supportedVersions: SupportedVersion[];
  eventEmitter?: EventEmitter;

  addDidMethod(didMethod: string, opts?: { resolveUrl?: string; baseUrl?: string }): Builder {
    const method = didMethod.startsWith('did:') ? getMethodFromDid(didMethod) : didMethod;
    if (method === SubjectSyntaxTypesSupportedValues.DID.valueOf()) {
      opts ? this.addResolver('', new UniResolver({ ...opts } as Config)) : this.addResolver('', null);
    }
    opts ? this.addResolver(method, new Resolver(getUniResolver(method, { ...opts }))) : this.addResolver(method, null);
    return this;
  }

  addIssuer(issuer: ResponseIss): Builder {
    this.issuer = issuer;
    return this;
  }

  withCustomResolver(resolver: Resolvable): Builder {
    this.customResolver = resolver;
    return this;
  }

  addResolver(didMethod: string, resolver: Resolvable): Builder {
    const qualifiedDidMethod = didMethod.startsWith('did:') ? getMethodFromDid(didMethod) : didMethod;
    this.resolvers.set(qualifiedDidMethod, resolver);
    return this;
  }

  /*withDid(did: string): OPBuilder {
    this.did = did;
    return this;
  }
*/
  withExpiresIn(expiresIn: number): Builder {
    this.expiresIn = expiresIn;
    return this;
  }

  withCheckLinkedDomain(mode: CheckLinkedDomain): Builder {
    this.checkLinkedDomain = mode;
    return this;
  }

  response(responseMode: ResponseMode): Builder {
    this.responseMode = responseMode;
    return this;
  }

  registration(responseRegistration: ResponseRegistrationOpts, targets?: PropertyTargets): Builder {
    this.responseRegistration = {
      targets,
      ...responseRegistration,
    };
    return this;
  }

  /*//TODO registration object creation
  authorizationEndpoint?: Schema.OPENID | string;
  scopesSupported?: Scope[] | Scope;
  subjectTypesSupported?: SubjectType[] | SubjectType;
  idTokenSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo;
  requestObjectSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo;
*/

  // Only internal and supplied signatures supported for now
  signature(signatureType: InternalSignature | SuppliedSignature): Builder {
    this.signatureType = signatureType;
    return this;
  }

  internalSignature(hexPrivateKey: string, did: string, kid: string, alg: SigningAlgo, customJwtSigner?: Signer): Builder {
    this.signature({ hexPrivateKey, did, kid, alg, customJwtSigner });
    return this;
  }

  suppliedSignature(signature: (data: string | Uint8Array) => Promise<EcdsaSignature | string>, did: string, kid: string, alg: SigningAlgo): Builder {
    this.signature({ signature, did, kid, alg });
    return this;
  }

  addVerifyCallback(verifyCallback: VerifyCallback) {
    this.verifyCallback = verifyCallback;
    return this;
  }

  withSupportedVersions(supportedVersions: SupportedVersion[] | SupportedVersion | string[] | string): Builder {
    const versions = Array.isArray(supportedVersions) ? supportedVersions : [supportedVersions];
    for (const version of versions) {
      this.addSupportedVersion(version);
    }
    return this;
  }

  addSupportedVersion(supportedVersion: string | SupportedVersion): Builder {
    if (!this.supportedVersions) {
      this.supportedVersions = [];
    }
    if (typeof supportedVersion === 'string') {
      this.supportedVersions.push(SupportedVersion[supportedVersion]);
    } else {
      this.supportedVersions.push(supportedVersion);
    }
    return this;
  }

  withPresentationSignCallback(presentationSignCallback: PresentationSignCallback) {
    this.presentationSignCallback = presentationSignCallback;
    return this;
  }

  withEventEmitter(eventEmitter: EventEmitter): Builder {
    this.eventEmitter = eventEmitter;
    return this;
  }

  build(): OP {
    // this.responseRegistration.didMethodsSupported = this.didMethods;
    // this.responseRegistration.subjectIdentifiersSupported = this.subjectIdentifierTypes;
    // this.responseRegistration.credentialFormatsSupported = this.credentialFormats;
    // We ignore the private visibility, as we don't want others to use the OP directly
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    return new OP({ builder: this });
  }
}
