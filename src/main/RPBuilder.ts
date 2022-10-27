import { Config, getUniResolver, UniResolver } from '@sphereon/did-uni-client';
import { IPresentationDefinition } from '@sphereon/pex';
import { VerifyCallback } from '@sphereon/wellknown-dids-client';
import { Resolvable, Resolver } from 'did-resolver';

import { RP } from './RP';
import { getMethodFromDid } from './functions';
import {
  CheckLinkedDomain,
  ClaimOpts,
  EcdsaSignature,
  ExternalSignature,
  IdToken,
  InternalSignature,
  NoSignature,
  ObjectBy,
  PassBy,
  PresentationVerificationCallback,
  RequestRegistrationOpts,
  ResponseContext,
  ResponseIss,
  ResponseMode,
  RevocationVerification,
  RevocationVerificationCallback,
  SubjectSyntaxTypesSupportedValues,
  SuppliedSignature,
  SupportedVersion,
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
  presentationVerificationCallback?: PresentationVerificationCallback;
  supportedVersions: Array<SupportedVersion>;
  scope: string;
  responseType: string;
  clientId: string;

  addScope(scope: string): RPBuilder {
    this.scope = scope;
    return this;
  }

  addResponseType(responseType: string): RPBuilder {
    this.responseType = responseType;
    return this;
  }

  addClientId(clientId: string): RPBuilder {
    this.clientId = clientId;
    return this;
  }

  addIssuer(issuer: ResponseIss): RPBuilder {
    this.issuer = issuer;
    return this;
  }

  withPresentationVerification(presentationVerificationCallback: PresentationVerificationCallback): RPBuilder {
    this.presentationVerificationCallback = presentationVerificationCallback;
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

  addClaims(definitionOpt: IPresentationDefinition, idToken?: IdToken): RPBuilder {
    if (!this.claims || !this.claims.vpToken) {
      this.claims = {
        idToken: idToken || {},
        vpToken: {
          presentationDefinition: definitionOpt,
        },
      };
    }
    return this;
  }

  addVerifyCallback(verifyCallback: VerifyCallback): RPBuilder {
    this.verifyCallback = verifyCallback;
    return this;
  }

  private initSupportedVersions() {
    if (!this.supportedVersions) {
      this.supportedVersions = [];
    }
  }

  withSupportedVersions(supportedVersions: Array<string | SupportedVersion>): RPBuilder {
    this.initSupportedVersions();
    for (const supportedVersion of supportedVersions) {
      this.addSupportedVersion(supportedVersion);
    }
    return this;
  }

  addSupportedVersion(supportedVersion: string | SupportedVersion): RPBuilder {
    this.initSupportedVersions();
    if (typeof supportedVersion === 'string') {
      this.supportedVersions.push(SupportedVersion[supportedVersion]);
    } else if (Array.isArray(supportedVersion)) {
      this.supportedVersions.push(supportedVersion as SupportedVersion);
    }
    return this;
  }

  build(): RP {
    return new RP({ builder: this });
  }
}
