import { Config, getUniResolver, UniResolver } from '@sphereon/did-uni-client';
import { IPresentationDefinition } from '@sphereon/pex';
import { VerifyCallback } from '@sphereon/wellknown-dids-client';
import { Resolvable, Resolver } from 'did-resolver';

import { RP } from './RP';
import { ClaimOpts, PresentationVerificationCallback } from './authorization-response';
import { getMethodFromDid } from './functions';
import {
  CheckLinkedDomain,
  ClientMetadataOpts,
  EcdsaSignature,
  ExternalSignature,
  InternalSignature,
  NoSignature,
  ObjectBy,
  PassBy,
  RequestObjectPayload,
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
  requestRegistration: Partial<ClientMetadataOpts> = {};
  redirectUri: string;
  requestObjectBy: ObjectBy;
  signatureType: InternalSignature | ExternalSignature | SuppliedSignature | NoSignature;
  responseMode?: ResponseMode;
  responseContext?: ResponseContext.RP;
  claims?: ClaimOpts;
  checkLinkedDomain?: CheckLinkedDomain;
  verifyCallback?: VerifyCallback;
  revocationVerification?: RevocationVerification;
  revocationVerificationCallback?: RevocationVerificationCallback;
  presentationVerificationCallback?: PresentationVerificationCallback;
  supportedVersions: SupportedVersion[];

  requestPayload: RequestObjectPayload = {};
  responseType: string;
  scope: string;
  clientId: string;

  withScope(scope: string): RPBuilder {
    this.scope = scope;
    this.requestPayload.scope = scope;
    return this;
  }

  withResponseType(responseType: string): RPBuilder {
    this.responseType = responseType;
    this.requestPayload.response_type = responseType;
    return this;
  }

  withClientId(clientId: string): RPBuilder {
    this.clientId = clientId;
    this.requestPayload.client_id = clientId;
    return this;
  }

  withIssuer(issuer: ResponseIss): RPBuilder {
    this.issuer = issuer;
    this.requestPayload.iss = issuer.valueOf();
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

  withRedirectUri(redirectUri: string): RPBuilder {
    this.redirectUri = redirectUri;
    return this;
  }

  withRequestBy(type: PassBy, referenceUri?: string): RPBuilder {
    this.requestObjectBy = {
      type,
      referenceUri,
    };
    return this;
  }

  withResponseMode(responseMode: ResponseMode): RPBuilder {
    this.responseMode = responseMode;
    return this;
  }

  withRegistrationBy(requestRegistration: ClientMetadataOpts): RPBuilder {
    this.requestRegistration = {
      ...requestRegistration,
    };
    return this;
  }

  // Only internal | supplied supported for now
  withSignature(signatureType: InternalSignature | SuppliedSignature): RPBuilder {
    this.signatureType = signatureType;
    return this;
  }

  withInternalSignature(hexPrivateKey: string, did: string, kid?: string): RPBuilder {
    this.withSignature({ hexPrivateKey, did, kid });
    return this;
  }

  withSuppliedSignature(signature: (data: string | Uint8Array) => Promise<EcdsaSignature | string>, did: string, kid: string): RPBuilder {
    this.withSignature({ signature, did, kid });
    return this;
  }

  addPresentationDefinitionClaim(definitionOpt: IPresentationDefinition): RPBuilder {
    if (!this.claims || !this.claims.vpToken) {
      this.claims = {
        vpToken: {
          presentationDefinition: definitionOpt,
        },
      };
    }
    return this;
  }

  withVerifyCallback(verifyCallback: VerifyCallback): RPBuilder {
    this.verifyCallback = verifyCallback;
    return this;
  }

  private initSupportedVersions() {
    if (!this.supportedVersions) {
      this.supportedVersions = [];
    }
  }

  withSupportedVersions(supportedVersion: SupportedVersion[] | SupportedVersion): RPBuilder {
    this.initSupportedVersions();
    if (Array.isArray(supportedVersion)) {
      this.supportedVersions.push(...supportedVersion);
    } else {
      this.supportedVersions.push(supportedVersion);
    }
    return this;
  }

  build(): RP {
    return new RP({ builder: this });
  }
}
