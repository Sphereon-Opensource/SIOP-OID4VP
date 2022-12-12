import { Config, getUniResolver, UniResolver } from '@sphereon/did-uni-client';
import { IPresentationDefinition } from '@sphereon/pex';
import { VerifyCallback } from '@sphereon/wellknown-dids-client';
import { Signer } from 'did-jwt';
import { Resolvable, Resolver } from 'did-resolver';

import { ClaimPayloadCommonOpts, ClaimPayloadOptsVID1 } from '../authorization-request';
import { PresentationVerificationCallback } from '../authorization-response';
import { getMethodFromDid } from '../did';
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
  ResponseType,
  RevocationVerification,
  RevocationVerificationCallback,
  SigningAlgo,
  SubjectSyntaxTypesSupportedValues,
  SuppliedSignature,
  SupportedVersion,
} from '../types';

import { RP } from './RP';

export default class Builder {
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
  claims?: ClaimPayloadCommonOpts | ClaimPayloadOptsVID1;
  checkLinkedDomain?: CheckLinkedDomain;
  verifyCallback?: VerifyCallback;
  revocationVerification?: RevocationVerification;
  revocationVerificationCallback?: RevocationVerificationCallback;
  presentationVerificationCallback?: PresentationVerificationCallback;
  supportedVersions: SupportedVersion[];

  requestPayload: Partial<RequestObjectPayload> = {};
  responseType: ResponseType;
  scope: string;
  clientId: string;

  presentationDefinition: IPresentationDefinition;

  private constructor(supportedRequestVersion?: SupportedVersion) {
    if (supportedRequestVersion) {
      this.addSupportedVersion(supportedRequestVersion);
    }
  }

  withScope(scope: string): Builder {
    this.scope = scope;
    this.requestPayload.scope = scope;
    return this;
  }

  withResponseType(responseType: ResponseType): Builder {
    this.responseType = responseType;
    this.requestPayload.response_type = responseType;
    return this;
  }

  withClientId(clientId: string): Builder {
    this.clientId = clientId;
    this.requestPayload.client_id = clientId;
    return this;
  }

  withIssuer(issuer: ResponseIss): Builder {
    this.issuer = issuer;
    this.requestPayload.iss = issuer.valueOf();
    return this;
  }

  withPresentationVerification(presentationVerificationCallback: PresentationVerificationCallback): Builder {
    this.presentationVerificationCallback = presentationVerificationCallback;
    return this;
  }

  withRevocationVerification(mode: RevocationVerification): Builder {
    this.revocationVerification = mode;
    return this;
  }

  withRevocationVerificationCallback(callback: RevocationVerificationCallback): Builder {
    this.revocationVerificationCallback = callback;
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

  withAuthorizationEndpoint(authorizationEndpoint: string): Builder {
    this.authorizationEndpoint = authorizationEndpoint;
    return this;
  }

  withCheckLinkedDomain(mode: CheckLinkedDomain): Builder {
    this.checkLinkedDomain = mode;
    return this;
  }

  addDidMethod(didMethod: string, opts?: { resolveUrl?: string; baseUrl?: string }): Builder {
    const method = didMethod.startsWith('did:') ? getMethodFromDid(didMethod) : didMethod;
    if (method === SubjectSyntaxTypesSupportedValues.DID.valueOf()) {
      opts ? this.addResolver('', new UniResolver({ ...opts } as Config)) : this.addResolver('', null);
    }
    opts ? this.addResolver(method, new Resolver(getUniResolver(method, { ...opts }))) : this.addResolver(method, null);
    return this;
  }

  withRedirectUri(redirectUri: string): Builder {
    this.redirectUri = redirectUri;
    return this;
  }

  withRequestBy(passBy: PassBy, referenceUri?: string): Builder {
    this.requestObjectBy = {
      passBy,
      referenceUri,
    };
    return this;
  }

  withResponseMode(responseMode: ResponseMode): Builder {
    this.responseMode = responseMode;
    return this;
  }

  withClientMetadata(clientMetadata: ClientMetadataOpts): Builder {
    this.requestRegistration = {
      ...clientMetadata,
    };
    return this;
  }

  // Only internal and supplied signatures supported for now
  withSignature(signatureType: InternalSignature | SuppliedSignature): Builder {
    this.signatureType = signatureType;
    return this;
  }

  withInternalSignature(hexPrivateKey: string, did: string, kid: string, alg: SigningAlgo, customJwtSigner?: Signer): Builder {
    this.withSignature({ hexPrivateKey, did, kid, alg, customJwtSigner });
    return this;
  }

  withSuppliedSignature(
    signature: (data: string | Uint8Array) => Promise<EcdsaSignature | string>,
    did: string,
    kid: string,
    alg: SigningAlgo
  ): Builder {
    this.withSignature({ signature, did, kid, alg });
    return this;
  }

  withPresentationDefinition(definitionOpt: IPresentationDefinition): Builder {
    if (this.getSupportedRequestVersion() < SupportedVersion.SIOPv2_D11) {
      if (!this.claims || !this.claims.vp_token) {
        this.claims = {
          vp_token: {
            presentation_definition: definitionOpt,
          },
        };
      }
    } else {
      this.presentationDefinition = definitionOpt;
    }
    return this;
  }

  withVerifyCallback(verifyCallback: VerifyCallback): Builder {
    this.verifyCallback = verifyCallback;
    return this;
  }

  private initSupportedVersions() {
    if (!this.supportedVersions) {
      this.supportedVersions = [];
    }
  }

  addSupportedVersion(supportedVersion: SupportedVersion): Builder {
    this.initSupportedVersions();
    if (!this.supportedVersions.includes(supportedVersion)) {
      this.supportedVersions.push(supportedVersion);
    }
    return this;
  }

  withSupportedVersions(supportedVersion: SupportedVersion[] | SupportedVersion): Builder {
    const versions = Array.isArray(supportedVersion) ? supportedVersion : [supportedVersion];
    for (const version of versions) {
      this.addSupportedVersion(version);
    }
    return this;
  }

  public getSupportedRequestVersion(): SupportedVersion | undefined {
    if (!this.supportedVersions || this.supportedVersions.length === 0) {
      return undefined;
    }
    return this.supportedVersions[0];
  }

  public static newInstance(supportedVersion?: SupportedVersion) {
    return new Builder(supportedVersion);
  }

  build(): RP {
    // We do not want others to directly use the RP class
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    return new RP({ builder: this });
  }
}
