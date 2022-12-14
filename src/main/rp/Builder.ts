import { Config, getUniResolver, UniResolver } from '@sphereon/did-uni-client';
import { IPresentationDefinition } from '@sphereon/pex';
import { VerifyCallback } from '@sphereon/wellknown-dids-client';
import { Signer } from 'did-jwt';
import { Resolvable, Resolver } from 'did-resolver';

import { PropertyTarget, PropertyTargets } from '../authorization-request';
import { PresentationVerificationCallback } from '../authorization-response';
import { getMethodFromDid } from '../did';
import {
  AuthorizationRequestPayload,
  CheckLinkedDomain,
  ClientMetadataOpts,
  EcdsaSignature,
  ExternalSignature,
  InternalSignature,
  NoSignature,
  ObjectBy,
  PassBy,
  RequestObjectPayload,
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

import { assignIfAuth, assignIfRequestObject, isTargetOrNoTargets } from './Opts';
import { RP } from './RP';

export default class Builder {
  resolvers: Map<string, Resolvable> = new Map<string, Resolvable>();
  customResolver?: Resolvable;
  requestObjectBy: ObjectBy;
  signatureType: InternalSignature | ExternalSignature | SuppliedSignature | NoSignature;
  checkLinkedDomain?: CheckLinkedDomain;
  verifyCallback?: VerifyCallback;
  revocationVerification?: RevocationVerification;
  revocationVerificationCallback?: RevocationVerificationCallback;
  presentationVerificationCallback?: PresentationVerificationCallback;
  supportedVersions: SupportedVersion[];
  authorizationRequestPayload: Partial<AuthorizationRequestPayload> = {};
  requestObjectPayload: Partial<RequestObjectPayload> = {};

  clientMetadata?: Partial<ClientMetadataOpts> = {};
  /*  response_mode?: ResponseMode;
    claims?: ClaimPayloadCommonOpts | ClaimPayloadOptsVID1;
    redirect_uri: string;
    response_type: ResponseType;
    scope: string;
    client_id: string;
    authorization_endpoint: string;
    iss: ResponseIss;
  presentationDefinition: IPresentationDefinition;
*/
  private constructor(supportedRequestVersion?: SupportedVersion) {
    if (supportedRequestVersion) {
      this.addSupportedVersion(supportedRequestVersion);
    }
  }

  withScope(scope: string, targets?: PropertyTargets): Builder {
    this.authorizationRequestPayload.scope = assignIfAuth({ propertyValue: scope, targets });
    this.requestObjectPayload.scope = assignIfRequestObject({ propertyValue: scope, targets });
    return this;
  }

  withResponseType(responseType: ResponseType, targets?: PropertyTargets): Builder {
    this.authorizationRequestPayload.response_type = assignIfAuth({ propertyValue: responseType, targets });
    this.requestObjectPayload.response_type = assignIfRequestObject({ propertyValue: responseType, targets });
    return this;
  }

  withClientId(clientId: string, targets?: PropertyTargets): Builder {
    this.authorizationRequestPayload.client_id = assignIfAuth({ propertyValue: clientId, targets });
    this.requestObjectPayload.client_id = assignIfRequestObject({ propertyValue: clientId, targets });
    return this;
  }

  withIssuer(issuer: ResponseIss, targets?: PropertyTargets): Builder {
    this.authorizationRequestPayload.iss = assignIfAuth({ propertyValue: issuer, targets });
    this.requestObjectPayload.iss = assignIfRequestObject({ propertyValue: issuer, targets });
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

  withAuthorizationEndpoint(authorizationEndpoint: string, targets?: PropertyTargets): Builder {
    this.authorizationRequestPayload.authorization_endpoint = assignIfAuth({
      propertyValue: authorizationEndpoint,
      targets,
    });
    this.requestObjectPayload.authorization_endpoint = assignIfRequestObject({
      propertyValue: authorizationEndpoint,
      targets,
    });
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

  withRedirectUri(redirectUri: string, targets?: PropertyTargets): Builder {
    this.authorizationRequestPayload.redirect_uri = assignIfAuth({ propertyValue: redirectUri, targets });
    this.requestObjectPayload.redirect_uri = assignIfRequestObject({ propertyValue: redirectUri, targets });
    return this;
  }

  withRequestBy(passBy: PassBy, referenceUri?: string): Builder {
    this.requestObjectBy = {
      passBy,
      referenceUri,
    };
    return this;
  }

  withResponseMode(responseMode: ResponseMode, targets?: PropertyTargets): Builder {
    this.authorizationRequestPayload.response_mode = assignIfAuth({ propertyValue: responseMode, targets });
    this.requestObjectPayload.response_mode = assignIfRequestObject({ propertyValue: responseMode, targets });
    return this;
  }

  withClientMetadata(clientMetadata: ClientMetadataOpts, targets?: PropertyTargets): Builder {
    if (this.getSupportedRequestVersion() < SupportedVersion.SIOPv2_D11) {
      this.authorizationRequestPayload.request_registration = assignIfAuth({
        propertyValue: clientMetadata,
        targets,
      });
      this.requestObjectPayload.request_registration = assignIfRequestObject({
        propertyValue: clientMetadata,
        targets,
      });
    } else {
      this.authorizationRequestPayload.client_metadata = assignIfAuth({
        propertyValue: clientMetadata,
        targets,
      });
      this.requestObjectPayload.client_metadata = assignIfRequestObject({
        propertyValue: clientMetadata,
        targets,
      });
    }
    //fixme: Add URL
    this.clientMetadata = clientMetadata;
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

  withPresentationDefinition(definition: IPresentationDefinition, definitionUri?: string, targets?: PropertyTargets): Builder {
    const definitionProperties = {
      presentation_definition: definition,
      presentation_definition_uri: definitionUri,
    };
    if (this.getSupportedRequestVersion() < SupportedVersion.SIOPv2_D11) {
      const vp_token = { ...definitionProperties };
      if (isTargetOrNoTargets(PropertyTarget.AUTHORIZATION_REQUEST, targets)) {
        this.authorizationRequestPayload.claims = {
          ...(this.authorizationRequestPayload.claims ? this.authorizationRequestPayload.claims : {}),
          vp_token,
        };
      }
      if (isTargetOrNoTargets(PropertyTarget.REQUEST_OBJECT, targets)) {
        this.requestObjectPayload.claims = {
          ...(this.requestObjectPayload.claims ? this.requestObjectPayload.claims : {}),
          vp_token,
        };
      }
    } else {
      this.authorizationRequestPayload.presentation_definition = assignIfAuth({ propertyValue: definition, targets });
      this.authorizationRequestPayload.presentation_definition_uri = assignIfAuth({
        propertyValue: definitionUri,
        targets,
      });
      this.requestObjectPayload.presentation_definition = assignIfRequestObject({ propertyValue: definition, targets });
      this.requestObjectPayload.presentation_definition_uri = assignIfRequestObject({
        propertyValue: definitionUri,
        targets,
      });
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

  public getSupportedRequestVersion(requireVersion?: boolean): SupportedVersion | undefined {
    if (!this.supportedVersions || this.supportedVersions.length === 0) {
      if (requireVersion !== false) {
        throw Error('No supported version supplied/available');
      }
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
