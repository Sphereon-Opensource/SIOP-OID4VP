import { getUniResolver } from '@sphereon/did-uni-client';
import { Format } from '@sphereon/pex-models';
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
  ResponseType,
  Scope,
  SigningAlgo,
  SubjectType,
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
  vpFormatsSupported: Format;
  idTokenSigningAlgValuesSupported: SigningAlgo[];
  subjectSyntaxTypesSupported: string[];
  requestObjectSigningAlgValuesSupported: SigningAlgo[];
  responseTypesSupported: ResponseType[];
  scopesSupported: Scope[];
  subjectTypesSupported: SubjectType[];

  addIssuer(issuer: ResponseIss): RPBuilder {
    this.issuer = issuer;
    return this;
  }

  addVpFormatsSupported(credentialType: Format): RPBuilder {
    this.vpFormatsSupported = credentialType;
    return this;
  }

  defaultResolver(resolver: Resolvable): RPBuilder {
    this.resolver = resolver;
    return this;
  }

  addResolver(didMethod: string, resolver: Resolvable): RPBuilder {
    if (!this.subjectSyntaxTypesSupported || !this.subjectSyntaxTypesSupported.length) {
      this.subjectSyntaxTypesSupported = [];
    }
    this.subjectSyntaxTypesSupported.push(DIDJwt.toSIOPRegistrationDidMethod(didMethod));
    this.resolvers.set(DIDJwt.getMethodFromDid(didMethod), resolver);
    return this;
  }

  addIdTokenSigningAlgValuesSupported(signingAlgo: SigningAlgo | SigningAlgo[]): RPBuilder {
    if (!this.idTokenSigningAlgValuesSupported || !this.idTokenSigningAlgValuesSupported.length) {
      this.idTokenSigningAlgValuesSupported = [];
    }
    if (Array.isArray(signingAlgo)) {
      this.idTokenSigningAlgValuesSupported.push(...signingAlgo);
    } else {
      this.idTokenSigningAlgValuesSupported.push(signingAlgo);
    }
    return this;
  }

  withAuthorizationEndpoint(authorizationEndpoint: string): RPBuilder {
    this.authorizationEndpoint = authorizationEndpoint;
    return this;
  }

  addRequestObjectSigningAlgValuesSupported(signingAlgs: SigningAlgo | SigningAlgo[]): RPBuilder {
    if (!this.requestObjectSigningAlgValuesSupported || !this.requestObjectSigningAlgValuesSupported.length) {
      this.requestObjectSigningAlgValuesSupported = [];
    }
    if (Array.isArray(signingAlgs)) {
      this.requestObjectSigningAlgValuesSupported.push(...signingAlgs);
    } else {
      this.requestObjectSigningAlgValuesSupported.push(signingAlgs);
    }
    return this;
  }

  addResponseTypesSupported(responseType: ResponseType | ResponseType[]): RPBuilder {
    if (!this.responseTypesSupported || !this.responseTypesSupported.length) {
      this.responseTypesSupported = [];
    }
    if (Array.isArray(responseType)) {
      this.responseTypesSupported.push(...responseType);
    } else {
      this.responseTypesSupported.push(responseType);
    }
    return this;
  }

  addScopesSupported(scopes: Scope | Scope[]): RPBuilder {
    if (!this.scopesSupported || !this.scopesSupported.length) {
      this.scopesSupported = [];
    }
    if (Array.isArray(scopes)) {
      this.scopesSupported.push(...scopes);
    } else {
      this.scopesSupported.push(scopes);
    }
    return this;
  }

  addSubjectTypesSupported(subjectTypes: SubjectType | SubjectType[]): RPBuilder {
    if (!this.subjectTypesSupported || !this.subjectTypesSupported.length) {
      this.subjectTypesSupported = [];
    }
    if (Array.isArray(subjectTypes)) {
      this.subjectTypesSupported.push(...subjectTypes);
    } else {
      this.subjectTypesSupported.push(subjectTypes);
    }
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

  registrationBy(registrationBy: PassBy, refUri?: string): RPBuilder {
    this.requestRegistration = {
      registrationBy: {
        type: registrationBy,
        referenceUri: refUri,
      },
    };
    /*if (refUri) {
          this.requestRegistration.registrationBy.referenceUri = refUri;
        }*/
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
    this.requestRegistration.requestObjectSigningAlgValuesSupported = this.requestObjectSigningAlgValuesSupported;
    this.requestRegistration.authorizationEndpoint = this.authorizationEndpoint;
    this.requestRegistration.subjectSyntaxTypesSupported = this.subjectSyntaxTypesSupported;
    this.requestRegistration.idTokenSigningAlgValuesSupported = this.idTokenSigningAlgValuesSupported;
    this.requestRegistration.vpFormatsSupported = this.vpFormatsSupported;
    this.requestRegistration.responseTypesSupported = this.responseTypesSupported;
    this.requestRegistration.scopesSupported = this.scopesSupported;
    this.requestRegistration.subjectTypesSupported = this.subjectTypesSupported;
    return new RP({ builder: this });
  }
}
