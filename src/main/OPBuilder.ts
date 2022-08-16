import { getUniResolver } from '@sphereon/did-uni-client';
import { Format } from '@sphereon/pex-models';
import { Resolvable, Resolver } from 'did-resolver';

import { OP } from './OP';
import { DIDJwt } from './functions';
import { EcdsaSignature } from './types/JWT.types';
import {
  ExternalSignature,
  InternalSignature,
  PassBy,
  ResponseIss,
  ResponseMode,
  ResponseRegistrationOpts,
  ResponseType,
  Schema,
  Scope,
  SigningAlgo,
  SubjectType,
  SuppliedSignature,
} from './types/SIOP.types';

export default class OPBuilder {
  authorizationEndpoint: Schema.OPENID | string;
  expiresIn?: number;
  idTokenSigningAlgValuesSupported: SigningAlgo[];
  issuer: ResponseIss;
  resolvers: Map<string, Resolvable> = new Map<string, Resolvable>();
  responseMode?: ResponseMode;
  responseRegistration: ResponseRegistrationOpts;
  responseTypesSupported: ResponseType[];
  // did: string;
  // vp?: VerifiablePresentation;
  resolver?: Resolvable;
  scopesSupported: Scope[];
  signatureType: InternalSignature | ExternalSignature | SuppliedSignature;
  subjectSyntaxTypesSupported: string[];
  subjectTypesSupported: SubjectType[];
  vpFormats: Format;

  addDidMethod(didMethod: string, opts?: { resolveUrl?: string; baseUrl?: string }): OPBuilder {
    this.addResolver(didMethod, new Resolver(getUniResolver(DIDJwt.getMethodFromDid(didMethod), { ...opts })));
    return this;
  }

  addIssuer(issuer: ResponseIss): OPBuilder {
    this.issuer = issuer;
    return this;
  }

  addIdTokenSigningAlgValuesSupported(idTokenSigningAlgValues: SigningAlgo | SigningAlgo[]): OPBuilder {
    if (!this.idTokenSigningAlgValuesSupported || !this.idTokenSigningAlgValuesSupported.length) {
      this.idTokenSigningAlgValuesSupported = [];
    }
    if (Array.isArray(idTokenSigningAlgValues)) {
      this.idTokenSigningAlgValuesSupported.push(...idTokenSigningAlgValues);
    } else {
      this.idTokenSigningAlgValuesSupported.push(idTokenSigningAlgValues);
    }
    return this;
  }

  defaultResolver(resolver: Resolvable): OPBuilder {
    this.resolver = resolver;
    return this;
  }

  addResolver(didMethod: string, resolver: Resolvable): OPBuilder {
    if (!this.subjectSyntaxTypesSupported || !this.subjectSyntaxTypesSupported.length) {
      this.subjectSyntaxTypesSupported = [];
    }
    this.subjectSyntaxTypesSupported.push(DIDJwt.toSIOPRegistrationDidMethod(didMethod));
    this.resolvers.set(DIDJwt.getMethodFromDid(didMethod), resolver);
    return this;
  }

  addVpFormatsSupported(credentialType: Format): OPBuilder {
    this.vpFormats = credentialType;
    return this;
  }

  addScopesSupported(scopes: Scope | Scope[]): OPBuilder {
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

  addSubjectTypesSupported(subjectTypes: SubjectType[] | SubjectType): OPBuilder {
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

  addResponseTypesSupported(responseTypes: ResponseType[] | ResponseType): OPBuilder {
    if (!this.responseTypesSupported || !this.responseTypesSupported.length) {
      this.responseTypesSupported = [];
    }
    if (Array.isArray(responseTypes)) {
      this.responseTypesSupported.push(...responseTypes);
    } else {
      this.responseTypesSupported.push(responseTypes);
    }
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

  withAuthorizationEndpoint(endpoint: string): OPBuilder {
    this.authorizationEndpoint = endpoint;
    return this;
  }

  response(responseMode: ResponseMode): OPBuilder {
    this.responseMode = responseMode;
    return this;
  }

  registrationBy(registrationBy: PassBy, refUri?: string): OPBuilder {
    this.responseRegistration = {
      authorizationEndpoint: this.authorizationEndpoint,
      vpFormats: this.vpFormats,
      issuer: this.issuer,
      responseTypesSupported: this.responseTypesSupported,
      subjectSyntaxTypesSupported: this.subjectSyntaxTypesSupported,
      registrationBy: {
        type: registrationBy,
      },
    };
    if (refUri) {
      this.responseRegistration.registrationBy.referenceUri = refUri;
    }
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

  build(): OP {
    // this.responseRegistration.didMethodsSupported = this.didMethods;
    // this.responseRegistration.subjectIdentifiersSupported = this.subjectIdentifierTypes;
    // this.responseRegistration.credentialFormatsSupported = this.credentialFormats;
    return new OP({ builder: this });
  }
}
