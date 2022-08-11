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
  SigningAlgo,
  SubjectType,
  SuppliedSignature,
} from './types/SIOP.types';

export default class OPBuilder {
  expiresIn?: number;
  idTokenSigningAlgValuesSupported: SigningAlgo[];
  issuer: ResponseIss;
  resolvers: Map<string, Resolvable> = new Map<string, Resolvable>();
  responseMode?: ResponseMode;
  responseRegistration: ResponseRegistrationOpts;
  responseTypesSupported: ResponseType[] | ResponseType;
  // did: string;
  // vp?: VerifiablePresentation;
  resolver?: Resolvable;
  signatureType: InternalSignature | ExternalSignature | SuppliedSignature;
  subjectSyntaxTypesSupported: string[] = [];
  vpFormats: Format;
  subjectTypesSupported: SubjectType[];

  addVpFormatsSupported(credentialType: Format): OPBuilder {
    this.vpFormats = credentialType;
    return this;
  }

  addResponseTypesSupported(responseTypesSupported: ResponseType[] | ResponseType): OPBuilder {
    this.responseTypesSupported = responseTypesSupported;
    return this;
  }

  addIssuer(issuer: ResponseIss): OPBuilder {
    this.issuer = issuer;
    return this;
  }

  defaultResolver(resolver: Resolvable): OPBuilder {
    this.resolver = resolver;
    return this;
  }

  addResolver(didMethod: string, resolver: Resolvable): OPBuilder {
    this.subjectSyntaxTypesSupported.push(DIDJwt.toSIOPRegistrationDidMethod(didMethod));
    this.resolvers.set(DIDJwt.getMethodFromDid(didMethod), resolver);
    return this;
  }

  addDidMethod(didMethod: string, opts?: { resolveUrl?: string; baseUrl?: string }): OPBuilder {
    this.addResolver(didMethod, new Resolver(getUniResolver(DIDJwt.getMethodFromDid(didMethod), { ...opts })));
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

  response(responseMode: ResponseMode): OPBuilder {
    this.responseMode = responseMode;
    return this;
  }

  //TODO: fill up with the actual values
  registrationBy(registrationBy: PassBy, refUri?: string): OPBuilder {
    this.responseRegistration = {
      vpFormats: this.vpFormats,
      issuer: undefined,
      responseTypesSupported: undefined,
      subjectSyntaxTypesSupported: [],
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
