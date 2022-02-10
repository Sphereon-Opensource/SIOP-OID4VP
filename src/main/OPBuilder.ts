import { getUniResolver } from '@sphereon/did-uni-client';
import { EcdsaSignature } from 'did-jwt/lib/util';
import { Resolvable, Resolver } from 'did-resolver';

import { OP } from './OP';
import { DIDJwt } from './functions';
import {
  CredentialFormat,
  ExternalSignature,
  InternalSignature,
  PassBy,
  ResponseMode,
  ResponseRegistrationOpts,
  SuppliedSignature
} from './types/SIOP.types';

export default class OPBuilder {
  didMethods: string[] = [];
  resolvers: Map<string, Resolvable> = new Map<string, Resolvable>();
  signatureType: InternalSignature | ExternalSignature | SuppliedSignature;
  credentialFormats: CredentialFormat[] = [];
  responseRegistration: ResponseRegistrationOpts;
  responseMode?: ResponseMode;
  // did: string;
  // vp?: VerifiablePresentation;
  expiresIn?: number;

  addCredentialFormat(credentialFormat: CredentialFormat): OPBuilder {
    this.credentialFormats.push(credentialFormat);
    return this;
  }

  addResolver(didMethod: string, resolver: Resolvable): OPBuilder {
    this.didMethods.push(DIDJwt.toSIOPRegistrationDidMethod(didMethod));
    this.resolvers.set(DIDJwt.getMethodFromDid(didMethod), resolver);
    return this;
  }

  addDidMethod(didMethod: string): OPBuilder {
    this.addResolver(didMethod, new Resolver(getUniResolver(DIDJwt.getMethodFromDid(didMethod))));
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

  registrationBy(registrationBy: PassBy, refUri?: string): OPBuilder {
    this.responseRegistration = {
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
    this.signature({ signature, did, kid })
    return this;
  }

  build(): OP {
    // this.responseRegistration.didMethodsSupported = this.didMethods;
    // this.responseRegistration.subjectIdentifiersSupported = this.subjectIdentifierTypes;
    // this.responseRegistration.credentialFormatsSupported = this.credentialFormats;
    return new OP({ builder: this });
  }
}
