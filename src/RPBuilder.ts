import { getResolver as getUniResolver } from '@sphereon/did-uni-client/dist/resolver/Resolver';
import { Resolvable, Resolver } from 'did-resolver';

import { RP } from './RP';
import { DIDJwt } from './functions';
import {
  ExternalSignature,
  InternalSignature,
  NoSignature,
  ObjectBy,
  PassBy,
  RequestRegistrationOpts,
  ResponseContext,
  ResponseMode,
  SubjectIdentifierType,
} from './types/SIOP.types';
import { OidcClaim } from './types/SSI.types';

export default class RPBuilder {
  subjectIdentifierTypes: SubjectIdentifierType = SubjectIdentifierType.DID;
  didMethods: string[] = [];
  resolvers: Map<string, Resolvable> = new Map<string, Resolvable>();

  requestRegistration: Partial<RequestRegistrationOpts> = {};
  redirectUri: string;
  requestObjectBy: ObjectBy;
  signatureType: InternalSignature | ExternalSignature | NoSignature;
  responseMode?: ResponseMode;
  responseContext?: ResponseContext.RP;
  claims?: OidcClaim;

  addResolver(didMethod: string, resolver: Resolvable): RPBuilder {
    this.didMethods.push(DIDJwt.toSIOPRegistrationDidMethod(didMethod));
    this.resolvers.set(DIDJwt.getMethodFromDid(didMethod), resolver);
    return this;
  }

  addDidMethod(didMethod: string): RPBuilder {
    this.addResolver(didMethod, new Resolver(getUniResolver(DIDJwt.getMethodFromDid(didMethod))));
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
      },
    };
    if (refUri) {
      this.requestRegistration.registrationBy.referenceUri = refUri;
    }
    return this;
  }

  // Only internal supported for now
  signature(signatureType: InternalSignature): RPBuilder {
    this.signatureType = signatureType;
    return this;
  }

  internalSignature(hexPrivateKey: string, did: string, kid?: string): RPBuilder {
    this.signature({ hexPrivateKey, did, kid });
    return this;
  }

  build(): RP {
    this.requestRegistration.didMethodsSupported = this.didMethods;
    this.requestRegistration.subjectIdentifiersSupported = this.subjectIdentifierTypes;
    return new RP({ builder: this });
  }
}
