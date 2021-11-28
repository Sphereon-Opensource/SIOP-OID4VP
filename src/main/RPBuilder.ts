import { getUniResolver } from '@sphereon/did-uni-client';
import { Resolvable, Resolver } from 'did-resolver';

import { RP } from './RP';
import { DIDJwt } from './functions';
import {
  ClaimOpts,
  CredentialFormat,
  ExternalSignature,
  InternalSignature,
  NoSignature,
  ObjectBy,
  PassBy,
  PresentationDefinitionWithLocation,
  RequestRegistrationOpts,
  ResponseContext,
  ResponseMode,
  SubjectIdentifierType,
} from './types/SIOP.types';

export default class RPBuilder {
  subjectIdentifierTypes: SubjectIdentifierType = SubjectIdentifierType.DID;
  didMethods: string[] = [];
  resolvers: Map<string, Resolvable> = new Map<string, Resolvable>();
  credentialFormats: CredentialFormat[] = [];
  requestRegistration: Partial<RequestRegistrationOpts> = {};
  redirectUri: string;
  requestObjectBy: ObjectBy;
  signatureType: InternalSignature | ExternalSignature | NoSignature;
  responseMode?: ResponseMode;
  responseContext?: ResponseContext.RP;
  claims?: ClaimOpts;

  // claims?: ClaimPayload;

  addCredentialFormat(credentialType: CredentialFormat): RPBuilder {
    this.credentialFormats.push(credentialType);
    return this;
  }

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
        referenceUri: refUri,
      },
    };
    /*if (refUri) {
          this.requestRegistration.registrationBy.referenceUri = refUri;
        }*/
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
    this.requestRegistration.didMethodsSupported = this.didMethods;
    this.requestRegistration.subjectIdentifiersSupported = this.subjectIdentifierTypes;
    this.requestRegistration.credentialFormatsSupported = this.credentialFormats;
    return new RP({ builder: this });
  }
}
