import { VerifyCallback } from '@sphereon/wellknown-dids-client';
import Ajv from 'ajv';
import { Resolvable } from 'did-resolver';

import RPBuilder from './RPBuilder';
import { URI } from './authorization-request/URI';
import { AuthorizationRequestOpts } from './authorization-request/types';
import { AuthorizationResponse } from './authorization-response';
import { verifyPresentations } from './authorization-response/OpenID4VP';
import { ClaimOpts, PresentationVerificationCallback, VerifyAuthorizationResponseOpts } from './authorization-response/types';
import { getNonce, getResolverUnion, getState, mergeAllDidMethods } from './functions';
import { AuthorizationRequestOptsSchema } from './schemas';
import {
  AuthorizationRequestURI,
  CheckLinkedDomain,
  ClientMetadataOpts,
  ExternalVerification,
  InternalVerification,
  Verification,
  VerificationMode,
  VerifiedAuthenticationResponse,
} from './types';

const ajv = new Ajv({ allowUnionTypes: true, strict: false });
const validate = ajv.compile(AuthorizationRequestOptsSchema);

export class RP {
  private readonly _authRequestOpts: AuthorizationRequestOpts;
  private readonly _verifyAuthResponseOpts: Partial<VerifyAuthorizationResponseOpts>;

  public constructor(opts: { builder?: RPBuilder; requestOpts?: AuthorizationRequestOpts; verifyOpts?: VerifyAuthorizationResponseOpts }) {
    const claims = opts.builder?.claims;
    const authReqOpts = createRequestOptsFromBuilderOrExistingOpts(opts);
    this._authRequestOpts = { ...authReqOpts, payload: { ...authReqOpts.payload, claims } };
    this._verifyAuthResponseOpts = { ...createVerifyResponseOptsFromBuilderOrExistingOpts(opts), claims };
  }

  get authRequestOpts(): AuthorizationRequestOpts {
    return this._authRequestOpts;
  }

  get verifyAuthResponseOpts(): Partial<VerifyAuthorizationResponseOpts> {
    return this._verifyAuthResponseOpts;
  }

  public async createAuthenticationRequest(opts?: { nonce?: string; state?: string }): Promise<AuthorizationRequestURI> {
    return await URI.fromOpts(this.newAuthenticationRequestOpts(opts));
  }

  public async verifyAuthenticationResponse(
    authorizationResponse: AuthorizationResponse,
    opts?: {
      audience: string;
      state?: string;
      nonce?: string;
      verification?: InternalVerification | ExternalVerification;
      claims?: ClaimOpts;
      checkLinkedDomain?: CheckLinkedDomain;
    }
  ): Promise<VerifiedAuthenticationResponse> {
    const verification: Verification = this._verifyAuthResponseOpts.verification;
    const verifyCallback = verification.wellknownDIDVerifyCallback || this._verifyAuthResponseOpts.verifyCallback;
    const presentationVerificationCallback =
      verification.presentationVerificationCallback || this.verifyAuthResponseOpts.presentationVerificationCallback;
    const verifyAuthenticationResponseOpts = this.newVerifyAuthenticationResponseOpts({
      ...opts,
      verifyCallback,
      presentationVerificationCallback,
    });
    await verifyPresentations(authorizationResponse.payload, verifyAuthenticationResponseOpts);
    return await authorizationResponse.idToken.verify(verifyAuthenticationResponseOpts);
  }

  public newAuthenticationRequestOpts(opts?: { nonce?: string; state?: string }): AuthorizationRequestOpts {
    const state = opts?.state || getState(opts?.state);
    const nonce = opts?.nonce || getNonce(state, opts?.nonce);
    return {
      ...this._authRequestOpts,
      payload: { ...this._authRequestOpts.payload, state, nonce },
    };
  }

  public newVerifyAuthenticationResponseOpts(opts?: {
    state?: string;
    nonce?: string;
    verification?: InternalVerification | ExternalVerification;
    claims?: ClaimOpts;
    audience: string;
    checkLinkedDomain?: CheckLinkedDomain;
    verifyCallback?: VerifyCallback;
    presentationVerificationCallback?: PresentationVerificationCallback;
  }): VerifyAuthorizationResponseOpts {
    return {
      ...this._verifyAuthResponseOpts,
      audience: opts.audience,
      state: opts?.state || this._verifyAuthResponseOpts.state,
      nonce: opts?.nonce || this._verifyAuthResponseOpts.nonce,
      claims: { ...this._verifyAuthResponseOpts.claims, ...opts.claims },
      verification: opts?.verification || this._verifyAuthResponseOpts.verification,
      verifyCallback: opts?.verifyCallback,
      presentationVerificationCallback: opts?.presentationVerificationCallback,
    };
  }

  public static fromRequestOpts(opts: AuthorizationRequestOpts): RP {
    return new RP({ requestOpts: opts });
  }

  public static builder() {
    return new RPBuilder();
  }
}

function createRequestOptsFromBuilderOrExistingOpts(opts: { builder?: RPBuilder; requestOpts?: AuthorizationRequestOpts }) {
  const requestOpts: AuthorizationRequestOpts = opts.builder
    ? {
        payload: {
          authorization_endpoint: opts.builder.authorizationEndpoint,
          subject_types_supported: opts.builder.requestRegistration.subjectTypesSupported,
          request_object_signing_alg_values_supported: opts.builder.requestRegistration.requestObjectSigningAlgValuesSupported,
          response_mode: opts.builder.responseMode,
          // responseContext: opts.builder.responseContext,
          claims: opts.builder.claims,
          scope: opts.builder.scope,
          response_type: opts.builder.responseType,
          client_id: opts.builder.clientId,
          redirect_uri: opts.builder.redirectUri,
          response_types_supported: opts.builder.requestRegistration.responseTypesSupported,
          scopes_supported: opts.builder.requestRegistration.scopesSupported,
        },
        requestObject: {
          ...opts.builder.requestObjectBy,
          signatureType: opts.builder.signatureType,
        },
        clientMetadata: opts.builder.requestRegistration as ClientMetadataOpts,
      }
    : opts.requestOpts;

  const valid = validate(requestOpts);
  if (!valid) {
    throw new Error('RP builder validation error: ' + JSON.stringify(validate.errors));
  }
  return requestOpts;
}

function createVerifyResponseOptsFromBuilderOrExistingOpts(opts: { builder?: RPBuilder; verifyOpts?: VerifyAuthorizationResponseOpts }) {
  if (opts?.builder?.resolvers.size && opts.builder?.requestRegistration) {
    opts.builder.requestRegistration.subjectSyntaxTypesSupported = mergeAllDidMethods(
      opts.builder.requestRegistration.subjectSyntaxTypesSupported,
      opts.builder.resolvers
    );
  }
  let resolver: Resolvable;
  if (opts.builder) {
    resolver = getResolverUnion(opts.builder.customResolver, opts.builder.requestRegistration.subjectSyntaxTypesSupported, opts.builder.resolvers);
  }
  return opts.builder
    ? {
        verification: {
          mode: VerificationMode.INTERNAL,
          checkLinkedDomain: opts.builder.checkLinkedDomain,
          wellknownDIDVerifyCallback: opts.builder.verifyCallback,
          presentationVerificationCallback: opts.builder.presentationVerificationCallback,
          resolveOpts: {
            subjectSyntaxTypesSupported: opts.builder.requestRegistration.subjectSyntaxTypesSupported,
            resolver: resolver,
          },
          supportedVersions: opts.builder.supportedVersions,
          revocationOpts: {
            revocationVerification: opts.builder.revocationVerification,
            revocationVerificationCallback: opts.builder.revocationVerificationCallback,
          },
        } as InternalVerification,
      }
    : opts.verifyOpts;
}
