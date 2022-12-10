import Ajv from 'ajv';
import { Resolvable } from 'did-resolver';

import RPBuilder from './RPBuilder';
import { URI } from './authorization-request/URI';
import { AuthorizationRequestOpts } from './authorization-request/types';
import { AuthorizationResponse } from './authorization-response';
import { verifyPresentations } from './authorization-response/OpenID4VP';
import { ClaimOpts, VerifyAuthorizationResponseOpts } from './authorization-response/types';
import { getNonce, getResolverUnion, getState, mergeAllDidMethods } from './functions';
import { AuthorizationRequestOptsSchema } from './schemas';
import {
  AuthorizationResponsePayload,
  CheckLinkedDomain,
  ClientMetadataOpts,
  ExternalVerification,
  InternalVerification,
  VerificationMode,
  VerifiedAuthenticationResponse,
} from './types';

const ajv = new Ajv({ allowUnionTypes: true, strict: false });
const validate = ajv.compile(AuthorizationRequestOptsSchema);

export class RP {
  private readonly _authorizationRequestOptions: AuthorizationRequestOpts;
  private readonly _verifyAuthorizationResponseOptions: Partial<VerifyAuthorizationResponseOpts>;

  public constructor(opts: { builder?: RPBuilder; requestOpts?: AuthorizationRequestOpts; verifyOpts?: VerifyAuthorizationResponseOpts }) {
    const claims = opts.builder?.claims || opts.requestOpts?.payload.claims;
    const authReqOpts = createRequestOptsFromBuilderOrExistingOpts(opts);
    this._authorizationRequestOptions = { ...authReqOpts, payload: { ...authReqOpts.payload, claims } };
    this._verifyAuthorizationResponseOptions = { ...createVerifyResponseOptsFromBuilderOrExistingOpts(opts), claims };
  }

  get authorizationRequestOptions(): AuthorizationRequestOpts {
    return this._authorizationRequestOptions;
  }

  get verifyAuthorizationResponseOptions(): Partial<VerifyAuthorizationResponseOpts> {
    return this._verifyAuthorizationResponseOptions;
  }

  public async createAuthorizationRequestURI(opts?: { nonce?: string; state?: string }): Promise<URI> {
    return await URI.fromOpts(this.newAuthorizationRequestOpts(opts));
  }

  public async verifyAuthorizationResponse(
    authorizationResponsePayload: AuthorizationResponsePayload,
    opts?: {
      audience?: string;
      state?: string;
      nonce?: string;
      verification?: InternalVerification | ExternalVerification;
      claims?: ClaimOpts;
    }
  ): Promise<VerifiedAuthenticationResponse> {
    const verifyAuthenticationResponseOpts = this.newVerifyAuthorizationResponseOpts({
      ...opts,
    });
    await verifyPresentations(authorizationResponsePayload, verifyAuthenticationResponseOpts);
    const authorizationResponse = await AuthorizationResponse.fromPayload(authorizationResponsePayload);
    return await authorizationResponse.verify(verifyAuthenticationResponseOpts);
  }

  private newAuthorizationRequestOpts(opts?: { nonce?: string; state?: string }): AuthorizationRequestOpts {
    const state = opts?.state || getState(opts?.state);
    const nonce = opts?.nonce || getNonce(state, opts?.nonce);
    return {
      ...this._authorizationRequestOptions,
      payload: { ...this._authorizationRequestOptions.payload, state, nonce },
    };
  }

  private newVerifyAuthorizationResponseOpts(opts?: {
    state?: string;
    nonce?: string;
    verification?: InternalVerification | ExternalVerification;
    claims?: ClaimOpts;
    audience?: string;
    checkLinkedDomain?: CheckLinkedDomain;
  }): VerifyAuthorizationResponseOpts {
    return {
      ...this._verifyAuthorizationResponseOptions,
      audience: opts?.audience || this._verifyAuthorizationResponseOptions.audience,
      state: opts?.state || this._verifyAuthorizationResponseOptions.state,
      nonce: opts?.nonce || this._verifyAuthorizationResponseOptions.nonce,
      claims: { ...this._verifyAuthorizationResponseOptions.claims, ...opts.claims },
      verification: opts?.verification || this._verifyAuthorizationResponseOptions.verification,
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
