import { VerifyCallback } from '@sphereon/wellknown-dids-client';
import Ajv from 'ajv';
import { Resolvable } from 'did-resolver';

import { getNonce, getResolverUnion, getState, mergeAllDidMethods } from './functions';
import { AuthenticationRequestOptsSchema } from './schemas';
import {
  AuthenticationRequestOpts,
  AuthenticationRequestURI,
  CheckLinkedDomain,
  ClaimOpts,
  ExternalVerification,
  InternalVerification,
  RequestRegistrationOpts,
  SignatureVerificationCallback,
  Verification,
  VerificationMode,
  VerifiedAuthenticationResponseWithJWT,
  VerifyAuthenticationResponseOpts,
} from './types';

import { AuthenticationRequest, AuthenticationResponse, RPBuilder } from './';

const ajv = new Ajv({ allowUnionTypes: true });
const validate = ajv.compile(AuthenticationRequestOptsSchema);

export class RP {
  private readonly _authRequestOpts: AuthenticationRequestOpts;
  private readonly _verifyAuthResponseOpts: Partial<VerifyAuthenticationResponseOpts>;

  public constructor(opts: { builder?: RPBuilder; requestOpts?: AuthenticationRequestOpts; verifyOpts?: VerifyAuthenticationResponseOpts }) {
    const claims = opts.builder?.claims;
    this._authRequestOpts = { claims, ...createRequestOptsFromBuilderOrExistingOpts(opts) };
    this._verifyAuthResponseOpts = { claims, ...createVerifyResponseOptsFromBuilderOrExistingOpts(opts) };
  }

  get authRequestOpts(): AuthenticationRequestOpts {
    return this._authRequestOpts;
  }

  get verifyAuthResponseOpts(): Partial<VerifyAuthenticationResponseOpts> {
    return this._verifyAuthResponseOpts;
  }

  public createAuthenticationRequest(opts?: { nonce?: string; state?: string }): Promise<AuthenticationRequestURI> {
    return AuthenticationRequest.createURI(this.newAuthenticationRequestOpts(opts));
  }

  public async verifyAuthenticationResponseJwt(
    jwt: string,
    opts?: {
      audience: string;
      state?: string;
      nonce?: string;
      verification?: InternalVerification | ExternalVerification;
      claims?: ClaimOpts;
      checkLinkedDomain?: CheckLinkedDomain;
    }
  ): Promise<VerifiedAuthenticationResponseWithJWT> {
    const verifyCallback = (this._verifyAuthResponseOpts.verification as Verification).verifyCallback || this._verifyAuthResponseOpts.verifyCallback;
    const signatureVerificationCallback =
      (this._verifyAuthResponseOpts.verification as Verification).signatureVerificationCallback ||
      this.verifyAuthResponseOpts.signatureVerificationCallback;
    return AuthenticationResponse.verifyJWT(
      jwt,
      this.newVerifyAuthenticationResponseOpts({ ...opts, verifyCallback, signatureVerificationCallback })
    );
  }

  public newAuthenticationRequestOpts(opts?: { nonce?: string; state?: string }): AuthenticationRequestOpts {
    const state = opts?.state || getState(opts?.state);
    const nonce = opts?.nonce || getNonce(state, opts?.nonce);
    return {
      ...this._authRequestOpts,
      state,
      nonce,
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
    signatureVerificationCallback?: SignatureVerificationCallback;
  }): VerifyAuthenticationResponseOpts {
    return {
      ...this._verifyAuthResponseOpts,
      audience: opts.audience,
      state: opts?.state || this._verifyAuthResponseOpts.state,
      nonce: opts?.nonce || this._verifyAuthResponseOpts.nonce,
      claims: { ...this._verifyAuthResponseOpts.claims, ...opts.claims },
      verification: opts?.verification || this._verifyAuthResponseOpts.verification,
      verifyCallback: opts?.verifyCallback,
      signatureVerificationCallback: opts?.signatureVerificationCallback,
    };
  }

  public static fromRequestOpts(opts: AuthenticationRequestOpts): RP {
    return new RP({ requestOpts: opts });
  }

  public static builder() {
    return new RPBuilder();
  }
}

function createRequestOptsFromBuilderOrExistingOpts(opts: { builder?: RPBuilder; requestOpts?: AuthenticationRequestOpts }) {
  const requestOpts: AuthenticationRequestOpts = opts.builder
    ? {
        authorizationEndpoint: opts.builder.authorizationEndpoint,
        registration: opts.builder.requestRegistration as RequestRegistrationOpts,
        redirectUri: opts.builder.redirectUri,
        requestBy: opts.builder.requestObjectBy,
        responseTypesSupported: opts.builder.requestRegistration.responseTypesSupported,
        scopesSupported: opts.builder.requestRegistration.scopesSupported,
        signatureType: opts.builder.signatureType,
        subjectTypesSupported: opts.builder.requestRegistration.subjectTypesSupported,
        requestObjectSigningAlgValuesSupported: opts.builder.requestRegistration.requestObjectSigningAlgValuesSupported,
        responseMode: opts.builder.responseMode,
        responseContext: opts.builder.responseContext,
        claims: opts.builder.claims,
      }
    : opts.requestOpts;

  const valid = validate(requestOpts);
  if (!valid) {
    throw new Error('RP builder validation error: ' + JSON.stringify(validate.errors));
  }
  return requestOpts;
}

function createVerifyResponseOptsFromBuilderOrExistingOpts(opts: { builder?: RPBuilder; verifyOpts?: VerifyAuthenticationResponseOpts }) {
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
          verifyCallback: opts.builder.verifyCallback,
          signatureVerificationCallback: opts.builder.signatureVerificationCallback,
          resolveOpts: {
            subjectSyntaxTypesSupported: opts.builder.requestRegistration.subjectSyntaxTypesSupported,
            resolver: resolver,
          },
          revocationOpts: {
            revocationVerification: opts.builder.revocationVerification,
            revocationVerificationCallback: opts.builder.revocationVerificationCallback,
          },
        } as InternalVerification,
      }
    : opts.verifyOpts;
}
