import Ajv from 'ajv';

import AuthenticationRequest from './AuthenticationRequest';
import AuthenticationResponse from './AuthenticationResponse';
import RPBuilder from './RPBuilder';
import { State } from './functions';
import { getResolver } from './functions/DIDResolution';
import { AuthenticationRequestOptsSchema } from './schemas/AuthenticationRequestOpts.schema';
import { SIOP } from './types';
import {
  AuthenticationRequestOpts,
  AuthenticationRequestURI,
  ClaimOpts,
  ExternalVerification,
  InternalVerification,
  RequestRegistrationOpts,
  VerificationMode,
  VerifiedAuthenticationResponseWithJWT,
  VerifyAuthenticationResponseOpts,
} from './types/SIOP.types';

const ajv = new Ajv();
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
    }
  ): Promise<VerifiedAuthenticationResponseWithJWT> {
    return AuthenticationResponse.verifyJWT(jwt, this.newVerifyAuthenticationResponseOpts(opts));
  }

  public newAuthenticationRequestOpts(opts?: { nonce?: string; state?: string }): AuthenticationRequestOpts {
    const state = opts?.state || State.getState(opts?.state);
    const nonce = opts?.nonce || State.getNonce(state, opts?.nonce);
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
  }): VerifyAuthenticationResponseOpts {
    return {
      ...this._verifyAuthResponseOpts,
      audience: opts.audience,
      state: opts?.state || this._verifyAuthResponseOpts.state,
      nonce: opts?.nonce || this._verifyAuthResponseOpts.nonce,
      claims: { ...this._verifyAuthResponseOpts.claims, ...opts.claims },
      verification: opts?.verification || this._verifyAuthResponseOpts.verification,
    };
  }

  public static fromRequestOpts(opts: SIOP.AuthenticationRequestOpts): RP {
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

function createVerifyResponseOptsFromBuilderOrExistingOpts(opts: { builder?: RPBuilder; verifyOpts?: Partial<VerifyAuthenticationResponseOpts> }) {
  return opts.builder
    ? {
        verification: {
          mode: VerificationMode.INTERNAL,
          resolveOpts: {
            //TODO: https://sphereon.atlassian.net/browse/VDX-126 add support of other subjectSyntaxTypes
            didMethods: !opts.builder.requestRegistration.subjectSyntaxTypesSupported
              ? []
              : opts.builder.requestRegistration.subjectSyntaxTypesSupported.filter((t) => t.startsWith('did:')),
            resolver: opts.builder.resolvers
              ? //TODO: discuss this with Niels
                getResolver({ resolver: opts.builder.resolvers.values().next().value })
              : getResolver({ subjectSyntaxTypesSupported: opts.builder.requestRegistration.subjectSyntaxTypesSupported }),
          },
        },
      }
    : opts.verifyOpts;
}
