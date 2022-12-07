import { PresentationExchange } from '../authorization-response/PresentationExchange';
import { fetchByReferenceOrUseByValue, getAudience, getResolver, parseJWT, validateLinkedDomainWithDid, verifyDidJWT } from '../functions';
import { authorizationRequestVersionDiscovery } from '../functions/SIOPVersionDiscovery';
import { RequestObject } from '../request-object/RequestObject';
import {
  AuthorizationRequestPayload,
  CheckLinkedDomain,
  PassBy,
  RequestObjectJwt,
  RequestObjectPayload,
  RPRegistrationMetadataPayload,
  SIOPErrors,
  VerifiedAuthorizationRequest,
  VerifiedJWT,
} from '../types';

import { assertValidAuthorizationRequestOpts, assertValidVerifyAuthorizationRequestOpts } from './Opts';
import { assertValidRPRegistrationMedataPayload, createAuthorizationRequestPayload } from './Payload';
import { URI } from './URI';
import { AuthorizationRequestOpts, VerifyAuthorizationRequestOpts } from './types';

export class AuthorizationRequest {
  private readonly _requestObject: RequestObject;
  private readonly _payload: AuthorizationRequestPayload;
  private readonly _options: AuthorizationRequestOpts;
  private _uri: URI;

  private constructor(payload: AuthorizationRequestPayload, requestObject?: RequestObject, opts?: AuthorizationRequestOpts, uri?: URI) {
    this._options = opts;
    this._payload = payload;
    this._requestObject = requestObject;
    this._uri = uri;
  }

  public static async fromUriOrJwt(jwtOrUri: string | URI): Promise<AuthorizationRequest> {
    if (!jwtOrUri) {
      throw Error(SIOPErrors.BAD_PARAMS);
    }
    return typeof jwtOrUri === 'string' && jwtOrUri.startsWith('ey')
      ? await AuthorizationRequest.fromJwt(jwtOrUri)
      : await AuthorizationRequest.fromURI(jwtOrUri);
  }

  public static async fromPayload(payload: AuthorizationRequestPayload): Promise<AuthorizationRequest> {
    if (!payload) {
      throw Error(SIOPErrors.BAD_PARAMS);
    }
    const requestObject = await RequestObject.fromAuthorizationRequestPayload(payload);
    return new AuthorizationRequest(payload, requestObject);
  }

  public static async fromOpts(opts: AuthorizationRequestOpts, requestObject?: RequestObject): Promise<AuthorizationRequest> {
    if (!opts) {
      throw Error(SIOPErrors.BAD_PARAMS);
    }
    assertValidAuthorizationRequestOpts(opts);
    const requestObjectArg = opts.type !== PassBy.NONE ? (requestObject ? requestObject : await RequestObject.fromOpts(opts)) : undefined;
    const requestPayload = await createAuthorizationRequestPayload(opts, requestObjectArg);
    return new AuthorizationRequest(requestPayload, requestObjectArg, opts);
  }

  get payload(): AuthorizationRequestPayload {
    return this._payload;
  }

  get requestObject(): RequestObject | undefined {
    return this._requestObject;
  }

  get options(): AuthorizationRequestOpts | undefined {
    return this._options;
  }

  async uri(): Promise<URI> {
    if (!this._uri) {
      this._uri = await URI.fromAuthorizationRequest(this);
    }
    return this._uri;
  }

  /**
   * Verifies a SIOP Request JWT on OP side
   *
   * @param uriOrJwt
   * @param opts
   */
  async verify(opts: VerifyAuthorizationRequestOpts): Promise<VerifiedAuthorizationRequest> {
    assertValidVerifyAuthorizationRequestOpts(opts);
    const isJwt = this.requestObject !== undefined;
    const jwt = isJwt ? await this.requestObject.toJwt() : undefined;

    let requestObjectPayload: RequestObjectPayload;
    let verifiedJwt: VerifiedJWT;
    if (isJwt && !this.payload.request_uri) {
      // Put back the request object as that won't be present in the Jwt
      this.payload.request = jwt;
    }
    if (jwt) {
      parseJWT(jwt);
      const options = {
        audience: getAudience(jwt),
      };

      verifiedJwt = await verifyDidJWT(jwt, getResolver(opts.verification.resolveOpts), options);
      if (!verifiedJwt || !verifiedJwt.payload) {
        throw Error(SIOPErrors.ERROR_VERIFYING_SIGNATURE);
      }
      requestObjectPayload = verifiedJwt.payload as RequestObjectPayload;
    }

    // AuthorizationRequest.assertValidRequestObject(origAuthenticationRequest);

    // We use the orig request for default values, but the JWT payload contains signed request object properties
    const authorizationRequestPayload = { ...this.payload, ...requestObjectPayload };
    const version = authorizationRequestVersionDiscovery(authorizationRequestPayload);
    if (opts.verification.supportedVersions && !opts.verification.supportedVersions.includes(version)) {
      throw new Error(SIOPErrors.SIOP_VERSION_NOT_SUPPORTED);
    } else if (opts.nonce && authorizationRequestPayload.nonce !== opts.nonce) {
      throw new Error(`${SIOPErrors.BAD_NONCE} payload: ${authorizationRequestPayload.nonce}, supplied: ${opts.nonce}`);
    }

    // todo: We can use client_metadata here as well probably
    const registrationMetadata: RPRegistrationMetadataPayload = await fetchByReferenceOrUseByValue(
      authorizationRequestPayload['registration_uri'],
      authorizationRequestPayload['registration']
    );
    assertValidRPRegistrationMedataPayload(registrationMetadata);

    if (authorizationRequestPayload.client_id.startsWith('did:')) {
      if (opts.verification.checkLinkedDomain && opts.verification.checkLinkedDomain != CheckLinkedDomain.NEVER) {
        await validateLinkedDomainWithDid(authorizationRequestPayload.client_id, opts.verifyCallback, opts.verification.checkLinkedDomain);
      } else if (!opts.verification.checkLinkedDomain) {
        await validateLinkedDomainWithDid(authorizationRequestPayload.client_id, opts.verifyCallback, CheckLinkedDomain.IF_PRESENT);
      }
    }
    const presentationDefinitions = await PresentationExchange.findValidPresentationDefinitions(authorizationRequestPayload);
    return {
      ...verifiedJwt,
      authorizationRequest: this,
      verifyOpts: opts,
      presentationDefinitions,
      requestObject: this.requestObject,
      authorizationRequestPayload: authorizationRequestPayload,
      version,
    };
  }

  static async verify(requestOrUri: string, verifyOpts: VerifyAuthorizationRequestOpts) {
    assertValidVerifyAuthorizationRequestOpts(verifyOpts);
    const authorizationRequest = await AuthorizationRequest.fromUriOrJwt(requestOrUri);
    return await authorizationRequest.verify(verifyOpts);
  }

  public async requestObjectJwt(): Promise<RequestObjectJwt | undefined> {
    return await this.requestObject?.toJwt();
  }

  private static async fromJwt(jwt: string): Promise<AuthorizationRequest> {
    if (!jwt) {
      throw Error(SIOPErrors.BAD_PARAMS);
    }
    const requestObject = await RequestObject.fromJwt(jwt);
    const payload: AuthorizationRequestPayload = { ...(await requestObject.getPayload()) } as AuthorizationRequestPayload;
    // Although this was a RequestObject we instantiate it as AuthzRequest and then copy in the JWT as the request Object
    payload.request = jwt;
    return new AuthorizationRequest({ ...payload }, requestObject);
  }

  private static async fromURI(uri: URI | string): Promise<AuthorizationRequest> {
    if (!uri) {
      throw Error(SIOPErrors.BAD_PARAMS);
    }
    const uriObject = typeof uri === 'string' ? await URI.fromUri(uri) : uri;
    const requestObject = await RequestObject.fromJwt(uriObject.requestObjectJwt);
    return new AuthorizationRequest(uriObject.authorizationRequestPayload, requestObject, undefined, uriObject);
  }
}
