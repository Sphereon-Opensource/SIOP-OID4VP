import { PresentationExchange } from '../PresentationExchange';
import { fetchByReferenceOrUseByValue, getAudience, getResolver, parseJWT, validateLinkedDomainWithDid, verifyDidJWT } from '../functions';
import { authorizationRequestVersionDiscovery } from '../functions/SIOPVersionDiscovery';
import { RequestObject } from '../request-object/RequestObject';
import {
  AuthorizationRequestOpts,
  AuthorizationRequestPayload,
  CheckLinkedDomain,
  PassBy,
  RequestObjectPayload,
  RPRegistrationMetadataPayload,
  SIOPErrors,
  VerifiedAuthorizationRequest,
  VerifiedJWT,
  VerifyAuthorizationRequestOpts,
} from '../types';

import { assertValidAuthorizationRequestOpts, assertValidVerifyAuthorizationRequestOpts } from './Opts';
import { assertValidRPRegistrationMedataPayload, createAuthorizationRequestPayload } from './Payload';
import { URI } from './URI';

export default class AuthorizationRequest {
  // public static readonly URI: URI = new URI();
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

  static async fromURI(uri: URI | string): Promise<AuthorizationRequest> {
    const uriObject = typeof uri === 'string' ? await URI.fromValue(uri) : uri;
    const requestObject = await RequestObject.fromJwt(uriObject.requestObjectJwt);
    return new AuthorizationRequest(uriObject.authorizationRequestPayload, requestObject, undefined, uriObject);
  }

  static async fromOpts(opts: AuthorizationRequestOpts, requestObject?: RequestObject): Promise<AuthorizationRequest> {
    assertValidAuthorizationRequestOpts(opts);
    const requestObjectArg = opts.requestBy.type !== PassBy.NONE ? (requestObject ? requestObject : await RequestObject.fromOpts(opts)) : undefined;
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
  static async verify(uriOrJwt: string, opts: VerifyAuthorizationRequestOpts): Promise<VerifiedAuthorizationRequest> {
    assertValidVerifyAuthorizationRequestOpts(opts);
    if (!uriOrJwt) {
      throw new Error(SIOPErrors.NO_URI);
    }
    const isJwt = uriOrJwt.startsWith('ey');
    const jwt = isJwt ? uriOrJwt : (await URI.parseAndResolve(uriOrJwt)).requestObjectJwt;

    const origAuthorizationRequest = isJwt ? (parseJWT(jwt).payload as AuthorizationRequestPayload) : URI.parse(uriOrJwt).authorizationRequestPayload;
    let requestObjectPayload: RequestObjectPayload;
    let verifiedJwt: VerifiedJWT;
    if (isJwt) {
      // Put back the request object as that won't be present in the Jwt
      origAuthorizationRequest.request = jwt;
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
    const authorizationRequest = { ...origAuthorizationRequest, ...requestObjectPayload };
    const version = authorizationRequestVersionDiscovery(authorizationRequest);
    if (opts.verification.supportedVersions && !opts.verification.supportedVersions.includes(version)) {
      throw new Error(SIOPErrors.SIOP_VERSION_NOT_SUPPORTED);
    } else if (opts.nonce && authorizationRequest.nonce !== opts.nonce) {
      throw new Error(`${SIOPErrors.BAD_NONCE} payload: ${authorizationRequest.nonce}, supplied: ${opts.nonce}`);
    }

    // todo: We can use client_metadata here as well probably
    const registrationMetadata: RPRegistrationMetadataPayload = await fetchByReferenceOrUseByValue(
      authorizationRequest['registration_uri'],
      authorizationRequest['registration']
    );
    assertValidRPRegistrationMedataPayload(registrationMetadata);

    if (authorizationRequest.client_id.startsWith('did:')) {
      if (opts.verification.checkLinkedDomain && opts.verification.checkLinkedDomain != CheckLinkedDomain.NEVER) {
        await validateLinkedDomainWithDid(authorizationRequest.client_id, opts.verifyCallback, opts.verification.checkLinkedDomain);
      } else if (!opts.verification.checkLinkedDomain) {
        await validateLinkedDomainWithDid(authorizationRequest.client_id, opts.verifyCallback, CheckLinkedDomain.IF_PRESENT);
      }
    }
    const presentationDefinitions = await PresentationExchange.findValidPresentationDefinitions(authorizationRequest);
    return {
      ...verifiedJwt,
      verifyOpts: opts,
      presentationDefinitions,
      payload: requestObjectPayload,
      authorizationRequest: authorizationRequest,
      version,
    };
  }
}
