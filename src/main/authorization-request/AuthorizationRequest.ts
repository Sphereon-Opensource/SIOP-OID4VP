import { PresentationExchange } from '../PresentationExchange';
import {
  fetchByReferenceOrUseByValue,
  getAudience,
  getNonce,
  getResolver,
  getState,
  parseJWT,
  validateLinkedDomainWithDid,
  verifyDidJWT,
} from '../functions';
import { authorizationRequestVersionDiscovery } from '../functions/SIOPVersionDiscovery';
import { assertValidRequestObjectOpts } from '../request-object/Opts';
import { RequestObject } from '../request-object/RequestObject';
import {
  AuthorizationRequestOpts,
  AuthorizationRequestPayload,
  CheckLinkedDomain,
  PassBy,
  RequestObjectPayload,
  RequestObjectResult,
  ResponseMode,
  ResponseType,
  RPRegistrationMetadataPayload,
  Scope,
  SIOPErrors,
  VerifiedAuthorizationRequest,
  VerifiedJWT,
  VerifyAuthorizationRequestOpts,
} from '../types';

import { assertValidAuthorizationRequestOpts, assertValidVerifyAuthorizationRequestOpts } from './Opts';
import { assertValidRPRegistrationMedataPayload, createClaimsProperties } from './Payload';
import { createRequestRegistration } from './RequestRegistration';
import URI from './URI';

export default class AuthorizationRequest {
  public static readonly URI: URI = new URI();

  static async createAuthorizationRequest(opts: AuthorizationRequestOpts, requestObject?: string): Promise<AuthorizationRequestPayload> {
    assertValidAuthorizationRequestOpts(opts);
    if (opts.requestBy && opts.requestBy.type === PassBy.VALUE && !requestObject) {
      throw Error(SIOPErrors.NO_JWT);
    }
    const state = getState(opts.state);
    const registration = await createRequestRegistration(opts['registration']);
    const claims = createClaimsProperties(opts.claims);
    const clientId = opts.clientId ? opts.clientId : registration.requestRegistration.registration.client_id;

    return {
      response_type: ResponseType.ID_TOKEN,
      scope: Scope.OPENID,
      //TODO implement /.well-known/openid-federation support in the OP side to resolve the client_id (URL) and retrieve the metadata
      client_id: clientId ? clientId : opts.signatureType.did,
      redirect_uri: opts.redirectUri,
      response_mode: opts.responseMode || ResponseMode.POST,
      id_token_hint: opts.idTokenHint,
      registration_uri: opts['registrationUri'],
      ...(opts.requestBy && opts.requestBy.type === PassBy.REFERENCE ? { request_uri: opts.requestBy.referenceUri } : {}),
      ...(opts.requestBy && opts.requestBy.type === PassBy.VALUE ? { request: requestObject } : {}),
      nonce: getNonce(state, opts.nonce),
      state,
      ...registration.requestRegistration,
      claims,
    };
  }

  /**
   * Create a signed SIOP request object as JWT on RP side, typically you will want to use the createURI version!
   *
   * @param opts Request input data to build a SIOP Request Object as JWT
   * @remarks This method is used to generate a SIOP request Object with info provided by the RP.
   * First it generates the request object payload, and then it creates the signed JWT.
   *
   * Normally you will want to use the createURI method. That creates a URI that includes the JWT from this method in the URI
   * If you do use this method, you can call the `convertRequestObjectToURI` afterwards to get the URI.
   * Please note that the createURI method allows you to differentiate between OAuth2 and OpenID parameters that become
   * part of the URI and which become part of the Request Object. If you generate a URI based upon the result of this method,
   * the URI will be constructed based on the Request Object only!
   */
  static async createRequestObject(opts: AuthorizationRequestOpts): Promise<RequestObjectResult> {
    assertValidRequestObjectOpts(opts, false);
    if (opts && opts.requestBy?.type === PassBy.NONE) {
      throw Error(`Cannot create a Request Object when the passBy options is set to None`);
    }
    const createdRequestObject = await RequestObject.fromAuthorizationRequestOpts(opts);
    /*const requestObject =
    const requestObjectPayload = JSON.parse(JSON.stringify(createdRequestObject));
    // https://openid.net/specs/openid-connect-core-1_0.html#RequestObject
    // request and request_uri parameters MUST NOT be included in Request Objects.
    delete requestObjectPayload.request;
    delete requestObjectPayload.request_uri;
    const requestObject = await signDidJwtPayload(requestObjectPayload, opts);*/

    return {
      opts,
      requestObject: await createdRequestObject.getJwt(),
      requestObjectPayload: await createdRequestObject.getPayload(),
    };
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
    const jwt = isJwt ? uriOrJwt : (await this.URI.parseAndResolve(uriOrJwt)).requestObject;

    const origAuthorizationRequest = isJwt ? (parseJWT(jwt).payload as AuthorizationRequestPayload) : this.URI.parse(uriOrJwt).authorizationRequest;
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
