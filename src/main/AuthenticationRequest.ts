import { PEX } from '@sphereon/pex';
import Ajv from 'ajv';
import { decodeJWT, JWTHeader } from 'did-jwt';

import { assertValidRequestRegistrationOpts, createRequestRegistration } from './AuthenticationRequestRegistration';
import { PresentationExchange } from './PresentationExchange';
import {
  decodeUriAsJson,
  encodeJsonAsURI,
  fetchByReferenceOrUseByValue,
  getAudience,
  getNonce,
  getResolver,
  getState,
  parseJWT,
  signDidJwtPayload,
  validateLinkedDomainWithDid,
  verifyDidJWT,
} from './functions';
import { authorizationRequestVersionDiscovery } from './functions/SIOPVersionDiscovery';
import { RPRegistrationMetadataPayloadSchema } from './schemas';
import {
  AuthenticationRequestOpts,
  AuthorizationRequestPayload,
  AuthorizationRequestURI,
  CheckLinkedDomain,
  ClaimOpts,
  ClaimPayload,
  isExternalVerification,
  isInternalVerification,
  JWTPayload,
  PassBy,
  RequestObjectPayload,
  RequestObjectResult,
  ResponseMode,
  ResponseType,
  RPRegistrationMetadataPayload,
  Scope,
  SIOPErrors,
  UrlEncodingFormat,
  VerifiedAuthenticationRequestWithJWT,
  VerifiedJWT,
  VerifyAuthenticationRequestOpts,
} from './types';

const ajv = new Ajv({ allowUnionTypes: true, strict: false });
const validateRPRegistrationMetadata = ajv.compile(RPRegistrationMetadataPayloadSchema);

export default class AuthenticationRequest {
  /**
   * Create a signed URL encoded URI with a signed SIOP request token on RP side
   *
   * @param opts Request input data to build a  SIOP Request Token
   * @remarks This method is used to generate a SIOP request with info provided by the RP.
   * First it generates the request payload and then it creates the signed JWT, which is returned as a URI
   *
   * Normally you will want to use this method to create the request.
   */
  public static async createURI(opts: AuthenticationRequestOpts): Promise<AuthorizationRequestURI> {
    const { requestObject } = await AuthenticationRequest.createRequestObject(opts);
    const authorizationRequest = await createAuthorizationRequestPayload(opts, requestObject);
    return AuthenticationRequest.createURIFromRequest(opts, authorizationRequest);
  }

  public static async parseAndResolveURI(encodedUri: string) {
    const { scheme, requestObject, authorizationRequest } = await AuthenticationRequest.parseAndResolveRequestUri(encodedUri);
    if (requestObject) {
      AuthenticationRequest.assertValidRequestObject(decodeJWT(requestObject) as RequestObjectPayload);
    }
    const registrationMetadata: RPRegistrationMetadataPayload = await fetchByReferenceOrUseByValue(
      authorizationRequest['registration_uri'],
      authorizationRequest['registration']
    );
    AuthenticationRequest.assertValidRegistrationObject(registrationMetadata);

    return { scheme, requestObject, authorizationRequest, registrationMetadata };
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
  static async createRequestObject(opts: AuthenticationRequestOpts): Promise<RequestObjectResult> {
    if (opts.requestBy.type === PassBy.NONE) {
      throw Error(`Cannot create a Request Object when the passBy options is set to None`);
    }
    const createdRequestObject = await createRequestObjectPayload(opts);
    const requestObjectPayload = JSON.parse(JSON.stringify(createdRequestObject));
    // https://openid.net/specs/openid-connect-core-1_0.html#RequestObject
    // request and request_uri parameters MUST NOT be included in Request Objects.
    delete requestObjectPayload.registration;
    delete requestObjectPayload.registration_uri;
    const requestObject = await signDidJwtPayload(requestObjectPayload, opts);

    return {
      opts,
      requestObject,
      requestObjectPayload,
    };
  }

  /**
   * Create a URI from the request object, typically you will want to use the createURI version!
   *
   * @remarks This method is used to generate a SIOP request Object with info provided by the RP.
   * First it generates the request object payload, and then it creates the signed JWT.
   *
   * Please note that the createURI method allows you to differentiate between OAuth2 and OpenID parameters that become
   * part of the URI and which become part of the Request Object. If you generate a URI based upon the result of this method,
   * the URI will be constructed based on the Request Object only!
   */
  static async convertRequestObjectToURI(request: RequestObjectResult): Promise<AuthorizationRequestURI> {
    return await AuthenticationRequest.createURIFromRequest(request.opts, request.requestObject);
  }

  /**
   * Verifies a SIOP Request JWT on OP side
   *
   * @param jwt
   * @param opts
   */
  static async verify(uriOrJwt: string, opts: VerifyAuthenticationRequestOpts): Promise<VerifiedAuthenticationRequestWithJWT> {
    assertValidVerifyOpts(opts);
    if (!uriOrJwt) {
      throw new Error(SIOPErrors.NO_URI);
    }
    const isJwt = uriOrJwt.startsWith('ey');
    const jwt = isJwt ? uriOrJwt : (await this.parseAndResolveRequestUri(uriOrJwt)).requestObject;

    const origAuthorizationRequest = isJwt ? (parseJWT(jwt).payload as AuthorizationRequestPayload) : this.parseURI(uriOrJwt).authorizationRequest;
    let requestObjectPayload: RequestObjectPayload;
    let verifiedJwt: VerifiedJWT;
    if (isJwt) {
      // Put back the request object as that won't be present in the Jwt
      origAuthorizationRequest.request = jwt;
      const { header, payload } = parseJWT(origAuthorizationRequest.request);
      assertValidRequestJWT(header, payload);
      const options = {
        audience: getAudience(jwt),
      };

      verifiedJwt = await verifyDidJWT(jwt, getResolver(opts.verification.resolveOpts), options);
      if (!verifiedJwt || !verifiedJwt.payload) {
        throw Error(SIOPErrors.ERROR_VERIFYING_SIGNATURE);
      }
      requestObjectPayload = verifiedJwt.payload as RequestObjectPayload;
    }

    // AuthenticationRequest.assertValidRequestObject(origAuthenticationRequest);

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
    AuthenticationRequest.assertValidRegistrationObject(registrationMetadata);

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

  private static assertValidRegistrationObject(regObj: RPRegistrationMetadataPayload) {
    if (regObj && !validateRPRegistrationMetadata(regObj)) {
      throw new Error('Registration data validation error: ' + JSON.stringify(validateRPRegistrationMetadata.errors));
    } else if (regObj?.subject_syntax_types_supported && regObj.subject_syntax_types_supported.length == 0) {
      throw new Error(`${SIOPErrors.VERIFY_BAD_PARAMS}`);
    }
  }

  private static assertValidRequestObject(verPayload: RequestObjectPayload): void {
    if (verPayload['registration_uri'] || verPayload['registration']) {
      throw new Error(`${SIOPErrors.REG_OBJ_N_REG_URI_CANT_BE_SET_SIMULTANEOUSLY}`);
    }
  }

  /**
   * Creates an URI Request
   * @param opts Options to define the Uri Request
   * @param requestObject
   * @param jwt
   *
   */
  private static async createURIFromRequest(
    opts: AuthenticationRequestOpts,
    request: AuthorizationRequestPayload | string
  ): Promise<AuthorizationRequestURI> {
    const schema = 'openid://';
    const isJwt = typeof request === 'string';
    const requestObject = isJwt ? request : request.request;
    if (isJwt && (!requestObject || !requestObject.startsWith('ey'))) {
      throw Error(SIOPErrors.NO_JWT);
    }
    const requestObjectPayload: RequestObjectPayload = requestObject ? (decodeJWT(requestObject) as RequestObjectPayload) : undefined;

    // Only used to validate if it contains a presentation definition
    await PresentationExchange.findValidPresentationDefinitions(requestObjectPayload);

    AuthenticationRequest.assertValidRequestObject(requestObjectPayload);
    // fixme. This should not be fetched at all. We should inspect the opts
    /*const registrationMetadata: RPRegistrationMetadataPayload = await fetchByReferenceOrUseByValue(
      requestObject['registration_uri'],
      requestObject['registration']
    );
    AuthenticationRequest.assertValidRegistrationObject(registrationMetadata);*/
    const authorizationRequest: AuthorizationRequestPayload = isJwt ? (requestObjectPayload as AuthorizationRequestPayload) : request;
    if (!authorizationRequest) {
      throw Error(SIOPErrors.BAD_PARAMS);
    }
    const type = opts.requestBy?.type;
    if (!type) {
      throw new Error(SIOPErrors.REQUEST_OBJECT_TYPE_NOT_SET);
    }

    if (type === PassBy.REFERENCE) {
      if (!opts.requestBy.referenceUri) {
        throw new Error(SIOPErrors.NO_REFERENCE_URI);
      }
      authorizationRequest.request_uri = opts.requestBy.referenceUri;
      delete authorizationRequest.request;
    } else if (type === PassBy.VALUE) {
      authorizationRequest.request = requestObject;
      delete authorizationRequest.request_uri;
    }
    return {
      encodedUri: `${schema}?${encodeJsonAsURI(authorizationRequest)}`,
      encodingFormat: UrlEncodingFormat.FORM_URL_ENCODED,
      requestOpts: opts,
      authorizationRequest,
      requestObject,
    };
  }

  /**
   * Create a Authentication Request Payload from a URI string
   *
   * @param uri
   */
  private static parseURI(uri: string): { scheme: string; authorizationRequest: AuthorizationRequestPayload } {
    // We strip the uri scheme before passing it to the decode function
    const scheme: string = uri.match(/^.*:\/\/\??/)[0];
    const authorizationRequest = decodeUriAsJson(uri.replace(/^.*:\/\/\??/, '')) as AuthorizationRequestPayload;
    return { scheme, authorizationRequest };
  }

  private static async parseAndResolveRequestUri(uri: string) {
    const { authorizationRequest, scheme } = AuthenticationRequest.parseURI(uri);
    const requestObject = await fetchByReferenceOrUseByValue(authorizationRequest.request, authorizationRequest.request_uri);
    return { scheme, authorizationRequest, requestObject };
  }
}

/***************************************
 *
 * Helper functions are down below
 *
 ***************************************/

// eslint-disable-next-line @typescript-eslint/no-unused-vars
function assertValidRequestJWT(_header: JWTHeader, _payload: JWTPayload) {
  /*console.log(_header);
    console.log(_payload);*/
}

function assertValidVerifyOpts(opts: VerifyAuthenticationRequestOpts) {
  if (!opts || !opts.verification || (!isExternalVerification(opts.verification) && !isInternalVerification(opts.verification))) {
    throw new Error(SIOPErrors.VERIFY_BAD_PARAMS);
  }
}

function assertValidRequestOpts(opts: AuthenticationRequestOpts) {
  if (!opts || !opts.redirectUri) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  } else if (!opts.requestBy) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  } else if (opts.requestBy.type !== PassBy.REFERENCE && opts.requestBy.type !== PassBy.VALUE) {
    throw new Error(SIOPErrors.REQUEST_OBJECT_TYPE_NOT_SET);
  } else if (opts.requestBy.type === PassBy.REFERENCE && !opts.requestBy.referenceUri) {
    throw new Error(SIOPErrors.NO_REFERENCE_URI);
  }
  assertValidRequestRegistrationOpts(opts['registration']);
}

function createClaimsPayloadProperties(opts: ClaimOpts): ClaimPayload {
  if (!opts || !opts.vpToken || (!opts.vpToken.presentationDefinition && !opts.vpToken.presentationDefinitionUri)) {
    return undefined;
  }
  const pex: PEX = new PEX();
  const discoveryResult = pex.definitionVersionDiscovery(opts.vpToken.presentationDefinition);
  if (discoveryResult.error) {
    throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
  }

  return {
    ...(opts.idToken ? { id_token: opts.idToken } : {}),
    ...(opts.vpToken.presentationDefinition || opts.vpToken.presentationDefinitionUri
      ? {
          vp_token: {
            ...(opts.vpToken.presentationDefinition ? { presentation_definition: opts.vpToken.presentationDefinition } : {}),
            ...(opts.vpToken.presentationDefinitionUri ? { presentation_definition_uri: opts.vpToken.presentationDefinitionUri } : {}),
          },
        }
      : {}),
  };
}

async function createAuthorizationRequestPayload(opts: AuthenticationRequestOpts, requestObject?: string): Promise<AuthorizationRequestPayload> {
  assertValidRequestOpts(opts);
  if (opts.requestBy && opts.requestBy.type === PassBy.VALUE && !requestObject) {
    throw Error(SIOPErrors.NO_JWT);
  }
  const state = getState(opts.state);
  const registration = await createRequestRegistration(opts['registration']);
  const claims = createClaimsPayloadProperties(opts.claims);
  const clientId = opts.clientId ? opts.clientId : registration.requestRegistrationPayload.registration.client_id;

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
    ...registration.requestRegistrationPayload,
    claims,
  };
}

async function createRequestObjectPayload(opts: AuthenticationRequestOpts): Promise<RequestObjectPayload> {
  assertValidRequestOpts(opts);

  // todo restrict opts to request type
  const requestOpts = opts.requestBy?.request ? { ...opts, ...opts.requestBy.request } : opts;
  const state = getState(requestOpts.state);
  const registration = await createRequestRegistration(requestOpts['registration']);
  const claims = createClaimsPayloadProperties(requestOpts.claims);

  const clientId = requestOpts.clientId ? requestOpts.clientId : registration.requestRegistrationPayload.registration.client_id;

  return {
    response_type: ResponseType.ID_TOKEN,
    scope: Scope.OPENID,
    //TODO implement /.well-known/openid-federation support in the OP side to resolve the client_id (URL) and retrieve the metadata
    client_id: clientId ? clientId : requestOpts.signatureType.did,
    redirect_uri: requestOpts.redirectUri,
    response_mode: requestOpts.responseMode || ResponseMode.POST,
    id_token_hint: requestOpts.idTokenHint,
    registration_uri: requestOpts['registrationUri'],
    nonce: getNonce(state, requestOpts.nonce),
    state,
    ...registration.requestRegistrationPayload,
    claims,
  };
}
