import { JWTVerifyOptions } from 'did-jwt';
import { decodeJWT } from 'did-jwt';
import { JWTDecoded } from 'did-jwt/lib/JWT';
import forge from 'node-forge';

import { PresentationDefinitionWithLocation } from '../authorization-response';
import { PresentationExchange } from '../authorization-response/PresentationExchange';
import { getAudience, getResolver, parseJWT, verifyDidJWT } from '../did';
import { fetchByReferenceOrUseByValue, removeNullUndefined } from '../helpers';
import { authorizationRequestVersionDiscovery } from '../helpers/SIOPSpecVersion';
import { RequestObject } from '../request-object';
import {
  AuthorizationRequestPayload,
  PassBy,
  RequestObjectJwt,
  RequestObjectPayload,
  RequestStateInfo,
  ResponseType,
  ResponseURIType,
  RPRegistrationMetadataPayload,
  Schema,
  SIOPErrors,
  SupportedVersion,
  VerifiedAuthorizationRequest,
  VerifiedJWT,
} from '../types';

import { assertValidAuthorizationRequestOpts, assertValidVerifyAuthorizationRequestOpts } from './Opts';
import { assertValidRPRegistrationMedataPayload, checkWellknownDIDFromRequest, createAuthorizationRequestPayload } from './Payload';
import { URI } from './URI';
import { CreateAuthorizationRequestOpts, VerifyAuthorizationRequestOpts } from './types';

export class AuthorizationRequest {
  private readonly _requestObject?: RequestObject;
  private readonly _payload: AuthorizationRequestPayload;
  private readonly _options: CreateAuthorizationRequestOpts;
  private _uri: URI;

  private constructor(payload: AuthorizationRequestPayload, requestObject?: RequestObject, opts?: CreateAuthorizationRequestOpts, uri?: URI) {
    this._options = opts;
    this._payload = removeNullUndefined(payload);
    this._requestObject = requestObject;
    this._uri = uri;
  }

  public static async fromUriOrJwt(jwtOrUri: string | URI): Promise<AuthorizationRequest> {
    if (!jwtOrUri) {
      throw Error(SIOPErrors.NO_REQUEST);
    }
    return typeof jwtOrUri === 'string' && jwtOrUri.startsWith('ey')
      ? await AuthorizationRequest.fromJwt(jwtOrUri)
      : await AuthorizationRequest.fromURI(jwtOrUri);
  }

  public static async fromPayload(payload: AuthorizationRequestPayload): Promise<AuthorizationRequest> {
    if (!payload) {
      throw Error(SIOPErrors.NO_REQUEST);
    }
    const requestObject = await RequestObject.fromAuthorizationRequestPayload(payload);
    return new AuthorizationRequest(payload, requestObject);
  }

  public static async fromOpts(opts: CreateAuthorizationRequestOpts, requestObject?: RequestObject): Promise<AuthorizationRequest> {
    // todo: response_uri/redirect_uri is not hooked up from opts!
    if (!opts || !opts.requestObject) {
      throw Error(SIOPErrors.BAD_PARAMS);
    }
    assertValidAuthorizationRequestOpts(opts);

    const requestObjectArg =
      opts.requestObject.passBy !== PassBy.NONE ? (requestObject ? requestObject : await RequestObject.fromOpts(opts)) : undefined;
    const requestPayload = opts?.payload ? await createAuthorizationRequestPayload(opts, requestObjectArg) : undefined;
    return new AuthorizationRequest(requestPayload, requestObjectArg, opts);
  }

  get payload(): AuthorizationRequestPayload {
    return this._payload;
  }

  get requestObject(): RequestObject | undefined {
    return this._requestObject;
  }

  get options(): CreateAuthorizationRequestOpts | undefined {
    return this._options;
  }

  public hasRequestObject(): boolean {
    return this.requestObject !== undefined;
  }

  public async getSupportedVersion() {
    if (this.options?.version) {
      return this.options.version;
    } else if (this._uri?.encodedUri?.startsWith(Schema.OPENID_VC) || this._uri?.scheme?.startsWith(Schema.OPENID_VC)) {
      return SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1;
    }

    return (await this.getSupportedVersionsFromPayload())[0];
  }

  public async getSupportedVersionsFromPayload(): Promise<SupportedVersion[]> {
    const mergedPayload = { ...this.payload, ...(await this.requestObject?.getPayload()) };
    return authorizationRequestVersionDiscovery(mergedPayload);
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
   * @param opts
   */
  async verify(opts: VerifyAuthorizationRequestOpts): Promise<VerifiedAuthorizationRequest> {
    assertValidVerifyAuthorizationRequestOpts(opts);

    let requestObjectPayload: RequestObjectPayload;
    let verifiedJwt: VerifiedJWT;

    const jwt = await this.requestObjectJwt();
    if (jwt) {
      const parsedJWT = parseJWT(jwt);
      const payload = parsedJWT.payload;
      const audience = getAudience(jwt);
      const resolver = getResolver(opts.verification.resolveOpts);
      const options: JWTVerifyOptions = {
        ...opts.verification?.resolveOpts?.jwtVerifyOpts,
        resolver,
        audience,
      };

      if (payload.client_id?.startsWith('http') && payload.iss.startsWith('http') && payload.iss === payload.client_id) {
        console.error(`FIXME: The client_id and iss are not DIDs. We do not verify the signature in this case yet! ${payload.iss}`);
        verifiedJwt = { payload, jwt, issuer: payload.iss };
      } else {
        verifiedJwt = await verifyDidJWT(jwt, resolver, options);
      }
      if (!verifiedJwt || !verifiedJwt.payload) {
        throw Error(SIOPErrors.ERROR_VERIFYING_SIGNATURE);
      }
      requestObjectPayload = verifiedJwt.payload as RequestObjectPayload;

      if (this.hasRequestObject() && !this.payload.request_uri) {
        // Put back the request object as that won't be present yet
        this.payload.request = jwt;
      }
    }

    // AuthorizationRequest.assertValidRequestObject(origAuthenticationRequest);

    // We use the orig request for default values, but the JWT payload contains signed request object properties
    const mergedPayload = { ...this.payload, ...requestObjectPayload };
    if (opts.state && mergedPayload.state !== opts.state) {
      throw new Error(`${SIOPErrors.BAD_STATE} payload: ${mergedPayload.state}, supplied: ${opts.state}`);
    } else if (opts.nonce && mergedPayload.nonce !== opts.nonce) {
      throw new Error(`${SIOPErrors.BAD_NONCE} payload: ${mergedPayload.nonce}, supplied: ${opts.nonce}`);
    }

    const registrationPropertyKey = mergedPayload['registration'] || mergedPayload['registration_uri'] ? 'registration' : 'client_metadata';
    let registrationMetadataPayload: RPRegistrationMetadataPayload;
    if (mergedPayload[registrationPropertyKey] || mergedPayload[`${registrationPropertyKey}_uri`]) {
      registrationMetadataPayload = await fetchByReferenceOrUseByValue(
        mergedPayload[`${registrationPropertyKey}_uri`],
        mergedPayload[registrationPropertyKey],
      );
      assertValidRPRegistrationMedataPayload(registrationMetadataPayload);
      // TODO: We need to do something with the metadata probably
    }
    // When the response_uri parameter is present, the redirect_uri Authorization Request parameter MUST NOT be present. If the redirect_uri Authorization Request parameter is present when the Response Mode is direct_post, the Wallet MUST return an invalid_request Authorization Response error.
    let responseURIType: ResponseURIType;
    let responseURI: string;
    if (mergedPayload.redirect_uri && mergedPayload.response_uri) {
      throw new Error(`${SIOPErrors.INVALID_REQUEST}, redirect_uri cannot be used together with response_uri`);
    } else if (mergedPayload.redirect_uri) {
      responseURIType = 'redirect_uri';
      responseURI = mergedPayload.redirect_uri;
    } else if (mergedPayload.response_uri) {
      responseURIType = 'response_uri';
      responseURI = mergedPayload.response_uri;
    } else if (mergedPayload.client_id_scheme === 'redirect_uri' && mergedPayload.client_id) {
      responseURIType = 'redirect_uri';
      responseURI = mergedPayload.client_id;
    } else {
      throw new Error(`${SIOPErrors.INVALID_REQUEST}, redirect_uri or response_uri is needed`);
    }

    if (mergedPayload.client_id_scheme === 'verifier_attestation') {
      verifiedJwt = await AuthorizationRequest.verifyAttestationJWT(jwt, mergedPayload.client_id);
    } else if (mergedPayload.client_id_scheme === 'x509_san_dns') {
      await this.checkX509SanDNSScheme(jwt, mergedPayload.client_id);
    } else if (mergedPayload.client_id_scheme === 'x509_san_uri') {
      throw new Error(SIOPErrors.VERIFICATION_X509_SAN_URI_SCHEME_NOT_IMPLEMENTED_ERROR)
    }
    await checkWellknownDIDFromRequest(mergedPayload, opts);

    const presentationDefinitions = await PresentationExchange.findValidPresentationDefinitions(mergedPayload, await this.getSupportedVersion());
    return {
      ...verifiedJwt,
      responseURIType,
      responseURI,
      clientIdScheme: mergedPayload.client_id_scheme,
      correlationId: opts.correlationId,
      authorizationRequest: this,
      verifyOpts: opts,
      presentationDefinitions,
      registrationMetadataPayload,
      requestObject: this.requestObject,
      authorizationRequestPayload: this.payload,
      versions: await this.getSupportedVersionsFromPayload(),
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

  public async toStateInfo(): Promise<RequestStateInfo> {
    const requestObject = await this.requestObject.getPayload();
    return {
      client_id: this.options.clientMetadata.client_id,
      iat: requestObject.iat ?? this.payload.iat,
      nonce: requestObject.nonce ?? this.payload.nonce,
      state: this.payload.state,
    };
  }

  /**
   * Verifies a JWT according to the 'verifier_attestation' client_id_scheme, where the JWT must be
   * signed with a private key corresponding to the public key specified within the JWT itself. This method
   * ensures that the JWT's 'sub' claim matches the provided clientId, and it extracts and validates the
   * public key from the JWT's 'cnf' (confirmation) claim, which must contain a JWK.
   *
   * @param jwt The JSON Web Token string to be verified. It is expected that this JWT is formatted correctly
   *            and includes a 'cnf' claim with a JWK representing the public key used for signing the JWT.
   * @param clientId The client identifier expected to match the 'sub' claim in the JWT. This is used to
   *                 validate that the JWT is intended for the correct recipient/client.
   */
  private static async verifyAttestationJWT(jwt: string, clientId: string): Promise<VerifiedJWT> {
    if (!jwt) {
      throw new Error(SIOPErrors.NO_JWT);
    }
    const payload = decodeJWT(jwt);
    const sub = payload['sub'];
    const cnf = payload['cnf'];

    if (sub !== clientId || !cnf || typeof cnf !== 'object' || !cnf['jwk'] || typeof cnf['jwk'] !== 'object') {
      throw new Error(SIOPErrors.VERIFICATION_VERIFIER_ATTESTATION_SCHEME_ERROR);
    }

    return {
      jwt,
      payload: payload.payload,
      issuer: payload['iss'],
      jwk: cnf['jwk'],
    };
  }

  /**
   * verifying JWTs against X.509 certificates focusing on DNS SAN compliance, which is crucial for environments where certificate-based security is pivotal.
   * @param jwt The encoded JWT from which the certificate needs to be extracted.
   * @param clientId The DNS name to match against the certificate's SANs.
   */
  private async checkX509SanDNSScheme(jwt: string, clientId: string): Promise<void> {
    const jwtDecoded: JWTDecoded = decodeJWT(jwt);
    const x5c = jwtDecoded.header['x5c'];

    if (x5c == null || !Array.isArray(x5c) || x5c.length === 0) {
      throw new Error(SIOPErrors.VERIFICATION_X509_SAN_DNS_SCHEME_ERROR);
    }

    const certificate = x5c[0];
    if (!certificate) {
      throw new Error(SIOPErrors.VERIFICATION_X509_SAN_DNS_SCHEME_NO_CERTIFICATE_ERROR);
    }

    const der = forge.util.decode64(certificate);
    const asn1 = forge.asn1.fromDer(der);
    const cert = forge.pki.certificateFromAsn1(asn1);

    const subjectAltNames = cert.getExtension('subjectAltName');
    if (!subjectAltNames || !Array.isArray(subjectAltNames['altNames'])) {
      throw new Error(SIOPErrors.VERIFICATION_X509_SAN_DNS_ALT_NAMES_ERROR);
    }
    if (!subjectAltNames || !subjectAltNames['altNames'].some((name: any) => name.value === clientId)) {
      throw new Error(SIOPErrors.VERIFICATION_X509_SAN_DNS_SCHEME_DNS_NAME_MATCH);
    }
  }

  public async containsResponseType(singleType: ResponseType | string): Promise<boolean> {
    const responseType: string = await this.getMergedProperty('response_type');
    return responseType?.includes(singleType) === true;
  }

  public async getMergedProperty<T>(key: string): Promise<T | undefined> {
    const merged = await this.mergedPayloads();
    return merged[key] as T;
  }

  public async mergedPayloads(): Promise<RequestObjectPayload> {
    return { ...this.payload, ...(this.requestObject && (await this.requestObject.getPayload())) };
  }

  public async getPresentationDefinitions(version?: SupportedVersion): Promise<PresentationDefinitionWithLocation[] | undefined> {
    return await PresentationExchange.findValidPresentationDefinitions(await this.mergedPayloads(), version);
  }
}
