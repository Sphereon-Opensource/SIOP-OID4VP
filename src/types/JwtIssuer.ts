import { AuthorizationResponseOpts } from '../authorization-response';
import { JwtType } from '../helpers/jwtUtils';

import { JwtHeader, JwtPayload } from './JWT.types';
import { ClientIdScheme, SigningAlgo } from './SIOP.types';

interface IssuanceContextBase {
  type: JwtType;
}

interface RequestObjectContext extends IssuanceContextBase {
  type: 'request-object';
}

interface IdTokenContext extends IssuanceContextBase {
  type: 'id-token';
  authorizationResponseOpts: AuthorizationResponseOpts;
}

export type JwtIssuanceContext = RequestObjectContext | IdTokenContext;

interface JwtIssuerDid {
  method: 'did';

  didUrl: string;
  alg: SigningAlgo;
}

interface JwtIssuerX5c {
  method: 'x5c';

  /**
   *
   * Array of base64-encoded certificate strings in the DER-format.
   *
   * The certificate containing the public key corresponding to the key used to digitally sign the JWS MUST be the first certificate.
   */
  chain: Array<string>;

  /**
   * The issuer jwt
   *
   * This value will be used as the iss value of the issue jwt.
   * It is also used as the client_id.
   * And will also be set as the redirect_uri
   *
   * It must match an entry in the x5c certificate leaf entry dnsName / uriName
   */
  issuer: string;

  clientIdScheme: ClientIdScheme;
}

interface JwtIssuerJwk {
  method: 'jwk';

  jwk: JsonWebKey;
}

interface JwtIssuerCustom extends Record<string, unknown> {
  method: 'custom';
}

export type JwtIssuer = JwtIssuerDid | JwtIssuerX5c | JwtIssuerJwk | JwtIssuerCustom;
export type JwtIssuerWithContext = JwtIssuer & JwtIssuanceContext;

export type CreateJwtCallback = <Issuer extends JwtIssuerWithContext>(
  jwtIssuer: Issuer,
  jwt: { header: JwtHeader; payload: JwtPayload },
) => Promise<string>;
