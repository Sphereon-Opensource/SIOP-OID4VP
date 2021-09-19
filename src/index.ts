import AuthenticationRequest from './AuthenticationRequest';
import * as RPRegistrationMetadata from './AuthenticationRequestRegistration';
import AuthenticationResponse from './AuthenticationResponse';
import * as RPAuthService from './RPAuthService';
import * as RPSession from './RPSession';
import { Encodings as DidAuthHexUtils, Keys as DidAuthKeyUtils } from './functions';
import { SIOP } from './types';

export { JWTHeader, JWTPayload, JWTOptions, JWTVerifyOptions } from 'did-jwt/lib/JWT';
export {
  AuthenticationRequest,
  AuthenticationResponse,
  RPAuthService,
  RPSession,
  RPRegistrationMetadata,
  SIOP,
  DidAuthHexUtils,
  DidAuthKeyUtils,
};
