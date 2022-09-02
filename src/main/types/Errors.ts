enum SIOPErrors {
  AUTH_REQUEST_EXPECTS_VP = 'authentication request expects a verifiable presentation in the response',
  AUTH_REQUEST_DOESNT_EXPECT_VP = "authentication request doesn't expect a verifiable presentation in the response",
  BAD_INTERNAL_VERIFICATION_PARAMS = 'Error: One of the either didUrlResolver or both registry and rpcUrl must be set',
  BAD_NONCE = 'The nonce in the payload does not match the supplied nonce',
  BAD_PARAMS = 'Wrong parameters provided.',
  BAD_SIGNATURE_PARAMS = 'Signature parameters should be internal signature with hexPrivateKey, did, and an optional kid, or external signature parameters with signatureUri, did, and optionals parameters authZToken, hexPublicKey, and kid',
  CANT_UNMARSHAL_JWT_VP = "can't unmarshal the presentation object",
  NO_PRESENTATION_SUBMISSION = 'The VP did not contain a presentation submission. Did you forget to call PresentationExchange.checkSubmissionFrom?',
  CREDENTIAL_FORMATS_NOT_SUPPORTED = 'CREDENTIAL_FORMATS_NOT_SUPPORTED',
  CREDENTIALS_FORMATS_NOT_PROVIDED = 'Credentials format not provided by RP/OP',
  COULD_NOT_FIND_VCS_MATCHING_PD = 'Could not find VerifiableCredentials matching presentationDefinition object in the provided VC list',
  DIDAUTH_REQUEST_PAYLOAD_NOT_CREATED = 'DidAuthRequestPayload not created',
  DID_METHODS_NOT_SUPORTED = 'DID_METHODS_NOT_SUPPORTED',
  EVALUATE_PRSENTATION_EXCHANGE_FAILED = 'Evaluation of presentation definition from the request against the Verifiable Presentation failed.',
  ERROR_ON_POST_CALL = 'Error on Post call: ',
  ERROR_RETRIEVING_DID_DOCUMENT = 'Error retrieving did document',
  ERROR_RETRIEVING_VERIFICATION_METHOD = 'Error retrieving verificaton method from did document',
  ERROR_VALIDATING_NONCE = 'Error validating nonce.',
  ERROR_VERIFYING_SIGNATURE = 'Error verifying the DID Auth Token signature.',
  EXPIRED = 'The token has expired',
  INVALID_AUDIENCE = 'Audience is invalid. Should be a string value.',
  ISS_DID_NOT_JWKS_URI_DID = ' DID in the jwks_uri does NOT match the DID in the iss claim',
  JWK_THUMBPRINT_MISMATCH_SUB = 'JWK computed thumbprint does not match thumbprint included in Response Token sub claim',
  LINK_DOMAIN_CANT_BE_VERIFIED = "Can't verify linked domains.",
  MALFORMED_SIGNATURE_RESPONSE = 'Response format is malformed',
  NO_ALG_SUPPORTED = 'Algorithm not supported.',
  NO_ALG_SUPPORTED_YET = 'Algorithm is not supported yet. Only ES256 supported for this version.',
  NO_AUDIENCE = 'No audience found in JWT payload',
  NO_DID_PAYLOAD = 'payload must contain did field in payload for self-issued tokens',
  NO_IDENTIFIERS_URI = 'identifiersUri must be defined to get the publick key',
  NO_ISS_DID = 'Token does not have a iss DID',
  NO_JWT = 'no JWT was supplied',
  NO_KEY_CURVE_SUPPORTED = 'Key Curve not supported.',
  NO_NONCE = 'No nonce found in JWT payload',
  NO_REFERENCE_URI = 'referenceUri must be defined when REFERENCE option is used',
  NO_SELFISSUED_ISS = 'The Response Token Issuer Claim (iss) MUST be https://self-isued.me',
  NO_SUB_TYPE = 'No or empty sub_type found in JWT payload',
  REGISTRATION_NOT_SET = 'Registration metadata not set.',
  REQUEST_CLAIMS_PRESENTATION_DEFINITION_BY_REF_AND_VALUE_NON_EXCLUSIVE = "Request claims can't have both 'presentation_definition' and 'presentation_definition_uri'",
  REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID = 'Presentation definition in the request claims is not valid',
  REQUEST_OBJECT_TYPE_NOT_SET = 'Request object type is not set.',
  RESPONSE_AUD_MISMATCH_REDIRECT_URI = 'The audience (aud) in Response Token does NOT match the redirect_uri value sent in the Authentication Request',
  RESPONSE_OPTS_MUST_CONTAIN_VERIFIABLE_CREDENTIALS_AND_HOLDER_DID = "Since the request has a presentation definition, response must contain verifiable credentials and holder's did",
  RESPONSE_OPTS_PRESENTATIONS_SUBMISSION_IS_NOT_VALID = 'presentation_submission object inside the response opts vp should be valid',
  RESPONSE_STATUS_UNEXPECTED = 'Received unexpected respons status',
  REG_OBJ_N_REG_URI_CANT_BE_SET_SIMULTANEOUSLY = 'Registration can either be passed by value or passed by reference. Hence, registration object and registration URI can not be set simultaneously',
  REG_OBJ_MALFORMED = 'The registration object is malformed.',
  REG_PASS_BY_REFERENCE_INCORRECTLY = 'The registration by reference should always have a valid URL',
  REGISTRATION_OBJECT_TYPE_NOT_SET = 'Registration object type is not set.',
  SIGNATURE_OBJECT_TYPE_NOT_SET = 'Signature object type is not set.',
  SUB_JWK_NOT_FOUND_OR_NOT_KID = 'Response Token does not contains sub_jwk claim or sub_jwk does not contain kid attribute.',
  VERIFIABLE_PRESENTATION_FORMAT_NOT_SUPPORTED = "This type of verifiable presentation isn't supported in this version",
  VERIFICATION_METHOD_NOT_SUPPORTED = 'Verification method not supported',
  VERIFICATION_METHOD_NO_MATCH = "The verification method from the RP's DID Document does NOT match the kid of the SIOP Request",
  VERIFY_BAD_PARAMS = 'Verify bad parameters',
}

export default SIOPErrors;
