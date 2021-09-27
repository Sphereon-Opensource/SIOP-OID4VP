export const AuthenticationResponseOptsSchema = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  $ref: '#/definitions/AuthenticationResponseOpts',
  definitions: {
    AuthenticationResponseOpts: {
      type: 'object',
      properties: {
        signatureType: {
          anyOf: [
            {
              $ref: '#/definitions/InternalSignature',
            },
            {
              $ref: '#/definitions/ExternalSignature',
            },
          ],
        },
        nonce: {
          type: 'string',
        },
        state: {
          type: 'string',
        },
        registration: {
          $ref: '#/definitions/ResponseRegistrationOpts',
        },
        responseMode: {
          $ref: '#/definitions/ResponseMode',
        },
        did: {
          type: 'string',
        },
        vp: {
          $ref: '#/definitions/VerifiablePresentation',
        },
        expiresIn: {
          type: 'number',
        },
      },
      required: ['signatureType', 'registration', 'did'],
      additionalProperties: false,
    },
    InternalSignature: {
      type: 'object',
      properties: {
        hexPrivateKey: {
          type: 'string',
        },
        did: {
          type: 'string',
        },
        kid: {
          type: 'string',
        },
      },
      required: ['hexPrivateKey', 'did'],
      additionalProperties: false,
    },
    ExternalSignature: {
      type: 'object',
      properties: {
        signatureUri: {
          type: 'string',
        },
        did: {
          type: 'string',
        },
        authZToken: {
          type: 'string',
        },
        hexPublicKey: {
          type: 'string',
        },
        kid: {
          type: 'string',
        },
      },
      required: ['signatureUri', 'did'],
      additionalProperties: false,
    },
    ResponseRegistrationOpts: {
      type: 'object',
      properties: {
        authorizationEndpoint: {
          type: 'string',
        },
        scopesSupported: {
          anyOf: [
            {
              type: 'array',
              items: {
                $ref: '#/definitions/Scope',
              },
            },
            {
              $ref: '#/definitions/Scope',
            },
          ],
        },
        subjectTypesSupported: {
          anyOf: [
            {
              type: 'array',
              items: {
                $ref: '#/definitions/SubjectType',
              },
            },
            {
              $ref: '#/definitions/SubjectType',
            },
          ],
        },
        idTokenSigningAlgValuesSupported: {
          anyOf: [
            {
              type: 'array',
              items: {
                $ref: '#/definitions/KeyAlgo',
              },
            },
            {
              $ref: '#/definitions/KeyAlgo',
            },
          ],
        },
        requestObjectSigningAlgValuesSupported: {
          anyOf: [
            {
              type: 'array',
              items: {
                $ref: '#/definitions/SigningAlgo',
              },
            },
            {
              $ref: '#/definitions/SigningAlgo',
            },
          ],
        },
        didsSupported: {
          type: 'boolean',
        },
        didMethodsSupported: {
          anyOf: [
            {
              type: 'array',
              items: {
                type: 'string',
              },
            },
            {
              type: 'string',
            },
          ],
        },
        credentialSupported: {
          type: 'boolean',
        },
        credentialEndpoint: {
          type: 'string',
        },
        credentialFormatsSupported: {
          anyOf: [
            {
              type: 'array',
              items: {
                $ref: '#/definitions/CredentialFormat',
              },
            },
            {
              $ref: '#/definitions/CredentialFormat',
            },
          ],
        },
        credentialClaimsSupported: {
          anyOf: [
            {
              type: 'array',
              items: {
                type: 'string',
              },
            },
            {
              type: 'string',
            },
          ],
        },
        credentialName: {
          type: 'string',
        },
        registrationBy: {
          $ref: '#/definitions/RegistrationType',
        },
      },
      required: ['registrationBy'],
      additionalProperties: false,
    },
    Scope: {
      type: 'string',
      enum: ['openid', 'openid did_authn'],
    },
    SubjectType: {
      type: 'string',
      enum: ['public', 'pairwise'],
    },
    KeyAlgo: {
      type: 'string',
      enum: ['EdDSA', 'RS256', 'ES256', 'ES256K'],
    },
    SigningAlgo: {
      type: 'string',
      enum: ['EdDSA', 'RS256', 'ES256', 'ES256K', 'none'],
    },
    CredentialFormat: {
      type: 'string',
      enum: ['w3cvc-jsonld', 'jwt'],
    },
    RegistrationType: {
      type: 'object',
      properties: {
        type: {
          type: 'string',
          enum: ['REFERENCE', 'VALUE'],
        },
        referenceUri: {
          type: 'string',
        },
        id_token_encrypted_response_alg: {
          $ref: '#/definitions/EncKeyAlgorithm',
        },
        id_token_encrypted_response_enc: {
          $ref: '#/definitions/EncSymmetricAlgorithmCode',
        },
      },
      additionalProperties: false,
      required: ['type'],
    },
    EncKeyAlgorithm: {
      type: 'string',
      const: 'ECDH-ES',
    },
    EncSymmetricAlgorithmCode: {
      type: 'string',
      const: 'XC20P',
    },
    ResponseMode: {
      type: 'string',
      enum: ['fragment', 'form_post', 'post', 'query'],
    },
    VerifiablePresentation: {
      type: 'object',
      properties: {
        '@context': {
          type: 'array',
          items: {
            type: 'string',
          },
        },
        type: {
          type: 'string',
        },
        verifiableCredential: {
          anyOf: [
            {
              type: 'array',
              items: {
                type: 'string',
              },
            },
            {
              type: 'array',
              items: {
                $ref: '#/definitions/VerifiableCredential',
              },
            },
          ],
        },
        proof: {
          $ref: '#/definitions/Proof',
        },
      },
      required: ['@context', 'proof', 'type', 'verifiableCredential'],
      additionalProperties: false,
    },
    VerifiableCredential: {
      type: 'object',
      properties: {
        '@context': {
          type: 'array',
          items: {
            type: 'string',
          },
        },
        id: {
          type: 'string',
        },
        type: {
          type: 'array',
          items: {
            type: 'string',
          },
        },
        credentialSubject: {
          $ref: '#/definitions/CredentialSubject',
        },
        issuer: {
          type: 'string',
        },
        issuanceDate: {
          type: 'string',
        },
        expirationDate: {
          type: 'string',
        },
        credentialStatus: {
          $ref: '#/definitions/CredentialStatus',
        },
        proof: {
          $ref: '#/definitions/Proof',
        },
      },
      required: ['@context', 'credentialSubject', 'id', 'issuanceDate', 'issuer', 'proof', 'type'],
    },
    CredentialSubject: {
      type: 'object',
      additionalProperties: {},
    },
    CredentialStatus: {
      type: 'object',
      properties: {
        id: {
          type: 'string',
        },
        type: {
          type: 'string',
        },
      },
      required: ['id', 'type'],
      additionalProperties: false,
    },
    Proof: {
      type: 'object',
      properties: {
        type: {
          type: 'string',
        },
        created: {
          type: 'string',
        },
        proofPurpose: {
          type: 'string',
        },
        verificationMethod: {
          type: 'string',
        },
        jws: {
          type: 'string',
        },
      },
      required: ['type', 'created', 'proofPurpose', 'verificationMethod', 'jws'],
      additionalProperties: {
        type: 'string',
      },
    },
  },
};
