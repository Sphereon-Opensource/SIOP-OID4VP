export const AuthenticationResponseOptsSchema = {
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$ref": "#/definitions/AuthenticationResponseOpts",
  "definitions": {
    "AuthenticationResponseOpts": {
      "type": "object",
      "properties": {
        "redirectUri": {
          "type": "string"
        },
        "registration": {
          "$ref": "#/definitions/ResponseRegistrationOpts"
        },
        "checkLinkedDomain": {
          "$ref": "#/definitions/CheckLinkedDomain"
        },
        "presentationVerificationCallback": {
          "$ref": "#/definitions/PresentationVerificationCallback"
        },
        "presentationSignCallback": {
          "$ref": "#/definitions/PresentationSignCallback"
        },
        "signatureType": {
          "anyOf": [
            {
              "$ref": "#/definitions/InternalSignature"
            },
            {
              "$ref": "#/definitions/ExternalSignature"
            },
            {
              "$ref": "#/definitions/SuppliedSignature"
            }
          ]
        },
        "nonce": {
          "type": "string"
        },
        "state": {
          "type": "string"
        },
        "responseMode": {
          "$ref": "#/definitions/ResponseMode"
        },
        "did": {
          "type": "string"
        },
        "vp": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/VerifiablePresentationResponseOpts"
          }
        },
        "expiresIn": {
          "type": "number"
        },
        "accessToken": {
          "type": "string"
        },
        "tokenType": {
          "type": "string"
        },
        "refreshToken": {
          "type": "string"
        }
      },
      "required": [
        "registration",
        "signatureType",
        "did"
      ],
      "additionalProperties": false
    },
    "ResponseRegistrationOpts": {
      "anyOf": [
        {
          "type": "object",
          "properties": {
            "registrationBy": {
              "$ref": "#/definitions/RegistrationType"
            },
            "authorizationEndpoint": {
              "anyOf": [
                {
                  "$ref": "#/definitions/Schema"
                },
                {
                  "type": "string"
                }
              ]
            },
            "issuer": {
              "anyOf": [
                {
                  "$ref": "#/definitions/ResponseIss"
                },
                {
                  "type": "string"
                }
              ]
            },
            "responseTypesSupported": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/ResponseType"
              }
            },
            "scopesSupported": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/Scope"
              }
            },
            "subjectTypesSupported": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/SubjectType"
              }
            },
            "idTokenSigningAlgValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/SigningAlgo"
                  }
                },
                {
                  "$ref": "#/definitions/SigningAlgo"
                }
              ]
            },
            "requestObjectSigningAlgValuesSupported": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/SigningAlgo"
              }
            },
            "subjectSyntaxTypesSupported": {
              "type": "array",
              "items": {
                "type": "string"
              }
            },
            "tokenEndpoint": {
              "type": "string"
            },
            "userinfoEndpoint": {
              "type": "string"
            },
            "jwksUri": {
              "type": "string"
            },
            "registrationEndpoint": {
              "type": "string"
            },
            "responseModesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/ResponseMode"
                  }
                },
                {
                  "$ref": "#/definitions/ResponseMode"
                }
              ]
            },
            "grantTypesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/GrantType"
                  }
                },
                {
                  "$ref": "#/definitions/GrantType"
                }
              ]
            },
            "acrValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/AuthenticationContextReferences"
                  }
                },
                {
                  "$ref": "#/definitions/AuthenticationContextReferences"
                }
              ]
            },
            "idTokenEncryptionAlgValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/KeyAlgo"
                  }
                },
                {
                  "$ref": "#/definitions/KeyAlgo"
                }
              ]
            },
            "idTokenEncryptionEncValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "userinfoSigningAlgValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/SigningAlgo"
                  }
                },
                {
                  "$ref": "#/definitions/SigningAlgo"
                }
              ]
            },
            "userinfoEncryptionAlgValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/SigningAlgo"
                  }
                },
                {
                  "$ref": "#/definitions/SigningAlgo"
                }
              ]
            },
            "userinfoEncryptionEncValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "requestObjectEncryptionAlgValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/SigningAlgo"
                  }
                },
                {
                  "$ref": "#/definitions/SigningAlgo"
                }
              ]
            },
            "requestObjectEncryptionEncValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "tokenEndpointAuthMethodsSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/TokenEndpointAuthMethod"
                  }
                },
                {
                  "$ref": "#/definitions/TokenEndpointAuthMethod"
                }
              ]
            },
            "tokenEndpointAuthSigningAlgValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/SigningAlgo"
                  }
                },
                {
                  "$ref": "#/definitions/SigningAlgo"
                }
              ]
            },
            "displayValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "claimTypesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/ClaimType"
                  }
                },
                {
                  "$ref": "#/definitions/ClaimType"
                }
              ]
            },
            "claimsSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "serviceDocumentation": {
              "type": "string"
            },
            "claimsLocalesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "uiLocalesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "claimsParameterSupported": {
              "type": "boolean"
            },
            "requestParameterSupported": {
              "type": "boolean"
            },
            "requestUriParameterSupported": {
              "type": "boolean"
            },
            "requireRequestUriRegistration": {
              "type": "boolean"
            },
            "opPolicyUri": {
              "type": "string"
            },
            "opTosUri": {
              "type": "string"
            },
            "clientId": {
              "type": "string"
            },
            "redirectUris": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "clientName": {
              "type": "string"
            },
            "tokenEndpointAuthMethod": {
              "type": "string"
            },
            "applicationType": {
              "type": "string"
            },
            "responseTypes": {
              "type": "string"
            },
            "grantTypes": {
              "type": "string"
            },
            "vpFormats": {
              "$ref": "#/definitions/Format"
            },
            "logoUri": {
              "type": "string"
            },
            "clientPurpose": {
              "type": "string"
            }
          },
          "required": [
            "registrationBy"
          ]
        },
        {
          "type": "object",
          "properties": {
            "registrationBy": {
              "$ref": "#/definitions/RegistrationType"
            },
            "authorizationEndpoint": {
              "anyOf": [
                {
                  "$ref": "#/definitions/Schema"
                },
                {
                  "type": "string"
                }
              ]
            },
            "issuer": {
              "anyOf": [
                {
                  "$ref": "#/definitions/ResponseIss"
                },
                {
                  "type": "string"
                }
              ]
            },
            "responseTypesSupported": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/ResponseType"
              }
            },
            "scopesSupported": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/Scope"
              }
            },
            "subjectTypesSupported": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/SubjectType"
              }
            },
            "idTokenSigningAlgValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/SigningAlgo"
                  }
                },
                {
                  "$ref": "#/definitions/SigningAlgo"
                }
              ]
            },
            "requestObjectSigningAlgValuesSupported": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/SigningAlgo"
              }
            },
            "subjectSyntaxTypesSupported": {
              "type": "array",
              "items": {
                "type": "string"
              }
            },
            "tokenEndpoint": {
              "type": "string"
            },
            "userinfoEndpoint": {
              "type": "string"
            },
            "jwksUri": {
              "type": "string"
            },
            "registrationEndpoint": {
              "type": "string"
            },
            "responseModesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/ResponseMode"
                  }
                },
                {
                  "$ref": "#/definitions/ResponseMode"
                }
              ]
            },
            "grantTypesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/GrantType"
                  }
                },
                {
                  "$ref": "#/definitions/GrantType"
                }
              ]
            },
            "acrValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/AuthenticationContextReferences"
                  }
                },
                {
                  "$ref": "#/definitions/AuthenticationContextReferences"
                }
              ]
            },
            "idTokenEncryptionAlgValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/KeyAlgo"
                  }
                },
                {
                  "$ref": "#/definitions/KeyAlgo"
                }
              ]
            },
            "idTokenEncryptionEncValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "userinfoSigningAlgValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/SigningAlgo"
                  }
                },
                {
                  "$ref": "#/definitions/SigningAlgo"
                }
              ]
            },
            "userinfoEncryptionAlgValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/SigningAlgo"
                  }
                },
                {
                  "$ref": "#/definitions/SigningAlgo"
                }
              ]
            },
            "userinfoEncryptionEncValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "requestObjectEncryptionAlgValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/SigningAlgo"
                  }
                },
                {
                  "$ref": "#/definitions/SigningAlgo"
                }
              ]
            },
            "requestObjectEncryptionEncValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "tokenEndpointAuthMethodsSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/TokenEndpointAuthMethod"
                  }
                },
                {
                  "$ref": "#/definitions/TokenEndpointAuthMethod"
                }
              ]
            },
            "tokenEndpointAuthSigningAlgValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/SigningAlgo"
                  }
                },
                {
                  "$ref": "#/definitions/SigningAlgo"
                }
              ]
            },
            "displayValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "claimTypesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/ClaimType"
                  }
                },
                {
                  "$ref": "#/definitions/ClaimType"
                }
              ]
            },
            "claimsSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "serviceDocumentation": {
              "type": "string"
            },
            "claimsLocalesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "uiLocalesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "claimsParameterSupported": {
              "type": "boolean"
            },
            "requestParameterSupported": {
              "type": "boolean"
            },
            "requestUriParameterSupported": {
              "type": "boolean"
            },
            "requireRequestUriRegistration": {
              "type": "boolean"
            },
            "opPolicyUri": {
              "type": "string"
            },
            "opTosUri": {
              "type": "string"
            },
            "clientId": {
              "type": "string"
            },
            "redirectUris": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "clientName": {
              "type": "string"
            },
            "tokenEndpointAuthMethod": {
              "type": "string"
            },
            "applicationType": {
              "type": "string"
            },
            "responseTypes": {
              "type": "string"
            },
            "grantTypes": {
              "type": "string"
            },
            "vpFormats": {
              "$ref": "#/definitions/Format"
            }
          },
          "required": [
            "registrationBy"
          ]
        },
        {
          "type": "object",
          "properties": {
            "registrationBy": {
              "$ref": "#/definitions/RegistrationType"
            },
            "authorizationEndpoint": {
              "anyOf": [
                {
                  "$ref": "#/definitions/Schema"
                },
                {
                  "type": "string"
                }
              ]
            },
            "issuer": {
              "anyOf": [
                {
                  "$ref": "#/definitions/ResponseIss"
                },
                {
                  "type": "string"
                }
              ]
            },
            "responseTypesSupported": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/ResponseType"
              }
            },
            "scopesSupported": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/Scope"
              }
            },
            "subjectTypesSupported": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/SubjectType"
              }
            },
            "idTokenSigningAlgValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/SigningAlgo"
                  }
                },
                {
                  "$ref": "#/definitions/SigningAlgo"
                }
              ]
            },
            "requestObjectSigningAlgValuesSupported": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/SigningAlgo"
              }
            },
            "subjectSyntaxTypesSupported": {
              "type": "array",
              "items": {
                "type": "string"
              }
            },
            "tokenEndpoint": {
              "type": "string"
            },
            "userinfoEndpoint": {
              "type": "string"
            },
            "jwksUri": {
              "type": "string"
            },
            "registrationEndpoint": {
              "type": "string"
            },
            "responseModesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/ResponseMode"
                  }
                },
                {
                  "$ref": "#/definitions/ResponseMode"
                }
              ]
            },
            "grantTypesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/GrantType"
                  }
                },
                {
                  "$ref": "#/definitions/GrantType"
                }
              ]
            },
            "acrValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/AuthenticationContextReferences"
                  }
                },
                {
                  "$ref": "#/definitions/AuthenticationContextReferences"
                }
              ]
            },
            "idTokenEncryptionAlgValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/KeyAlgo"
                  }
                },
                {
                  "$ref": "#/definitions/KeyAlgo"
                }
              ]
            },
            "idTokenEncryptionEncValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "userinfoSigningAlgValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/SigningAlgo"
                  }
                },
                {
                  "$ref": "#/definitions/SigningAlgo"
                }
              ]
            },
            "userinfoEncryptionAlgValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/SigningAlgo"
                  }
                },
                {
                  "$ref": "#/definitions/SigningAlgo"
                }
              ]
            },
            "userinfoEncryptionEncValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "requestObjectEncryptionAlgValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/SigningAlgo"
                  }
                },
                {
                  "$ref": "#/definitions/SigningAlgo"
                }
              ]
            },
            "requestObjectEncryptionEncValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "tokenEndpointAuthMethodsSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/TokenEndpointAuthMethod"
                  }
                },
                {
                  "$ref": "#/definitions/TokenEndpointAuthMethod"
                }
              ]
            },
            "tokenEndpointAuthSigningAlgValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/SigningAlgo"
                  }
                },
                {
                  "$ref": "#/definitions/SigningAlgo"
                }
              ]
            },
            "displayValuesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "claimTypesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/ClaimType"
                  }
                },
                {
                  "$ref": "#/definitions/ClaimType"
                }
              ]
            },
            "claimsSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "serviceDocumentation": {
              "type": "string"
            },
            "claimsLocalesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "uiLocalesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                {
                  "type": "string"
                }
              ]
            },
            "claimsParameterSupported": {
              "type": "boolean"
            },
            "requestParameterSupported": {
              "type": "boolean"
            },
            "requestUriParameterSupported": {
              "type": "boolean"
            },
            "requireRequestUriRegistration": {
              "type": "boolean"
            },
            "opPolicyUri": {
              "type": "string"
            },
            "opTosUri": {
              "type": "string"
            },
            "idTokenTypesSupported": {
              "anyOf": [
                {
                  "type": "array",
                  "items": {
                    "$ref": "#/definitions/IdTokenType"
                  }
                },
                {
                  "$ref": "#/definitions/IdTokenType"
                }
              ]
            },
            "vpFormatsSupported": {
              "$ref": "#/definitions/Format"
            }
          },
          "required": [
            "registrationBy"
          ]
        }
      ]
    },
    "RegistrationType": {
      "type": "object",
      "properties": {
        "type": {
          "type": "string",
          "enum": [
            "REFERENCE",
            "VALUE"
          ]
        },
        "referenceUri": {
          "type": "string"
        },
        "id_token_encrypted_response_alg": {
          "$ref": "#/definitions/EncKeyAlgorithm"
        },
        "id_token_encrypted_response_enc": {
          "$ref": "#/definitions/EncSymmetricAlgorithmCode"
        }
      },
      "additionalProperties": false,
      "required": [
        "type"
      ]
    },
    "EncKeyAlgorithm": {
      "type": "string",
      "const": "ECDH-ES"
    },
    "EncSymmetricAlgorithmCode": {
      "type": "string",
      "const": "XC20P"
    },
    "Schema": {
      "type": "string",
      "enum": [
        "openid:",
        "openid-vc:"
      ]
    },
    "ResponseIss": {
      "type": "string",
      "enum": [
        "https://self-issued.me",
        "https://self-issued.me/v2"
      ]
    },
    "ResponseType": {
      "type": "string",
      "enum": [
        "id_token",
        "vp_token"
      ]
    },
    "Scope": {
      "type": "string",
      "enum": [
        "openid",
        "openid did_authn",
        "profile",
        "email",
        "address",
        "phone"
      ]
    },
    "SubjectType": {
      "type": "string",
      "enum": [
        "public",
        "pairwise"
      ]
    },
    "SigningAlgo": {
      "type": "string",
      "enum": [
        "EdDSA",
        "RS256",
        "ES256",
        "ES256K",
        "none"
      ]
    },
    "ResponseMode": {
      "type": "string",
      "enum": [
        "fragment",
        "form_post",
        "post",
        "query"
      ]
    },
    "GrantType": {
      "type": "string",
      "enum": [
        "authorization_code",
        "implicit"
      ]
    },
    "AuthenticationContextReferences": {
      "type": "string",
      "enum": [
        "phr",
        "phrh"
      ]
    },
    "KeyAlgo": {
      "type": "string",
      "enum": [
        "EdDSA",
        "RS256",
        "ES256",
        "ES256K"
      ]
    },
    "TokenEndpointAuthMethod": {
      "type": "string",
      "enum": [
        "client_secret_post",
        "client_secret_basic",
        "client_secret_jwt",
        "private_key_jwt"
      ]
    },
    "ClaimType": {
      "type": "string",
      "enum": [
        "normal",
        "aggregated",
        "distributed"
      ]
    },
    "Format": {
      "type": "object",
      "properties": {
        "jwt": {
          "$ref": "#/definitions/JwtObject"
        },
        "jwt_vc": {
          "$ref": "#/definitions/JwtObject"
        },
        "jwt_vp": {
          "$ref": "#/definitions/JwtObject"
        },
        "ldp": {
          "$ref": "#/definitions/LdpObject"
        },
        "ldp_vc": {
          "$ref": "#/definitions/LdpObject"
        },
        "ldp_vp": {
          "$ref": "#/definitions/LdpObject"
        }
      },
      "additionalProperties": false
    },
    "JwtObject": {
      "type": "object",
      "properties": {
        "alg": {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "required": [
        "alg"
      ],
      "additionalProperties": false
    },
    "LdpObject": {
      "type": "object",
      "properties": {
        "proof_type": {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "required": [
        "proof_type"
      ],
      "additionalProperties": false
    },
    "IdTokenType": {
      "type": "string",
      "enum": [
        "subject_signed",
        "attester_signed"
      ]
    },
    "CheckLinkedDomain": {
      "type": "string",
      "enum": [
        "never",
        "if_present",
        "always"
      ]
    },
    "PresentationVerificationCallback": {
      "properties": {
        "isFunction": {
          "type": "boolean",
          "const": true
        }
      }
    },
    "PresentationSignCallback": {
      "properties": {
        "isFunction": {
          "type": "boolean",
          "const": true
        }
      }
    },
    "InternalSignature": {
      "type": "object",
      "properties": {
        "hexPrivateKey": {
          "type": "string"
        },
        "did": {
          "type": "string"
        },
        "kid": {
          "type": "string"
        }
      },
      "required": [
        "hexPrivateKey",
        "did"
      ],
      "additionalProperties": false
    },
    "ExternalSignature": {
      "type": "object",
      "properties": {
        "signatureUri": {
          "type": "string"
        },
        "did": {
          "type": "string"
        },
        "authZToken": {
          "type": "string"
        },
        "hexPublicKey": {
          "type": "string"
        },
        "kid": {
          "type": "string"
        }
      },
      "required": [
        "signatureUri",
        "did"
      ],
      "additionalProperties": false
    },
    "SuppliedSignature": {
      "type": "object",
      "properties": {
        "signature": {
          "properties": {
            "isFunction": {
              "type": "boolean",
              "const": true
            }
          }
        },
        "did": {
          "type": "string"
        },
        "kid": {
          "type": "string"
        }
      },
      "required": [
        "signature",
        "did",
        "kid"
      ],
      "additionalProperties": false
    },
    "VerifiablePresentationResponseOpts": {
      "type": "object",
      "properties": {
        "format": {
          "$ref": "#/definitions/VerifiablePresentationTypeFormat"
        },
        "presentation": {
          "$ref": "#/definitions/IVerifiablePresentation"
        },
        "location": {
          "$ref": "#/definitions/PresentationLocation"
        }
      },
      "required": [
        "format",
        "location",
        "presentation"
      ],
      "additionalProperties": false
    },
    "VerifiablePresentationTypeFormat": {
      "type": "string",
      "enum": [
        "jwt_vp",
        "ldp_vp"
      ]
    },
    "IVerifiablePresentation": {
      "type": "object",
      "properties": {
        "proof": {
          "anyOf": [
            {
              "$ref": "#/definitions/IProof"
            },
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/IProof"
              }
            }
          ]
        },
        "id": {
          "type": "string"
        },
        "@context": {
          "anyOf": [
            {
              "$ref": "#/definitions/ICredentialContextType"
            },
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/ICredentialContextType"
              }
            }
          ]
        },
        "type": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "verifiableCredential": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/W3CVerifiableCredential"
          }
        },
        "presentation_submission": {
          "$ref": "#/definitions/PresentationSubmission"
        },
        "holder": {
          "type": "string"
        }
      },
      "required": [
        "@context",
        "proof",
        "type",
        "verifiableCredential"
      ]
    },
    "IProof": {
      "type": "object",
      "properties": {
        "type": {
          "anyOf": [
            {
              "$ref": "#/definitions/IProofType"
            },
            {
              "type": "string"
            }
          ]
        },
        "created": {
          "type": "string"
        },
        "proofPurpose": {
          "anyOf": [
            {
              "$ref": "#/definitions/IProofPurpose"
            },
            {
              "type": "string"
            }
          ]
        },
        "verificationMethod": {
          "type": "string"
        },
        "challenge": {
          "type": "string"
        },
        "domain": {
          "type": "string"
        },
        "proofValue": {
          "type": "string"
        },
        "jws": {
          "type": "string"
        },
        "nonce": {
          "type": "string"
        },
        "requiredRevealStatements": {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "required": [
        "type",
        "created",
        "proofPurpose",
        "verificationMethod"
      ]
    },
    "IProofType": {
      "type": "string",
      "enum": [
        "Ed25519Signature2018",
        "Ed25519Signature2020",
        "EcdsaSecp256k1Signature2019",
        "EcdsaSecp256k1RecoverySignature2020",
        "JsonWebSignature2020",
        "RsaSignature2018",
        "GpgSignature2020",
        "JcsEd25519Signature2020",
        "BbsBlsSignatureProof2020",
        "BbsBlsBoundSignatureProof2020"
      ]
    },
    "IProofPurpose": {
      "type": "string",
      "enum": [
        "verificationMethod",
        "assertionMethod",
        "authentication",
        "keyAgreement",
        "contactAgreement",
        "capabilityInvocation",
        "capabilityDelegation"
      ]
    },
    "ICredentialContextType": {
      "anyOf": [
        {
          "type": "object",
          "properties": {
            "name": {
              "type": "string"
            },
            "did": {
              "type": "string"
            }
          }
        },
        {
          "type": "string"
        }
      ]
    },
    "W3CVerifiableCredential": {
      "anyOf": [
        {
          "$ref": "#/definitions/IVerifiableCredential"
        },
        {
          "$ref": "#/definitions/CompactJWT"
        }
      ],
      "description": "Represents a signed Verifiable Credential (includes proof), in either JSON or compact JWT format. See  {@link  https://www.w3.org/TR/vc-data-model/#credentials | VC data model } \nSee  {@link  https://www.w3.org/TR/vc-data-model/#proof-formats | proof formats }"
    },
    "IVerifiableCredential": {
      "type": "object",
      "properties": {
        "proof": {
          "anyOf": [
            {
              "$ref": "#/definitions/IProof"
            },
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/IProof"
              }
            }
          ]
        },
        "@context": {
          "anyOf": [
            {
              "$ref": "#/definitions/ICredentialContextType"
            },
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/ICredentialContextType"
              }
            }
          ]
        },
        "type": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "credentialSchema": {
          "anyOf": [
            {
              "$ref": "#/definitions/ICredentialSchemaType"
            },
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/ICredentialSchemaType"
              }
            }
          ]
        },
        "issuer": {
          "anyOf": [
            {
              "$ref": "#/definitions/IIssuerId"
            },
            {
              "$ref": "#/definitions/IIssuer"
            }
          ]
        },
        "issuanceDate": {
          "type": "string"
        },
        "credentialSubject": {
          "anyOf": [
            {
              "type": "object",
              "properties": {
                "id": {
                  "type": "string"
                }
              }
            },
            {
              "type": "array",
              "items": {
                "type": "object",
                "properties": {
                  "id": {
                    "type": "string"
                  }
                }
              }
            }
          ]
        },
        "expirationDate": {
          "type": "string"
        },
        "id": {
          "type": "string"
        },
        "credentialStatus": {
          "$ref": "#/definitions/ICredentialStatus"
        },
        "description": {
          "type": "string"
        },
        "name": {
          "type": "string"
        }
      },
      "required": [
        "@context",
        "credentialSubject",
        "issuanceDate",
        "issuer",
        "proof",
        "type"
      ]
    },
    "ICredentialSchemaType": {
      "anyOf": [
        {
          "$ref": "#/definitions/ICredentialSchema"
        },
        {
          "type": "string"
        }
      ]
    },
    "ICredentialSchema": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "type": {
          "type": "string"
        }
      },
      "required": [
        "id"
      ],
      "additionalProperties": false
    },
    "IIssuerId": {
      "type": "string"
    },
    "IIssuer": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        }
      },
      "required": [
        "id"
      ]
    },
    "ICredentialStatus": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "type": {
          "type": "string"
        }
      },
      "required": [
        "id",
        "type"
      ],
      "additionalProperties": false
    },
    "CompactJWT": {
      "type": "string",
      "description": "Represents a Json Web Token in compact form."
    },
    "PresentationSubmission": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string",
          "description": "A UUID or some other unique ID to identify this Presentation Submission"
        },
        "definition_id": {
          "type": "string",
          "description": "A UUID or some other unique ID to identify this Presentation Definition"
        },
        "descriptor_map": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/Descriptor"
          },
          "description": "List of descriptors of how the claims are being mapped to presentation definition"
        }
      },
      "required": [
        "id",
        "definition_id",
        "descriptor_map"
      ],
      "additionalProperties": false,
      "description": "It expresses how the inputs are presented as proofs to a Verifier."
    },
    "Descriptor": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string",
          "description": "ID to identify the descriptor from Presentation Definition Input Descriptor it coresponds to."
        },
        "path": {
          "type": "string",
          "description": "The path where the verifiable credential is located in the presentation submission json"
        },
        "path_nested": {
          "$ref": "#/definitions/Descriptor"
        },
        "format": {
          "type": "string",
          "description": "The Proof or JWT algorith that the proof is in"
        }
      },
      "required": [
        "id",
        "path",
        "format"
      ],
      "additionalProperties": false,
      "description": "descriptor map laying out the structure of the presentation submission."
    },
    "PresentationLocation": {
      "type": "string",
      "enum": [
        "vp_token",
        "id_token"
      ]
    }
  }
};