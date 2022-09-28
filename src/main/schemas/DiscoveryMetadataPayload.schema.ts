export const DiscoveryMetadataPayloadSchema = {
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$ref": "#/definitions/DiscoveryMetadataPayload",
  "definitions": {
    "DiscoveryMetadataPayload": {
      "type": "object",
      "properties": {
        "acr_values_supported": {
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
        "authorization_endpoint": {
          "anyOf": [
            {
              "$ref": "#/definitions/Schema"
            },
            {
              "type": "string"
            }
          ]
        },
        "claims_locales_supported": {
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
        "claims_supported": {
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
          ],
          "description": "RECOMMENDED. JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for. Note that for privacy or other reasons, this might not be an exhaustive list."
        },
        "claim_types_supported": {
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
          ],
          "description": "OPTIONAL. JSON array containing a list of the Claim Types that the OpenID Provider supports. These Claim Types are described in Section 5.6 of OpenID Connect Core 1.0 [OpenID.Core]. Values defined by this specification are normal, aggregated, and distributed. If omitted, the implementation supports only normal Claims."
        },
        "display_values_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {}
            },
            {}
          ],
          "description": "OPTIONAL. JSON array containing a list of the display parameter values that the OpenID Provider supports. These values are described in Section 3.1.2.1 of OpenID Connect Core 1.0 [OpenID.Core]."
        },
        "grant_types_supported": {
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
        "id_token_encryption_alg_values_supported": {
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
        "id_token_encryption_enc_values_supported": {
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
          ],
          "description": "OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT]."
        },
        "id_token_signing_alg_values_supported": {
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
        "issuer": {
          "$ref": "#/definitions/ResponseIss"
        },
        "jwks_uri": {
          "type": "string"
        },
        "token_endpoint": {
          "type": "string"
        },
        "userinfo_endpoint": {
          "type": "string"
        },
        "registration_endpoint": {
          "type": "string"
        },
        "response_types_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/ResponseType"
              }
            },
            {
              "$ref": "#/definitions/ResponseType"
            }
          ]
        },
        "response_modes_supported": {
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
        "scopes_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/Scope"
              }
            },
            {
              "$ref": "#/definitions/Scope"
            }
          ]
        },
        "subject_types_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/SubjectType"
              }
            },
            {
              "$ref": "#/definitions/SubjectType"
            }
          ]
        },
        "userinfo_signing_alg_values_supported": {
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
        "userinfo_encryption_alg_values_supported": {
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
        "request_object_encryption_alg_values_supported": {
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
        "request_object_encryption_enc_values_supported": {
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
          ],
          "description": "OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for Request Objects. These algorithms are used both when the Request Object is passed by value and when it is passed by reference."
        },
        "request_object_signing_alg_values_supported": {
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
        "token_endpoint_auth_methods_supported": {
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
        "token_endpoint_auth_signing_alg_values_supported": {
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
        "userinfo_encryption_enc_values_supported": {
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
          ],
          "description": "OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT]."
        },
        "service_documentation": {
          "type": "string"
        },
        "ui_locales_supported": {
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
        "claims_parameter_supported": {
          "type": "boolean"
        },
        "request_parameter_supported": {
          "type": "boolean"
        },
        "request_uri_parameter_supported": {
          "type": "boolean"
        },
        "require_request_uri_registration": {
          "type": "boolean"
        },
        "op_policy_uri": {
          "type": "string"
        },
        "op_tos_uri": {
          "type": "string"
        },
        "subject_syntax_types_supported": {
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
        "id_token_types_supported": {
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
        "vp_formats": {
          "$ref": "#/definitions/Format"
        },
        "client_name": {
          "type": "string"
        },
        "logo_uri": {
          "type": "string"
        },
        "client_purpose": {
          "type": "string"
        }
      },
      "required": [
        "authorization_endpoint",
        "id_token_signing_alg_values_supported",
        "issuer",
        "response_types_supported",
        "scopes_supported",
        "subject_types_supported",
        "subject_syntax_types_supported",
        "vp_formats",
        "client_name",
        "logo_uri",
        "client_purpose"
      ],
      "additionalProperties": false
    },
    "AuthenticationContextReferences": {
      "type": "string",
      "enum": [
        "phr",
        "phrh"
      ]
    },
    "Schema": {
      "type": "string",
      "const": "openid:"
    },
    "ClaimType": {
      "type": "string",
      "enum": [
        "normal",
        "aggregated",
        "distributed"
      ]
    },
    "GrantType": {
      "type": "string",
      "enum": [
        "authorization_code",
        "implicit"
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
    "ResponseMode": {
      "type": "string",
      "enum": [
        "fragment",
        "form_post",
        "post",
        "query"
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
    "TokenEndpointAuthMethod": {
      "type": "string",
      "enum": [
        "client_secret_post",
        "client_secret_basic",
        "client_secret_jwt",
        "private_key_jwt"
      ]
    },
    "IdTokenType": {
      "type": "string",
      "enum": [
        "subject_signed",
        "attester_signed"
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
    }
  }
};