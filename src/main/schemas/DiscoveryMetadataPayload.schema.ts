export const DiscoveryMetadataPayloadSchema = {
  "$ref": "#/definitions/DiscoveryMetadataPayload",
  "$schema": "http://json-schema.org/draft-07/schema#",
  "definitions": {
    "AuthenticationContextReferences": {
      "enum": [
        "phr",
        "phrh"
      ],
      "type": "string"
    },
    "ClaimType": {
      "enum": [
        "aggregated",
        "distributed",
        "normal"
      ],
      "type": "string"
    },
    "DiscoveryMetadataPayload": {
      "additionalProperties": false,
      "properties": {
        "acr_values_supported": {
          "anyOf": [
            {
              "items": {
                "$ref": "#/definitions/AuthenticationContextReferences"
              },
              "type": "array"
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
        "claim_types_supported": {
          "anyOf": [
            {
              "items": {
                "$ref": "#/definitions/ClaimType"
              },
              "type": "array"
            },
            {
              "$ref": "#/definitions/ClaimType"
            }
          ],
          "description": "OPTIONAL. JSON array containing a list of the Claim Types that the OpenID Provider supports. These Claim Types are described in Section 5.6 of OpenID Connect Core 1.0 [OpenID.Core]. Values defined by this specification are normal, aggregated, and distributed. If omitted, the implementation supports only normal Claims."
        },
        "claims_locales_supported": {
          "anyOf": [
            {
              "items": {
                "type": "string"
              },
              "type": "array"
            },
            {
              "type": "string"
            }
          ]
        },
        "claims_parameter_supported": {
          "type": "boolean"
        },
        "claims_supported": {
          "anyOf": [
            {
              "items": {
                "type": "string"
              },
              "type": "array"
            },
            {
              "type": "string"
            }
          ],
          "description": "RECOMMENDED. JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for. Note that for privacy or other reasons, this might not be an exhaustive list."
        },
        "display_values_supported": {
          "anyOf": [
            {
              "items": {},
              "type": "array"
            },
            {}
          ],
          "description": "OPTIONAL. JSON array containing a list of the display parameter values that the OpenID Provider supports. These values are described in Section 3.1.2.1 of OpenID Connect Core 1.0 [OpenID.Core]."
        },
        "grant_types_supported": {
          "anyOf": [
            {
              "items": {
                "$ref": "#/definitions/GrantType"
              },
              "type": "array"
            },
            {
              "$ref": "#/definitions/GrantType"
            }
          ]
        },
        "id_token_encryption_alg_values_supported": {
          "anyOf": [
            {
              "items": {
                "$ref": "#/definitions/KeyAlgo"
              },
              "type": "array"
            },
            {
              "$ref": "#/definitions/KeyAlgo"
            }
          ]
        },
        "id_token_encryption_enc_values_supported": {
          "anyOf": [
            {
              "items": {
                "type": "string"
              },
              "type": "array"
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
              "items": {
                "$ref": "#/definitions/SigningAlgo"
              },
              "type": "array"
            },
            {
              "$ref": "#/definitions/SigningAlgo"
            }
          ]
        },
        "id_token_types_supported": {
          "anyOf": [
            {
              "items": {
                "$ref": "#/definitions/IdTokenType"
              },
              "type": "array"
            },
            {
              "$ref": "#/definitions/IdTokenType"
            }
          ]
        },
        "issuer": {
          "$ref": "#/definitions/ResponseIss"
        },
        "jwks_uri": {
          "type": "string"
        },
        "op_policy_uri": {
          "type": "string"
        },
        "op_tos_uri": {
          "type": "string"
        },
        "registration_endpoint": {
          "type": "string"
        },
        "request_object_encryption_alg_values_supported": {
          "anyOf": [
            {
              "items": {
                "$ref": "#/definitions/SigningAlgo"
              },
              "type": "array"
            },
            {
              "$ref": "#/definitions/SigningAlgo"
            }
          ]
        },
        "request_object_encryption_enc_values_supported": {
          "anyOf": [
            {
              "items": {
                "type": "string"
              },
              "type": "array"
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
              "items": {
                "$ref": "#/definitions/SigningAlgo"
              },
              "type": "array"
            },
            {
              "$ref": "#/definitions/SigningAlgo"
            }
          ]
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
        "response_modes_supported": {
          "anyOf": [
            {
              "items": {
                "$ref": "#/definitions/ResponseMode"
              },
              "type": "array"
            },
            {
              "$ref": "#/definitions/ResponseMode"
            }
          ]
        },
        "response_types_supported": {
          "anyOf": [
            {
              "items": {
                "$ref": "#/definitions/ResponseType"
              },
              "type": "array"
            },
            {
              "$ref": "#/definitions/ResponseType"
            }
          ]
        },
        "scopes_supported": {
          "anyOf": [
            {
              "items": {
                "$ref": "#/definitions/Scope"
              },
              "type": "array"
            },
            {
              "$ref": "#/definitions/Scope"
            }
          ]
        },
        "service_documentation": {
          "type": "string"
        },
        "subject_syntax_types_supported": {
          "anyOf": [
            {
              "items": {
                "type": "string"
              },
              "type": "array"
            },
            {
              "type": "string"
            }
          ]
        },
        "subject_types_supported": {
          "anyOf": [
            {
              "items": {
                "$ref": "#/definitions/SubjectType"
              },
              "type": "array"
            },
            {
              "$ref": "#/definitions/SubjectType"
            }
          ]
        },
        "token_endpoint": {
          "type": "string"
        },
        "token_endpoint_auth_methods_supported": {
          "anyOf": [
            {
              "items": {
                "$ref": "#/definitions/TokenEndpointAuthMethod"
              },
              "type": "array"
            },
            {
              "$ref": "#/definitions/TokenEndpointAuthMethod"
            }
          ]
        },
        "token_endpoint_auth_signing_alg_values_supported": {
          "anyOf": [
            {
              "items": {
                "$ref": "#/definitions/SigningAlgo"
              },
              "type": "array"
            },
            {
              "$ref": "#/definitions/SigningAlgo"
            }
          ]
        },
        "ui_locales_supported": {
          "anyOf": [
            {
              "items": {
                "type": "string"
              },
              "type": "array"
            },
            {
              "type": "string"
            }
          ]
        },
        "userinfo_encryption_alg_values_supported": {
          "anyOf": [
            {
              "items": {
                "$ref": "#/definitions/SigningAlgo"
              },
              "type": "array"
            },
            {
              "$ref": "#/definitions/SigningAlgo"
            }
          ]
        },
        "userinfo_encryption_enc_values_supported": {
          "anyOf": [
            {
              "items": {
                "type": "string"
              },
              "type": "array"
            },
            {
              "type": "string"
            }
          ],
          "description": "OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT]."
        },
        "userinfo_endpoint": {
          "type": "string"
        },
        "userinfo_signing_alg_values_supported": {
          "anyOf": [
            {
              "items": {
                "$ref": "#/definitions/SigningAlgo"
              },
              "type": "array"
            },
            {
              "$ref": "#/definitions/SigningAlgo"
            }
          ]
        },
        "vp_formats": {
          "$ref": "#/definitions/Format"
        }
      },
      "required": [
        "authorization_endpoint",
        "id_token_signing_alg_values_supported",
        "issuer",
        "response_types_supported",
        "scopes_supported",
        "subject_syntax_types_supported",
        "subject_types_supported",
        "vp_formats"
      ],
      "type": "object"
    },
    "Format": {
      "additionalProperties": false,
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
      "type": "object"
    },
    "GrantType": {
      "enum": [
        "authorization_code",
        "implicit"
      ],
      "type": "string"
    },
    "IdTokenType": {
      "enum": [
        "attester_signed",
        "subject_signed"
      ],
      "type": "string"
    },
    "JwtObject": {
      "additionalProperties": false,
      "properties": {
        "alg": {
          "items": {
            "type": "string"
          },
          "type": "array"
        }
      },
      "required": [
        "alg"
      ],
      "type": "object"
    },
    "KeyAlgo": {
      "enum": [
        "ES256",
        "ES256K",
        "EdDSA",
        "RS256"
      ],
      "type": "string"
    },
    "LdpObject": {
      "additionalProperties": false,
      "properties": {
        "proof_type": {
          "items": {
            "type": "string"
          },
          "type": "array"
        }
      },
      "required": [
        "proof_type"
      ],
      "type": "object"
    },
    "ResponseIss": {
      "enum": [
        "https://self-issued.me",
        "https://self-issued.me/v2"
      ],
      "type": "string"
    },
    "ResponseMode": {
      "enum": [
        "form_post",
        "fragment",
        "post",
        "query"
      ],
      "type": "string"
    },
    "ResponseType": {
      "enum": [
        "id_token",
        "vp_token"
      ],
      "type": "string"
    },
    "Schema": {
      "const": "openid:",
      "type": "string"
    },
    "Scope": {
      "enum": [
        "address",
        "email",
        "openid",
        "openid did_authn",
        "phone",
        "profile"
      ],
      "type": "string"
    },
    "SigningAlgo": {
      "enum": [
        "ES256",
        "ES256K",
        "EdDSA",
        "RS256",
        "none"
      ],
      "type": "string"
    },
    "SubjectType": {
      "enum": [
        "pairwise",
        "public"
      ],
      "type": "string"
    },
    "TokenEndpointAuthMethod": {
      "enum": [
        "client_secret_basic",
        "client_secret_jwt",
        "client_secret_post",
        "private_key_jwt"
      ],
      "type": "string"
    }
  }
};