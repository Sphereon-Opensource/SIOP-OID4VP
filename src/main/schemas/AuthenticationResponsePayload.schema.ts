export const AuthenticationResponsePayloadSchema = {
  "$ref": "#/definitions/AuthenticationResponsePayload",
  "$schema": "http://json-schema.org/draft-07/schema#",
  "definitions": {
    "AuthenticationContextReferences": {
      "enum": [
        "phr",
        "phrh"
      ],
      "type": "string"
    },
    "AuthenticationResponsePayload": {
      "properties": {
        "aud": {
          "type": "string"
        },
        "did": {
          "type": "string"
        },
        "exp": {
          "type": "number"
        },
        "iat": {
          "type": "number"
        },
        "iss": {
          "type": "string"
        },
        "jti": {
          "type": "string"
        },
        "nbf": {
          "type": "number"
        },
        "nonce": {
          "type": "string"
        },
        "registration": {
          "$ref": "#/definitions/DiscoveryMetadataPayload"
        },
        "registration_uri": {
          "type": "string"
        },
        "rexp": {
          "type": "number"
        },
        "state": {
          "type": "string"
        },
        "sub": {
          "type": "string"
        },
        "sub_jwk": {
          "$ref": "#/definitions/JWK"
        },
        "type": {
          "type": "string"
        },
        "verifiable_presentations": {
          "items": {
            "$ref": "#/definitions/VerifiablePresentationPayload"
          },
          "type": "array"
        },
        "vp_token": {
          "$ref": "#/definitions/VerifiablePresentationPayload"
        }
      },
      "required": [
        "aud",
        "did",
        "exp",
        "iat",
        "iss",
        "nonce",
        "state",
        "sub",
        "sub_jwk"
      ],
      "type": "object"
    },
    "ClaimType": {
      "enum": [
        "aggregated",
        "distributed",
        "normal"
      ],
      "type": "string"
    },
    "Descriptor": {
      "additionalProperties": false,
      "properties": {
        "format": {
          "type": "string"
        },
        "id": {
          "type": "string"
        },
        "path": {
          "type": "string"
        },
        "path_nested": {
          "$ref": "#/definitions/Descriptor"
        }
      },
      "required": [
        "format",
        "id",
        "path"
      ],
      "type": "object"
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
    "ICredentialContext": {
      "additionalProperties": {},
      "properties": {
        "did": {
          "type": "string"
        },
        "name": {
          "type": "string"
        }
      },
      "type": "object"
    },
    "ICredentialContextType": {
      "anyOf": [
        {
          "$ref": "#/definitions/ICredentialContext"
        },
        {
          "type": "string"
        }
      ]
    },
    "ICredentialSchema": {
      "additionalProperties": false,
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
      "type": "object"
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
    "ICredentialStatus": {
      "additionalProperties": false,
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
      "type": "object"
    },
    "ICredentialSubject": {
      "additionalProperties": {},
      "properties": {
        "id": {
          "type": "string"
        }
      },
      "type": "object"
    },
    "IIssuer": {
      "additionalProperties": {},
      "properties": {
        "id": {
          "type": "string"
        }
      },
      "required": [
        "id"
      ],
      "type": "object"
    },
    "IPresentation": {
      "additionalProperties": false,
      "properties": {
        "@context": {
          "anyOf": [
            {
              "$ref": "#/definitions/ICredentialContextType"
            },
            {
              "items": {
                "$ref": "#/definitions/ICredentialContextType"
              },
              "type": "array"
            }
          ]
        },
        "holder": {
          "type": "string"
        },
        "presentation_submission": {
          "$ref": "#/definitions/PresentationSubmission"
        },
        "type": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "verifiableCredential": {
          "items": {
            "$ref": "#/definitions/IVerifiableCredential"
          },
          "type": "array"
        }
      },
      "required": [
        "@context",
        "type",
        "verifiableCredential"
      ],
      "type": "object"
    },
    "IProof": {
      "additionalProperties": {
        "anyOf": [
          {
            "type": "string"
          },
          {
            "items": {
              "type": "string"
            },
            "type": "array"
          },
          {
            "not": {}
          }
        ]
      },
      "properties": {
        "challenge": {
          "type": "string"
        },
        "created": {
          "type": "string"
        },
        "domain": {
          "type": "string"
        },
        "jws": {
          "type": "string"
        },
        "nonce": {
          "type": "string"
        },
        "proofPurpose": {
          "anyOf": [
            {
              "$ref": "#/definitions/ProofPurpose"
            },
            {
              "type": "string"
            }
          ]
        },
        "proofValue": {
          "type": "string"
        },
        "requiredRevealStatements": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "type": {
          "anyOf": [
            {
              "$ref": "#/definitions/ProofType"
            },
            {
              "type": "string"
            }
          ]
        },
        "verificationMethod": {
          "type": "string"
        }
      },
      "required": [
        "created",
        "proofPurpose",
        "type",
        "verificationMethod"
      ],
      "type": "object"
    },
    "IVerifiableCredential": {
      "properties": {
        "@context": {
          "anyOf": [
            {
              "items": {
                "$ref": "#/definitions/ICredentialContextType"
              },
              "type": "array"
            },
            {
              "$ref": "#/definitions/ICredentialContextType"
            }
          ]
        },
        "credentialSchema": {
          "anyOf": [
            {
              "$ref": "#/definitions/ICredentialSchemaType"
            },
            {
              "items": {
                "$ref": "#/definitions/ICredentialSchemaType"
              },
              "type": "array"
            }
          ]
        },
        "credentialStatus": {
          "$ref": "#/definitions/ICredentialStatus"
        },
        "credentialSubject": {
          "$ref": "#/definitions/ICredentialSubject"
        },
        "description": {
          "type": "string"
        },
        "expirationDate": {
          "type": "string"
        },
        "id": {
          "type": "string"
        },
        "issuanceDate": {
          "type": "string"
        },
        "issuer": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "$ref": "#/definitions/IIssuer"
            }
          ]
        },
        "name": {
          "type": "string"
        },
        "proof": {
          "anyOf": [
            {
              "$ref": "#/definitions/IProof"
            },
            {
              "items": {
                "$ref": "#/definitions/IProof"
              },
              "type": "array"
            }
          ]
        },
        "type": {
          "items": {
            "type": "string"
          },
          "type": "array"
        }
      },
      "required": [
        "@context",
        "credentialSubject",
        "id",
        "issuanceDate",
        "issuer",
        "proof",
        "type"
      ],
      "type": "object"
    },
    "IdTokenType": {
      "enum": [
        "attester_signed",
        "subject_signed"
      ],
      "type": "string"
    },
    "JWK": {
      "additionalProperties": {},
      "properties": {
        "alg": {
          "type": "string"
        },
        "crv": {
          "type": "string"
        },
        "d": {
          "type": "string"
        },
        "dp": {
          "type": "string"
        },
        "dq": {
          "type": "string"
        },
        "e": {
          "type": "string"
        },
        "ext": {
          "type": "boolean"
        },
        "k": {
          "type": "string"
        },
        "key_ops": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "kid": {
          "type": "string"
        },
        "kty": {
          "type": "string"
        },
        "n": {
          "type": "string"
        },
        "oth": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "d": {
                "type": "string"
              },
              "r": {
                "type": "string"
              },
              "t": {
                "type": "string"
              }
            },
            "type": "object"
          },
          "type": "array"
        },
        "p": {
          "type": "string"
        },
        "q": {
          "type": "string"
        },
        "qi": {
          "type": "string"
        },
        "use": {
          "type": "string"
        },
        "x": {
          "type": "string"
        },
        "x5c": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "x5t": {
          "type": "string"
        },
        "x5t#S256": {
          "type": "string"
        },
        "x5u": {
          "type": "string"
        },
        "y": {
          "type": "string"
        }
      },
      "type": "object"
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
    "PresentationSubmission": {
      "additionalProperties": false,
      "properties": {
        "definition_id": {
          "type": "string"
        },
        "descriptor_map": {
          "items": {
            "$ref": "#/definitions/Descriptor"
          },
          "type": "array"
        },
        "id": {
          "type": "string"
        }
      },
      "required": [
        "definition_id",
        "descriptor_map",
        "id"
      ],
      "type": "object"
    },
    "ProofPurpose": {
      "enum": [
        "assertionMethod",
        "authentication",
        "capabilityDelegation",
        "capabilityInvocation",
        "contactAgreement",
        "keyAgreement"
      ],
      "type": "string"
    },
    "ProofType": {
      "enum": [
        "BbsBlsBoundSignatureProof2020",
        "BbsBlsSignatureProof2020",
        "EcdsaSecp256k1RecoverySignature2020",
        "EcdsaSecp256k1Signature2019",
        "Ed25519Signature2018",
        "Ed25519Signature2020",
        "GpgSignature2020",
        "JcsEd25519Signature2020",
        "JsonWebSignature2020",
        "RsaSignature2018"
      ],
      "type": "string"
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
    },
    "VerifiablePresentationPayload": {
      "additionalProperties": false,
      "description": "A wrapper for verifiablePresentation",
      "properties": {
        "format": {
          "$ref": "#/definitions/VerifiablePresentationTypeFormat"
        },
        "presentation": {
          "$ref": "#/definitions/IPresentation"
        }
      },
      "required": [
        "format",
        "presentation"
      ],
      "type": "object"
    },
    "VerifiablePresentationTypeFormat": {
      "enum": [
        "jwt_vp",
        "ldp_vp"
      ],
      "type": "string"
    }
  }
};