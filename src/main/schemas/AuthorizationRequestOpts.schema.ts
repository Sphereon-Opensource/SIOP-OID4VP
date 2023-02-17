export const CreateAuthorizationRequestOptsSchemaObj = {
  "$id": "CreateAuthorizationRequestOptsSchema",
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$ref": "#/definitions/CreateAuthorizationRequestOpts",
  "definitions": {
    "CreateAuthorizationRequestOpts": {
      "anyOf": [
        {
          "$ref": "#/definitions/AuthorizationRequestOptsVID1"
        },
        {
          "$ref": "#/definitions/AuthorizationRequestOptsVD11"
        }
      ]
    },
    "AuthorizationRequestOptsVID1": {
      "type": "object",
      "properties": {
        "version": {
          "$ref": "#/definitions/SupportedVersion"
        },
        "clientMetadata": {
          "$ref": "#/definitions/ClientMetadataOpts"
        },
        "payload": {
          "$ref": "#/definitions/AuthorizationRequestPayloadOpts%3CClaimPayloadOptsVID1%3E"
        },
        "requestObject": {
          "$ref": "#/definitions/RequestObjectOpts%3CClaimPayloadOptsVID1%3E"
        },
        "uriScheme": {
          "type": "string"
        }
      },
      "required": [
        "version",
        "requestObject"
      ],
      "additionalProperties": false
    },
    "SupportedVersion": {
      "type": "number",
      "enum": [
        70,
        110,
        71
      ]
    },
    "ClientMetadataOpts": {
      "type": "object",
      "properties": {
        "passBy": {
          "$ref": "#/definitions/PassBy"
        },
        "referenceUri": {
          "type": "string"
        },
        "id_token_encrypted_response_alg": {
          "$ref": "#/definitions/EncKeyAlgorithm"
        },
        "id_token_encrypted_response_enc": {
          "$ref": "#/definitions/EncSymmetricAlgorithmCode"
        },
        "clientId": {
          "anyOf": [
            {
              "type": "string"
            },
            {}
          ]
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
        "responseTypesSupported": {
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
        "scopesSupported": {
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
        "subjectTypesSupported": {
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
        "subjectSyntaxTypesSupported": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "vpFormatsSupported": {
          "anyOf": [
            {},
            {
              "$ref": "#/definitions/Format"
            }
          ]
        },
        "clientName": {
          "anyOf": [
            {
              "type": "string"
            },
            {}
          ]
        },
        "logoUri": {
          "anyOf": [
            {
              "type": "string"
            },
            {}
          ]
        },
        "clientPurpose": {
          "anyOf": [
            {
              "type": "string"
            },
            {}
          ]
        }
      },
      "required": [
        "passBy"
      ]
    },
    "PassBy": {
      "type": "string",
      "enum": [
        "NONE",
        "REFERENCE",
        "VALUE"
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
    "SigningAlgo": {
      "type": "string",
      "enum": [
        "EdDSA",
        "RS256",
        "ES256",
        "ES256K"
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
    "AuthorizationRequestPayloadOpts<ClaimPayloadOptsVID1>": {
      "type": "object",
      "properties": {
        "scope": {
          "type": "string"
        },
        "response_type": {
          "type": "string"
        },
        "client_id": {
          "type": "string"
        },
        "redirect_uri": {
          "type": "string"
        },
        "id_token_hint": {
          "type": "string"
        },
        "claims": {
          "$ref": "#/definitions/ClaimPayloadOptsVID1"
        },
        "nonce": {
          "type": "string"
        },
        "state": {
          "type": "string"
        },
        "authorization_endpoint": {
          "type": "string"
        },
        "response_mode": {
          "$ref": "#/definitions/ResponseMode"
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
        "request_uri": {
          "type": "string"
        }
      }
    },
    "ClaimPayloadOptsVID1": {
      "type": "object",
      "properties": {
        "id_token": {
          "$ref": "#/definitions/IdTokenClaimPayload"
        },
        "vp_token": {
          "$ref": "#/definitions/PresentationDefinitionPayloadOpts"
        }
      }
    },
    "IdTokenClaimPayload": {
      "type": "object"
    },
    "PresentationDefinitionPayloadOpts": {
      "type": "object",
      "properties": {
        "presentation_definition": {
          "$ref": "#/definitions/IPresentationDefinition"
        },
        "presentation_definition_uri": {
          "type": "string"
        }
      },
      "additionalProperties": false
    },
    "IPresentationDefinition": {
      "anyOf": [
        {
          "$ref": "#/definitions/PresentationDefinitionV1"
        },
        {
          "$ref": "#/definitions/PresentationDefinitionV2"
        }
      ]
    },
    "PresentationDefinitionV1": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "name": {
          "type": "string"
        },
        "purpose": {
          "type": "string"
        },
        "format": {
          "$ref": "#/definitions/Format"
        },
        "submission_requirements": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/SubmissionRequirement"
          }
        },
        "input_descriptors": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/InputDescriptorV1"
          }
        }
      },
      "required": [
        "id",
        "input_descriptors"
      ],
      "additionalProperties": false
    },
    "SubmissionRequirement": {
      "type": "object",
      "properties": {
        "name": {
          "type": "string"
        },
        "purpose": {
          "type": "string"
        },
        "rule": {
          "$ref": "#/definitions/Rules"
        },
        "count": {
          "type": "number"
        },
        "min": {
          "type": "number"
        },
        "max": {
          "type": "number"
        },
        "from": {
          "type": "string"
        },
        "from_nested": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/SubmissionRequirement"
          }
        }
      },
      "required": [
        "rule"
      ],
      "additionalProperties": false
    },
    "Rules": {
      "type": "string",
      "enum": [
        "all",
        "pick"
      ]
    },
    "InputDescriptorV1": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "name": {
          "type": "string"
        },
        "purpose": {
          "type": "string"
        },
        "group": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "schema": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/Schema"
          }
        },
        "constraints": {
          "$ref": "#/definitions/ConstraintsV1"
        }
      },
      "required": [
        "id",
        "schema"
      ],
      "additionalProperties": false
    },
    "Schema": {
      "type": "object",
      "properties": {
        "uri": {
          "type": "string"
        },
        "required": {
          "type": "boolean"
        }
      },
      "required": [
        "uri"
      ],
      "additionalProperties": false
    },
    "ConstraintsV1": {
      "type": "object",
      "properties": {
        "limit_disclosure": {
          "$ref": "#/definitions/Optionality"
        },
        "statuses": {
          "$ref": "#/definitions/Statuses"
        },
        "fields": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/FieldV1"
          }
        },
        "subject_is_issuer": {
          "$ref": "#/definitions/Optionality"
        },
        "is_holder": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/HolderSubject"
          }
        },
        "same_subject": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/HolderSubject"
          }
        }
      },
      "additionalProperties": false
    },
    "Optionality": {
      "type": "string",
      "enum": [
        "required",
        "preferred"
      ]
    },
    "Statuses": {
      "type": "object",
      "properties": {
        "active": {
          "$ref": "#/definitions/PdStatus"
        },
        "suspended": {
          "$ref": "#/definitions/PdStatus"
        },
        "revoked": {
          "$ref": "#/definitions/PdStatus"
        }
      },
      "additionalProperties": false
    },
    "PdStatus": {
      "type": "object",
      "properties": {
        "directive": {
          "$ref": "#/definitions/Directives"
        }
      },
      "additionalProperties": false
    },
    "Directives": {
      "type": "string",
      "enum": [
        "required",
        "allowed",
        "disallowed"
      ]
    },
    "FieldV1": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "path": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "purpose": {
          "type": "string"
        },
        "filter": {
          "$ref": "#/definitions/FilterV1"
        },
        "predicate": {
          "$ref": "#/definitions/Optionality"
        }
      },
      "additionalProperties": false
    },
    "FilterV1": {
      "type": "object",
      "properties": {
        "_const": {
          "type": [
            "number",
            "string",
            "null"
          ]
        },
        "_enum": {
          "type": "array",
          "items": {
            "type": [
              "number",
              "string"
            ]
          }
        },
        "exclusiveMinimum": {
          "type": [
            "number",
            "string",
            "null"
          ]
        },
        "exclusiveMaximum": {
          "type": [
            "number",
            "string",
            "null"
          ]
        },
        "format": {
          "type": "string"
        },
        "minLength": {
          "type": "number"
        },
        "maxLength": {
          "type": "number"
        },
        "minimum": {
          "type": [
            "number",
            "string",
            "null"
          ]
        },
        "maximum": {
          "type": [
            "number",
            "string",
            "null"
          ]
        },
        "not": {
          "type": "object"
        },
        "pattern": {
          "type": "string"
        },
        "type": {
          "type": "string"
        }
      },
      "required": [
        "type"
      ],
      "additionalProperties": false
    },
    "HolderSubject": {
      "type": "object",
      "properties": {
        "field_id": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "directive": {
          "$ref": "#/definitions/Optionality"
        }
      },
      "required": [
        "field_id",
        "directive"
      ],
      "additionalProperties": false
    },
    "PresentationDefinitionV2": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "name": {
          "type": "string"
        },
        "purpose": {
          "type": "string"
        },
        "format": {
          "$ref": "#/definitions/Format"
        },
        "submission_requirements": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/SubmissionRequirement"
          }
        },
        "input_descriptors": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/InputDescriptorV2"
          }
        },
        "frame": {
          "type": "object"
        }
      },
      "required": [
        "id",
        "input_descriptors"
      ],
      "additionalProperties": false
    },
    "InputDescriptorV2": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "name": {
          "type": "string"
        },
        "purpose": {
          "type": "string"
        },
        "group": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "constraints": {
          "$ref": "#/definitions/ConstraintsV2"
        }
      },
      "required": [
        "id"
      ],
      "additionalProperties": false
    },
    "ConstraintsV2": {
      "type": "object",
      "properties": {
        "limit_disclosure": {
          "$ref": "#/definitions/Optionality"
        },
        "statuses": {
          "$ref": "#/definitions/Statuses"
        },
        "fields": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/FieldV2"
          }
        },
        "subject_is_issuer": {
          "$ref": "#/definitions/Optionality"
        },
        "is_holder": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/HolderSubject"
          }
        },
        "same_subject": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/HolderSubject"
          }
        }
      },
      "additionalProperties": false
    },
    "FieldV2": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "path": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "purpose": {
          "type": "string"
        },
        "filter": {
          "$ref": "#/definitions/FilterV2"
        },
        "predicate": {
          "$ref": "#/definitions/Optionality"
        }
      },
      "additionalProperties": false
    },
    "FilterV2": {
      "type": "object",
      "properties": {
        "_const": {
          "type": [
            "number",
            "string",
            "null"
          ]
        },
        "_enum": {
          "type": "array",
          "items": {
            "type": [
              "number",
              "string"
            ]
          }
        },
        "exclusiveMinimum": {
          "type": [
            "number",
            "string",
            "null"
          ]
        },
        "exclusiveMaximum": {
          "type": [
            "number",
            "string",
            "null"
          ]
        },
        "format": {
          "type": "string"
        },
        "formatMaximum": {
          "type": "string"
        },
        "formatMinimum": {
          "type": "string"
        },
        "formatExclusiveMaximum": {
          "type": "string"
        },
        "formatExclusiveMinimum": {
          "type": "string"
        },
        "minLength": {
          "type": "number"
        },
        "maxLength": {
          "type": "number"
        },
        "minimum": {
          "type": [
            "number",
            "string",
            "null"
          ]
        },
        "maximum": {
          "type": [
            "number",
            "string",
            "null"
          ]
        },
        "not": {
          "type": "object"
        },
        "pattern": {
          "type": "string"
        },
        "type": {
          "type": "string"
        }
      },
      "required": [
        "type"
      ],
      "additionalProperties": false
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
    "RequestObjectOpts<ClaimPayloadOptsVID1>": {
      "type": "object",
      "properties": {
        "passBy": {
          "$ref": "#/definitions/PassBy"
        },
        "referenceUri": {
          "type": "string"
        },
        "payload": {
          "$ref": "#/definitions/RequestObjectPayloadOpts%3CClaimPayloadOptsVID1%3E"
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
            },
            {
              "$ref": "#/definitions/NoSignature"
            }
          ]
        }
      },
      "required": [
        "passBy",
        "signatureType"
      ],
      "additionalProperties": false
    },
    "RequestObjectPayloadOpts<ClaimPayloadOptsVID1>": {
      "type": "object",
      "properties": {
        "scope": {
          "type": "string"
        },
        "response_type": {
          "type": "string"
        },
        "client_id": {
          "type": "string"
        },
        "redirect_uri": {
          "type": "string"
        },
        "id_token_hint": {
          "type": "string"
        },
        "claims": {
          "$ref": "#/definitions/ClaimPayloadOptsVID1"
        },
        "nonce": {
          "type": "string"
        },
        "state": {
          "type": "string"
        },
        "authorization_endpoint": {
          "type": "string"
        },
        "response_mode": {
          "$ref": "#/definitions/ResponseMode"
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
        }
      },
      "required": [
        "scope",
        "response_type",
        "client_id",
        "redirect_uri"
      ]
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
        "alg": {
          "$ref": "#/definitions/SigningAlgo"
        },
        "kid": {
          "type": "string"
        },
        "customJwtSigner": {
          "$ref": "#/definitions/Signer"
        }
      },
      "required": [
        "hexPrivateKey",
        "did",
        "alg"
      ],
      "additionalProperties": false
    },
    "Signer": {
      "properties": {
        "isFunction": {
          "type": "boolean",
          "const": true
        }
      }
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
        "alg": {
          "$ref": "#/definitions/SigningAlgo"
        },
        "kid": {
          "type": "string"
        }
      },
      "required": [
        "signatureUri",
        "did",
        "alg"
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
        "alg": {
          "$ref": "#/definitions/SigningAlgo"
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
        "alg",
        "did",
        "kid"
      ],
      "additionalProperties": false
    },
    "NoSignature": {
      "type": "object",
      "properties": {
        "hexPublicKey": {
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
        "hexPublicKey",
        "did"
      ],
      "additionalProperties": false
    },
    "AuthorizationRequestOptsVD11": {
      "type": "object",
      "properties": {
        "version": {
          "$ref": "#/definitions/SupportedVersion"
        },
        "clientMetadata": {
          "$ref": "#/definitions/ClientMetadataOpts"
        },
        "payload": {
          "$ref": "#/definitions/AuthorizationRequestPayloadOpts%3CClaimPayloadCommonOpts%3E"
        },
        "requestObject": {
          "$ref": "#/definitions/RequestObjectOpts%3CClaimPayloadCommonOpts%3E"
        },
        "uriScheme": {
          "type": "string"
        },
        "idTokenType": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "required": [
        "requestObject",
        "version"
      ]
    },
    "AuthorizationRequestPayloadOpts<ClaimPayloadCommonOpts>": {
      "type": "object",
      "properties": {
        "scope": {
          "type": "string"
        },
        "response_type": {
          "type": "string"
        },
        "client_id": {
          "type": "string"
        },
        "redirect_uri": {
          "type": "string"
        },
        "id_token_hint": {
          "type": "string"
        },
        "claims": {
          "$ref": "#/definitions/ClaimPayloadCommonOpts"
        },
        "nonce": {
          "type": "string"
        },
        "state": {
          "type": "string"
        },
        "authorization_endpoint": {
          "type": "string"
        },
        "response_mode": {
          "$ref": "#/definitions/ResponseMode"
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
        "request_uri": {
          "type": "string"
        }
      }
    },
    "ClaimPayloadCommonOpts": {
      "type": "object"
    },
    "RequestObjectOpts<ClaimPayloadCommonOpts>": {
      "type": "object",
      "properties": {
        "passBy": {
          "$ref": "#/definitions/PassBy"
        },
        "referenceUri": {
          "type": "string"
        },
        "payload": {
          "$ref": "#/definitions/RequestObjectPayloadOpts%3CClaimPayloadCommonOpts%3E"
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
            },
            {
              "$ref": "#/definitions/NoSignature"
            }
          ]
        }
      },
      "required": [
        "passBy",
        "signatureType"
      ],
      "additionalProperties": false
    },
    "RequestObjectPayloadOpts<ClaimPayloadCommonOpts>": {
      "type": "object",
      "properties": {
        "scope": {
          "type": "string"
        },
        "response_type": {
          "type": "string"
        },
        "client_id": {
          "type": "string"
        },
        "redirect_uri": {
          "type": "string"
        },
        "id_token_hint": {
          "type": "string"
        },
        "claims": {
          "$ref": "#/definitions/ClaimPayloadCommonOpts"
        },
        "nonce": {
          "type": "string"
        },
        "state": {
          "type": "string"
        },
        "authorization_endpoint": {
          "type": "string"
        },
        "response_mode": {
          "$ref": "#/definitions/ResponseMode"
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
        }
      },
      "required": [
        "scope",
        "response_type",
        "client_id",
        "redirect_uri"
      ]
    }
  }
};