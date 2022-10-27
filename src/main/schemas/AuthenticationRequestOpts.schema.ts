export const AuthenticationRequestOptsSchema = {
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$ref": "#/definitions/AuthenticationRequestOpts",
  "definitions": {
    "AuthenticationRequestOpts": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "scope": {
          "type": "string"
        },
        "responseType": {
          "type": "string"
        },
        "clientId": {
          "type": "string"
        },
        "redirectUri": {
          "type": "string"
        },
        "idTokenHint": {
          "type": "string"
        },
        "claims": {
          "$ref": "#/definitions/ClaimOpts"
        },
        "request": {
          "type": "string"
        },
        "requestUri": {
          "type": "string"
        },
        "clientMetadata": {
          "type": "object"
        },
        "clientMetadataUri": {
          "type": "string"
        },
        "idTokenType": {
          "type": "string"
        },
        "registration": {
          "$ref": "#/definitions/RequestRegistrationOpts"
        },
        "registrationUri": {
          "type": "string"
        },
        "authorizationEndpoint": {
          "type": "string"
        },
        "requestBy": {
          "$ref": "#/definitions/ObjectBy"
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
        },
        "checkLinkedDomain": {
          "$ref": "#/definitions/CheckLinkedDomain"
        },
        "responseMode": {
          "$ref": "#/definitions/ResponseMode"
        },
        "responseContext": {
          "$ref": "#/definitions/ResponseContext"
        },
        "responseTypesSupported": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/ResponseType"
          }
        },
        "nonce": {
          "type": "string"
        },
        "state": {
          "type": "string"
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
        "requestObjectSigningAlgValuesSupported": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/SigningAlgo"
          }
        },
        "revocationVerificationCallback": {
          "$ref": "#/definitions/RevocationVerificationCallback"
        }
      },
      "required": [
        "clientId",
        "redirectUri",
        "requestBy",
        "responseType",
        "scope",
        "signatureType"
      ]
    },
    "ClaimOpts": {
      "type": "object",
      "properties": {
        "id_token": {
          "$ref": "#/definitions/IdToken"
        },
        "vp_token": {
          "type": "object",
          "properties": {
            "presentation_definition": {
              "$ref": "#/definitions/IPresentationDefinition"
            }
          },
          "additionalProperties": false
        }
      },
      "additionalProperties": false
    },
    "IdToken": {
      "type": "object",
      "properties": {
        "iss": {
          "type": "string"
        },
        "sub": {
          "type": "string"
        },
        "aud": {
          "type": "string"
        },
        "iat": {
          "type": "number"
        },
        "nbf": {
          "type": "number"
        },
        "type": {
          "type": "string"
        },
        "exp": {
          "type": "number"
        },
        "rexp": {
          "type": "number"
        },
        "jti": {
          "type": "string"
        },
        "auth_time": {
          "type": "number"
        },
        "nonce": {
          "type": "string"
        },
        "_vp_token": {
          "type": "object",
          "properties": {
            "presentation_submission": {
              "$ref": "#/definitions/PresentationSubmission"
            }
          },
          "additionalProperties": false
        }
      }
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
    "RequestRegistrationOpts": {
      "type": "object",
      "properties": {
        "registrationBy": {
          "$ref": "#/definitions/RegistrationType"
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
        "registrationBy"
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
    "ObjectBy": {
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
        }
      },
      "required": [
        "type"
      ],
      "additionalProperties": false
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
    "CheckLinkedDomain": {
      "type": "string",
      "enum": [
        "never",
        "if_present",
        "always"
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
    "ResponseContext": {
      "type": "string",
      "enum": [
        "rp",
        "op"
      ]
    },
    "RevocationVerificationCallback": {
      "properties": {
        "isFunction": {
          "type": "boolean",
          "const": true
        }
      }
    }
  }
};